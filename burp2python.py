import argparse
import base64
import os
import socket
import ssl
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import urlsplit

print_lock = threading.Lock()


@dataclass
class HttpRequest:
    method: str
    path: str
    version: str
    headers: dict[str, str]
    body: bytes
    host: str
    port: int
    use_tls: bool


def extract_raw_from_burp_file(raw_bytes: bytes) -> tuple[bytes, bool | None]:
    """Detects whether the input is a Burp XML export or a raw HTTP request."""
    stripped = raw_bytes.lstrip()

    if stripped.startswith(b"<?xml") or stripped.startswith(b"<items"):
        root = ET.fromstring(raw_bytes)
        item = root.find(".//item")

        if item is None:
            raise ValueError("Missing <item> tag in Burp XML file.")

        req_elem = item.find("request")

        if req_elem is None or not req_elem.text:
            raise ValueError("Missing or empty <request> tag in Burp XML file.")

        is_b64 = req_elem.attrib.get("base64", "false").lower() == "true"
        req_bytes = (
            base64.b64decode(req_elem.text)
            if is_b64
            else req_elem.text.encode("latin-1")
        )

        proto_elem = item.find("protocol")
        xml_tls = None

        if proto_elem is not None and proto_elem.text:
            xml_tls = proto_elem.text.strip().lower() == "https"

        return req_bytes, xml_tls

    return raw_bytes, None


def parse_burp_request(
    raw_bytes: bytes,
    force_tls: bool | None = None
) -> HttpRequest:

    raw_bytes, xml_tls = extract_raw_from_burp_file(raw_bytes)

    if force_tls is None and xml_tls is not None:
        force_tls = xml_tls

    normalized = raw_bytes.replace(b"\r\n", b"\n").lstrip(b"\n")
    parts = normalized.split(b"\n\n", 1)

    header_block = parts[0].decode("latin-1")
    body = parts[1] if len(parts) > 1 else b""

    lines = [line for line in header_block.split("\n") if line.strip()]

    if not lines:
        raise ValueError("Request file is empty.")

    request_line = lines[0].strip()
    tokens = request_line.split(" ")

    if len(tokens) == 3:
        method, target, version = tokens
    elif len(tokens) == 2:
        method, target = tokens
        version = "HTTP/1.1"
    else:
        raise ValueError(f"Invalid request line: {request_line!r}")

    if version.upper() == "HTTP/2":
        version = "HTTP/1.1"

    headers = {}

    for line in lines[1:]:
        if ":" not in line:
            continue

        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()

    host_header = next(
        (v for k, v in headers.items() if k.lower() == "host"),
        ""
    )

    if not host_header:
        raise ValueError("Host header not found in request.")

    scheme = None
    path = target

    if target.startswith("http://") or target.startswith("https://"):
        scheme, rest = target.split("://", 1)
        slash_idx = rest.find("/")

        if slash_idx != -1:
            host_header = rest[:slash_idx]
            path = rest[slash_idx:]
        else:
            host_header = rest
            path = "/"

    if ":" in host_header:
        host, port_str = host_header.rsplit(":", 1)
        port = int(port_str)
    else:
        host = host_header
        port = 0

    if force_tls is not None:
        use_tls = force_tls
    elif scheme == "https":
        use_tls = True
    elif scheme == "http":
        use_tls = False
    else:
        use_tls = port == 443 or port not in (80, 8080, 8000)

    if port == 0:
        port = 443 if use_tls else 80

    return HttpRequest(
        method=method,
        path=path,
        version=version,
        headers=headers,
        body=body,
        host=host,
        port=port,
        use_tls=use_tls,
    )


def build_wire_payload(req: HttpRequest) -> bytes:

    headers_out = []
    has_content_length = False

    for k, v in req.headers.items():

        if k.lower() == "proxy-connection":
            continue

        if k.lower() == "content-length":
            has_content_length = True
            headers_out.append((k, str(len(req.body))))
        else:
            headers_out.append((k, v))

    if (
        req.body
        and not has_content_length
        and "transfer-encoding" not in {k.lower() for k in req.headers}
    ):
        headers_out.append(("Content-Length", str(len(req.body))))

    req_line = (
        f"{req.method} {req.path} {req.version}\r\n"
    ).encode("latin-1")

    hdr_bytes = "".join(
        f"{k}: {v}\r\n" for k, v in headers_out
    ).encode("latin-1")

    return req_line + hdr_bytes + b"\r\n" + req.body


def send_once(
    req: HttpRequest,
    payload: bytes,
    timeout: float = 10.0,
    insecure: bool = False,
    proxy_url: str | None = None,
    proxy_user: str | None = None,
    proxy_pass: str | None = None,
) -> tuple[int | None, bytes, float]:

    start = time.perf_counter()
    proxy_auth = None

    if proxy_url:

        parsed = urlsplit(proxy_url)

        if parsed.scheme != "http" or not parsed.hostname:
            raise ValueError("Proxy must use http://IP:PORT")

        if parsed.username or parsed.password:
            raise ValueError(
                "Use --proxy-user and --proxy-pass for authentication."
            )

        proxy_host = parsed.hostname
        proxy_port = parsed.port or 8080

        if proxy_user is not None and proxy_pass is not None:
            credentials = f"{proxy_user}:{proxy_pass}".encode()
            proxy_auth = base64.b64encode(credentials).decode()

        sock = socket.create_connection(
            (proxy_host, proxy_port),
            timeout=timeout
        )

        try:

            if req.use_tls:

                authority = f"{req.host}:{req.port}"

                connect_request = (
                    f"CONNECT {authority} HTTP/1.1\r\n"
                    f"Host: {authority}\r\n"
                )

                if proxy_auth:
                    connect_request += (
                        f"Proxy-Authorization: Basic {proxy_auth}\r\n"
                    )

                connect_request += "\r\n"

                sock.sendall(connect_request.encode("latin-1"))

                response_headers = b""

                while b"\r\n\r\n" not in response_headers:

                    chunk = sock.recv(4096)

                    if not chunk:
                        raise ConnectionError(
                            "Proxy closed connection during CONNECT."
                        )

                    response_headers += chunk

                    if len(response_headers) > 65536:
                        raise ConnectionError(
                            "Proxy response headers too large."
                        )

                status_line = response_headers.split(b"\r\n", 1)[0]

                if b" 200 " not in status_line:
                    raise ConnectionError(
                        f"Proxy CONNECT failed: "
                        f"{status_line.decode('latin-1', errors='replace')}"
                    )

                ctx = ssl.create_default_context()

                if insecure:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                sock = ctx.wrap_socket(
                    sock,
                    server_hostname=req.host
                )

                wire_payload = payload

            else:

                authority = (
                    f"[{req.host}]"
                    if ":" in req.host
                    else req.host
                )

                if req.port != 80:
                    authority += f":{req.port}"

                absolute_target = (
                    f"http://{authority}{req.path}"
                )

                first_line, rest = payload.split(b"\r\n", 1)

                method = first_line.split(b" ", 1)[0]

                new_first_line = (
                    method
                    + b" "
                    + absolute_target.encode("latin-1")
                    + b" HTTP/1.1\r\n"
                )

                if proxy_auth:
                    rest = (
                        b"Proxy-Authorization: Basic "
                        + proxy_auth.encode()
                        + b"\r\n"
                        + rest
                    )

                wire_payload = new_first_line + rest

        except Exception:
            sock.close()
            raise

    else:

        sock = socket.create_connection(
            (req.host, req.port),
            timeout=timeout
        )

        if req.use_tls:

            ctx = ssl.create_default_context()

            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            sock = ctx.wrap_socket(
                sock,
                server_hostname=req.host
            )

        wire_payload = payload

    try:

        sock.settimeout(timeout)
        sock.sendall(wire_payload)

        chunks = []

        while True:

            data = sock.recv(4096)

            if not data:
                break

            chunks.append(data)

            joined = b"".join(chunks)

            if b"\r\n\r\n" in joined:

                head, rest = joined.split(b"\r\n\r\n", 1)
                cl = None

                for line in head.split(b"\r\n")[1:]:

                    if line.lower().startswith(b"content-length:"):
                        cl = int(line.split(b":", 1)[1].strip())
                        break

                if cl is not None and len(rest) >= cl:
                    break

        elapsed = (time.perf_counter() - start) * 1000
        response = b"".join(chunks)

        status_code = None

        if b"\r\n" in response:

            first_line = response.split(
                b"\r\n", 1
            )[0].decode("latin-1", errors="replace")

            parts = first_line.split(" ")

            if len(parts) >= 2 and parts[1].isdigit():
                status_code = int(parts[1])

        return status_code, response, elapsed

    finally:
        sock.close()


def worker(
    thread_id: int,
    req: HttpRequest,
    payload: bytes,
    barrier: threading.Barrier | None,
    timeout: float,
    insecure: bool,
    verbose: bool,
    output_dir: str | None,
    proxy_url: str | None,
    proxy_user: str | None,
    proxy_pass: str | None,
) -> None:

    try:

        if barrier is not None:
            barrier.wait()

        status, response, elapsed = send_once(
            req,
            payload,
            timeout=timeout,
            insecure=insecure,
            proxy_url=proxy_url,
            proxy_user=proxy_user,
            proxy_pass=proxy_pass,
        )

        if output_dir:

            out_path = os.path.join(
                output_dir,
                f"thread_{thread_id}.txt"
            )

            with open(out_path, "wb") as f:
                f.write(b"=== REQUEST ===\n")
                f.write(payload)
                f.write(b"\n\n=== RESPONSE ===\n")
                f.write(response)

        with print_lock:

            print(
                f"[Thread {thread_id}] "
                f"Status: {status} | "
                f"Bytes: {len(response)} | "
                f"Time: {elapsed:.1f} ms"
            )

            if verbose:

                print(f"\n--- [Thread {thread_id}] REQUEST ---")
                print(payload.decode("latin-1", errors="replace"))

                print(f"--- [Thread {thread_id}] RESPONSE ---")
                print(response.decode("latin-1", errors="replace"))

                print("-" * 40)

    except Exception as exc:

        with print_lock:
            print(f"[Thread {thread_id}] Error: {exc}")


def main() -> None:

    parser = argparse.ArgumentParser(
        description="Replay a Burp Suite request with optional HTTP proxy."
    )

    parser.add_argument(
        "file",
        help="Path to the request file saved from Burp Suite"
    )

    parser.add_argument(
        "-n", "--threads",
        type=int,
        default=1,
        help="Number of parallel threads (default: 1)"
    )

    parser.add_argument(
        "--barrier",
        action="store_true",
        help="Synchronize threads using threading.Barrier"
    )

    parser.add_argument(
        "--tls",
        action="store_true",
        help="Force HTTPS (TLS)"
    )

    parser.add_argument(
        "--no-tls",
        action="store_true",
        help="Force plain HTTP (no TLS)"
    )

    parser.add_argument(
        "-k", "--insecure",
        action="store_true",
        help="Disable TLS certificate verification"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Socket timeout in seconds (default: 10)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print full HTTP request and response"
    )

    parser.add_argument(
        "-o", "--output-dir",
        type=str,
        default=None,
        help="Directory to save each thread's request and response"
    )

    # Proxy options

    parser.add_argument(
        "--proxy",
        type=str,
        default=None,
        help="HTTP proxy (example: http://127.0.0.1:8080)"
    )

    parser.add_argument(
        "--proxy-user",
        type=str,
        default=None,
        help="Proxy authentication username"
    )

    parser.add_argument(
        "--proxy-pass",
        type=str,
        default=None,
        help="Proxy authentication password"
    )

    args = parser.parse_args()

    if args.threads < 1:
        parser.error("--threads must be at least 1")

    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    if args.tls and args.no_tls:
        parser.error("--tls and --no-tls cannot be used together")

    if args.proxy_user is not None or args.proxy_pass is not None:

        if not args.proxy:
            parser.error("--proxy is required for proxy authentication")

        if args.proxy_user is None or args.proxy_pass is None:
            parser.error(
                "--proxy-user and --proxy-pass must be provided together"
            )

    force_tls = (
        True if args.tls
        else False if args.no_tls
        else None
    )

    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)

    with open(args.file, "rb") as f:
        raw_bytes = f.read()

    req = parse_burp_request(
        raw_bytes,
        force_tls=force_tls
    )

    payload = build_wire_payload(req)

    use_barrier = args.barrier and args.threads > 1

    barrier = (
        threading.Barrier(args.threads)
        if use_barrier
        else None
    )

    if args.proxy:
        print(f"[+] Proxy enabled: {args.proxy}")
    else:
        print("[+] Proxy disabled (direct connection)")

    threads = []

    for i in range(args.threads):

        t = threading.Thread(
            target=worker,
            args=(
                i + 1,
                req,
                payload,
                barrier,
                args.timeout,
                args.insecure,
                args.verbose,
                args.output_dir,
                args.proxy,
                args.proxy_user,
                args.proxy_pass,
            )
        )

        t.start()
        threads.append(t)

    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
