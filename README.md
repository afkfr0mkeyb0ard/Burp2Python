# Burp2Python
Python script to send Burp requests

## Usage

```
$ burp2python.py [-h] [-n THREADS] [--barrier] [--tls] [--no-tls] [-k] [--timeout TIMEOUT] [-v] [-o OUTPUT_DIR] [--proxy PROXY] [--proxy-user PROXY_USER] [--proxy-pass PROXY_PASS] file

Replay a Burp Suite request with optional HTTP proxy.

positional arguments:
  file                  Path to the request file saved from Burp Suite

options:
  -h, --help            show this help message and exit
  -n THREADS, --threads THREADS
                        Number of parallel threads (default: 1)
  --barrier             Synchronize threads using threading.Barrier
  --tls                 Force HTTPS (TLS)
  --no-tls              Force plain HTTP (no TLS)
  -k, --insecure        Disable TLS certificate verification
  --timeout TIMEOUT     Socket timeout in seconds (default: 10)
  -v, --verbose         Print full HTTP request and response
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Directory to save each thread's request and response
  --proxy PROXY         HTTP proxy (example: http://127.0.0.1:8080)
  --proxy-user PROXY_USER
                        Proxy authentication username
  --proxy-pass PROXY_PASS
                        Proxy authentication password
```

*This script was partially generated using AI.*
