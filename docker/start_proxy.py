#!/usr/bin/env python3
"""Start httpcloak local proxy and keep it running.

Sets HTTP_PROXY / HTTPS_PROXY and writes the proxy URL to stdout so the
calling shell script can export it before launching hermes.
"""
import signal
import sys
import time

from httpcloak import LocalProxy

PROXY_PORT = 8080


def main() -> None:
    proxy = LocalProxy(port=PROXY_PORT, preset="chrome-latest")
    # Print the proxy URL so the shell can capture it
    print(proxy.proxy_url, flush=True)

    def _shutdown(signum, frame):
        proxy.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        while proxy.is_running:
            time.sleep(1)
    finally:
        proxy.close()


if __name__ == "__main__":
    main()
