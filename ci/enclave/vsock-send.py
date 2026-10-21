#!/usr/bin/env python3
"""Enclave-side vsock client: stream a file to the parent instance.

Usage: vsock-send.py <parent_cid> <port> <file>
"""
import socket
import sys


def main() -> int:
    if len(sys.argv) != 4:
        sys.stderr.write("usage: vsock-send.py <parent_cid> <port> <file>\n")
        return 2
    cid = int(sys.argv[1])
    port = int(sys.argv[2])
    path = sys.argv[3]

    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.connect((cid, port))
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            s.sendall(chunk)
    s.shutdown(socket.SHUT_WR)
    # Wait for the parent's ack so we don't exit before it finishes writing.
    s.recv(16)
    s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
