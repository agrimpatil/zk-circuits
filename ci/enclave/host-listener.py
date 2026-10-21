#!/usr/bin/env python3
"""Parent-side vsock listener: receive the enclave's output bundle.

Runs on the EC2 host. Accepts one connection from the enclave and writes the
received tar.gz to <out>. Use for the non-debug (real PCR) run where the enclave
has no console.

Usage: host-listener.py [port] [out_path]
"""
import os
import socket
import sys


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5005
    out = sys.argv[2] if len(sys.argv) > 2 else "enclave-out/enclave-out.tar.gz"
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)

    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # VMADDR_CID_ANY: accept from any enclave CID.
    s.bind((socket.VMADDR_CID_ANY, port))
    s.listen(1)
    print(f"[host-listener] waiting on vsock port {port} ...", flush=True)

    conn, (cid, _) = s.accept()
    print(f"[host-listener] connection from CID {cid}", flush=True)
    total = 0
    with open(out, "wb") as f:
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            f.write(chunk)
            total += len(chunk)
    conn.sendall(b"ok")
    conn.close()
    s.close()
    print(f"[host-listener] wrote {total} bytes to {out}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
