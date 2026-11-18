#!/usr/bin/env python3
"""用演示 CA 签发新的服务器证书（模拟运维拿到新证书或 CA 回签）。

用法:
  # 生成一张新证书（上传用）
  python3 scripts/make_cert.py --data-dir /tmp/certops-local/data --out-dir /tmp/newcert \
      [--domain demo.internal] [--days 365] [--not-before-days-ago 0]
  # 对指定 CSR 用演示 CA 回签（模拟 CA 处理续期申请）
  python3 scripts/make_cert.py --data-dir /tmp/certops-local/data --out-dir /tmp/signed \
      --csr /tmp/renewal.csr [--days 365]

输出 out-dir/chain.pem（服务器证书+CA 链）与 key.pem（仅生成模式），并打印指纹。
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web"))

from app import certutil  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", required=True, help="应用数据目录（内含 ca/）")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--domain", default="demo.internal")
    ap.add_argument("--days", type=int, default=365)
    ap.add_argument("--not-before-days-ago", type=int, default=0)
    ap.add_argument("--csr", help="若指定，则用演示 CA 回签该 CSR（不生成新私钥）")
    args = ap.parse_args()

    with open(os.path.join(args.data_dir, "ca", "ca.pem"), "rb") as f:
        ca_cert = f.read()
    with open(os.path.join(args.data_dir, "ca", "ca-key.pem"), "rb") as f:
        ca_key = f.read()

    if args.csr:
        with open(args.csr, "rb") as f:
            csr = f.read()
        chain = certutil.sign_csr(
            csr, ca_cert, ca_key,
            days_valid=args.days, not_before_days_ago=args.not_before_days_ago,
        )
        key = None
    else:
        chain, key = certutil.generate_server_cert(
            args.domain, ca_cert, ca_key,
            days_valid=args.days, not_before_days_ago=args.not_before_days_ago,
        )
    os.makedirs(args.out_dir, exist_ok=True)
    with open(os.path.join(args.out_dir, "chain.pem"), "wb") as f:
        f.write(chain)
    if key is not None:
        with open(os.path.join(args.out_dir, "key.pem"), "wb") as f:
            f.write(key)
    fp = certutil.fingerprint_pem_chain(chain)
    print(f"written to {args.out_dir}  fingerprint={fp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
