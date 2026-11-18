"""续期申请的边界情况：重复回签不同证书、已上传同证书的关联、并发回签。

使用独立数据目录，避免与其他测试共享模块级 app 实例。
"""
from __future__ import annotations

import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app import certutil
from app.service import CertService, Config, Conflict


DOMAIN = "demo.internal"


class SilentControl:
    def probe(self):
        from app.service import ProbeError
        raise ProbeError("no nginx")

    def request_reload(self, token):
        pass

    def wait_receipt(self, token, timeout):
        return None


@pytest.fixture()
def svc(tmp_path):
    cfg = Config(
        site_domain=DOMAIN,
        data_dir=str(tmp_path / "data"),
        live_dir=str(tmp_path / "live"),
        reload_dir=str(tmp_path / "reload"),
        startup_probe_timeout=0.1,
    )
    s = CertService(cfg)
    s.control = SilentControl()
    s.startup(background=False)
    yield s
    s.shutdown()


def _ca(s):
    with open(f"{s.cfg.data_dir}/ca/ca.pem", "rb") as f:
        ca_cert = f.read()
    with open(f"{s.cfg.data_dir}/ca/ca-key.pem", "rb") as f:
        ca_key = f.read()
    return ca_cert, ca_key


def _second_signback(s, csr_pem):
    """用同一申请 CSR 再签一张不同序列号/有效期的证书。"""
    ca_cert, ca_key = _ca(s)
    import datetime as dt
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    ca = x509.load_pem_x509_certificate(ca_cert)
    key = serialization.load_pem_private_key(ca_key, password=None)
    csr = certutil.parse_csr(csr_pem)
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(DOMAIN)]), False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM) + ca_cert


def test_second_different_signback_conflicts(svc):
    r = svc.create_renewal()
    ca_cert, ca_key = _ca(svc)
    chain1 = certutil.sign_csr(r["csr_pem"].encode(), ca_cert, ca_key)
    v1, created1 = svc.signback(r["id"], chain1)
    chain2 = _second_signback(svc, r["csr_pem"].encode())
    with pytest.raises(Conflict, match="不能重复登记"):
        svc.signback(r["id"], chain2)
    st = svc.status(probe=False)
    assert len(st["versions"]) == 2  # 种子 + 回签的一张
    assert svc.get_renewal(r["id"])["version_id"] == v1["id"]
    # 已登记的那张重传仍幂等
    assert svc.signback(r["id"], chain1) == (v1, False)


def test_signback_links_preexisting_identical_cert(svc):
    """同一 CSR 回签的证书先通过普通上传登记过，回签应关联而非重复登记。"""
    r = svc.create_renewal()
    ca_cert, ca_key = _ca(svc)
    chain = certutil.sign_csr(r["csr_pem"].encode(), ca_cert, ca_key)
    key = svc.get_renewal(r["id"], include_key=True)["key_pem"].encode()
    up, created_up = svc.upload(chain, key)
    assert created_up
    v, created = svc.signback(r["id"], chain)
    assert v["id"] == up["id"] and not created
    assert svc.get_renewal(r["id"])["state"] == "submitted"


def test_signback_preexisting_same_cert_different_key_conflicts(svc):
    """指纹相同但私钥不同（理论上不可构造）时不得把申请私钥挂上去。"""
    r = svc.create_renewal()
    ca_cert, ca_key = _ca(svc)
    chain = certutil.sign_csr(r["csr_pem"].encode(), ca_cert, ca_key)
    # 用错误的私钥占用该指纹记录，模拟数据损坏/异常导入
    other_key, _ = certutil.generate_csr(DOMAIN)
    with svc.db.txn() as c:
        c.execute(
            "INSERT INTO versions (fingerprint, domain, subject, san, not_before,"
            " not_after, cert_pem, key_pem, status, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (certutil.fingerprint_pem_chain(chain), DOMAIN, "cn", DOMAIN,
             "2026-01-01T00:00:00+00:00", "2027-01-01T00:00:00+00:00",
             chain.decode(), other_key.decode(), "candidate",
             "2026-01-01T00:00:00+00:00"),
        )
    with pytest.raises(Conflict, match="私钥"):
        svc.signback(r["id"], chain)
    assert svc.get_renewal(r["id"])["state"] == "pending"


def test_concurrent_signbacks_register_once(svc):
    r = svc.create_renewal()
    ca_cert, ca_key = _ca(svc)
    chain = certutil.sign_csr(r["csr_pem"].encode(), ca_cert, ca_key)
    results, errors = [], []

    def worker():
        try:
            results.append(svc.signback(r["id"], chain))
        except Conflict as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    created = [res for res in results if res[1]]
    assert len(created) == 1, results
    assert len(results) == 8 and not errors
    assert len(svc.status(probe=False)["versions"]) == 2  # 种子 + 1 张
