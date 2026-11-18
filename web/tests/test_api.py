"""HTTP 层测试：续期申请路由、CSR 下载、回签/撤销的响应语义。

app.main 在导入时按环境变量创建服务，因此先设置临时目录与短探测超时，
再导入应用。TestClient 会触发 lifespan（启动初始化、结束清理）。
"""
from __future__ import annotations

import os
import tempfile

import pytest

_TMP = tempfile.mkdtemp(prefix="certops-api-")
os.environ.update(
    SITE_DOMAIN="demo.internal",
    DATA_DIR=os.path.join(_TMP, "data"),
    LIVE_DIR=os.path.join(_TMP, "live"),
    RELOAD_DIR=os.path.join(_TMP, "reload"),
    NGINX_PROBE_HOST="127.0.0.1",
    NGINX_PROBE_PORT="1",          # 无服务：探测立即失败，后台不阻塞
    STARTUP_PROBE_TIMEOUT="0.2",
    RECEIPT_TIMEOUT="0.1",
    VERIFY_TIMEOUT="0.2",
)

from fastapi.testclient import TestClient  # noqa: E402

from app import certutil  # noqa: E402
from app.main import app, service  # noqa: E402


@pytest.fixture(scope="module")
def client():
    # lifespan 结束时 service.shutdown() 会关闭 SQLite，因此整个模块共用一个客户端
    with TestClient(app) as c:
        yield c


def _sign(service_, csr_pem, **kw):
    with open(f"{service_.cfg.data_dir}/ca/ca.pem", "rb") as f:
        ca_cert = f.read()
    with open(f"{service_.cfg.data_dir}/ca/ca-key.pem", "rb") as f:
        ca_key = f.read()
    return certutil.sign_csr(csr_pem, ca_cert, ca_key, **kw)


def test_create_and_download_csr(client):
    r = client.post("/renewal", data={"key_type": "ec"})
    assert r.status_code == 200
    body = r.json()
    rid = body["renewal_id"]
    assert "key_pem" not in body["renewal"]

    r = client.get(f"/api/renewal/{rid}/csr")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/pkcs10")
    assert "attachment" in r.headers["content-disposition"]
    assert b"BEGIN CERTIFICATE REQUEST" in r.content
    # 下载内容与记录一致，且不包含私钥
    assert r.content.decode() == client.get(f"/api/renewal/{rid}").json()["csr_pem"]
    assert b"PRIVATE KEY" not in r.content


def test_index_shows_renewal_section(client):
    html = client.get("/").text
    assert "续期申请" in html and "下载 CSR" in html


def test_signback_flow_via_http(client):
    rid = client.post("/renewal", data={"key_type": "rsa"}).json()["renewal_id"]
    csr = client.get(f"/api/renewal/{rid}/csr").content
    chain = _sign(service, csr)

    r = client.post(f"/renewal/{rid}/signback",
                    files={"cert_file": ("chain.pem", chain)})
    assert r.status_code == 200
    vid = r.json()["version_id"]

    # 重复回签：200 且标记未新登记
    r = client.post(f"/renewal/{rid}/signback",
                    files={"cert_file": ("chain.pem", chain)})
    assert r.status_code == 200
    assert r.json() == {"msg": f"该回签证书已登记（版本 #{vid}），未重复登记",
                        "version_id": vid, "created": False}

    st = client.get("/api/status").json()
    assert st["renewals"][0]["state"] == "submitted"
    assert st["renewals"][0]["version_id"] == vid


def test_signback_bad_chain_http_400(client):
    rid = client.post("/renewal", data={"key_type": "rsa"}).json()["renewal_id"]
    csr = client.get(f"/api/renewal/{rid}/csr").content
    chain = _sign(service, csr)
    leaf = chain.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----\n"
    other_ca, _ = certutil.generate_ca("Other CA")
    r = client.post(f"/renewal/{rid}/signback",
                    files={"cert_file": ("chain.pem", leaf + other_ca)})
    assert r.status_code == 400
    assert "校验失败" in r.json()["err"]
    assert client.get(f"/api/renewal/{rid}").json()["state"] == "pending"


def test_revoke_http_then_signback_409(client):
    rid = client.post("/renewal", data={"key_type": "rsa"}).json()["renewal_id"]
    csr = client.get(f"/api/renewal/{rid}/csr").content
    r = client.post(f"/renewal/{rid}/revoke")
    assert r.status_code == 200
    assert r.json()["renewal"]["state"] == "revoked"
    r = client.post(f"/renewal/{rid}/signback",
                    files={"cert_file": ("chain.pem", _sign(service, csr))})
    assert r.status_code == 409
    assert "撤销" in r.json()["err"]


def test_unknown_renewal_404(client):
    assert client.get("/api/renewal/9999").status_code == 404
    assert client.get("/api/renewal/9999/csr").status_code == 404
    assert client.post("/renewal/9999/revoke").status_code == 404
    r = client.post("/renewal/9999/signback",
                    files={"cert_file": ("chain.pem", b"x")})
    assert r.status_code == 404


def test_create_bad_key_type_400(client):
    r = client.post("/renewal", data={"key_type": "dsa"})
    assert r.status_code == 400


def test_form_redirect_mode(client):
    r = client.post("/renewal", data={"key_type": "rsa", "redirect": "1"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert "/?msg=" in r.headers["location"]
