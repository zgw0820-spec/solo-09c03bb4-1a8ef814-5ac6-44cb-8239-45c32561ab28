#!/usr/bin/env python3
"""端到端验证续期申请流程：对运行中的本地栈执行真实检查。

前置：scripts/local_stack.sh up 已运行。
覆盖：生成 CSR（私钥不出服务端）、网页下载 CSR、用演示 CA 回签、
上传回签登记候选、沿用原流程启用并以 openssl 实测为准、重复回签不重复登记、
回签失败不影响在用证书、撤销后不能回签、Web 重启后申请与私钥仍可找回。
"""
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

WEB = os.environ.get("WEB", "http://127.0.0.1:8080")
TLS_PORT = int(os.environ.get("TLS_PORT", "8443"))
WORK = os.environ.get("LOCAL_WORK", "/tmp/certops-local")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STACK = os.path.join(ROOT, "scripts", "local_stack.sh")

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'PASS' if cond else 'FAIL'}  {name} {extra}")


def api(path):
    with urllib.request.urlopen(WEB + path, timeout=20) as r:
        return json.load(r)


def get_raw(path):
    with urllib.request.urlopen(WEB + path, timeout=20) as r:
        return r.status, r.read()


def post_form(path, data=None, files=None):
    boundary = "----renewboundary"
    body = b""
    for k, v in (data or {}).items():
        body += f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
    for k, (fname, content) in (files or {}).items():
        body += (
            f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"; '
            f'filename="{fname}"\r\nContent-Type: application/x-pem-file\r\n\r\n'
        ).encode() + content + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    req = urllib.request.Request(
        WEB + path, data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def openssl_fp():
    out = subprocess.run(
        ["openssl", "s_client", "-connect", f"127.0.0.1:{TLS_PORT}",
         "-servername", "demo.internal"],
        input="", capture_output=True, text=True, timeout=10,
    ).stdout
    cert = subprocess.run(
        ["openssl", "x509", "-fingerprint", "-sha256", "-noout"],
        input=out, capture_output=True, text=True,
    ).stdout.strip()
    return cert.split("=")[1].replace(":", "").lower()


def sign_csr(csr_path, out_dir):
    subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "make_cert.py"),
         "--data-dir", f"{WORK}/data", "--out-dir", out_dir, "--csr", csr_path],
        check=True, capture_output=True,
    )
    with open(f"{out_dir}/chain.pem", "rb") as f:
        return f.read()


def restart_web(env_overrides=None):
    env = dict(os.environ)
    env.update(env_overrides or {})
    subprocess.run(["bash", STACK, "restart-web"], check=True,
                   capture_output=True, timeout=120, env=env)
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            api("/api/status")
            return
        except OSError:
            time.sleep(0.5)
    raise RuntimeError("web did not come back")


def main():
    st = api("/api/status")
    v1_fp = st["active"]["fingerprint"]
    check("前置：在用版本与实测一致", st["served_fingerprint"] == v1_fp)

    # 1. 网页生成续期申请
    code, resp = post_form("/renewal", data={"key_type": "rsa"})
    rid = resp.get("renewal_id")
    check("网页生成续期申请", code == 200 and isinstance(rid, int), f"code={code} {resp}")
    r = api(f"/api/renewal/{rid}")
    check("申请初始状态 pending", r["state"] == "pending")
    check("API 不返回申请私钥", "key_pem" not in r and "PRIVATE KEY" not in json.dumps(r))

    # 2. 网页下载 CSR
    code, csr_bytes = get_raw(f"/api/renewal/{rid}/csr")
    check("网页下载 CSR", code == 200 and b"BEGIN CERTIFICATE REQUEST" in csr_bytes)
    csr_path = f"/tmp/renewal-{rid}.csr"
    with open(csr_path, "wb") as f:
        f.write(csr_bytes)
    # CSR 的公钥应等于服务端保存的申请私钥（用回签+启用结果间接验证；此处先解析）
    csr_pub = subprocess.run(
        ["openssl", "req", "-in", csr_path, "-noout", "-pubkey"],
        capture_output=True, text=True, check=True,
    ).stdout

    # 3. 演示 CA 回签
    chain = sign_csr(csr_path, f"/tmp/renewal-signed-{rid}")
    signed_leaf_pub = subprocess.run(
        ["openssl", "x509", "-noout", "-pubkey"],
        input=chain.decode(), capture_output=True, text=True, check=True,
    ).stdout
    check("回签证书公钥 == CSR 公钥", signed_leaf_pub.strip() == csr_pub.strip())

    # 4. 失败回签不影响在用证书：用其它域名(同公钥)构造的证书必须被拒
    # 用另一个申请的 CSR 回签，公钥不符
    code, resp2 = post_form("/renewal", data={"key_type": "ec"})
    other_id = resp2["renewal_id"]
    _, other_csr = get_raw(f"/api/renewal/{other_id}/csr")
    other_path = f"/tmp/renewal-{other_id}.csr"
    with open(other_path, "wb") as f:
        f.write(other_csr)
    wrong_chain = sign_csr(other_path, f"/tmp/renewal-other-{other_id}")
    before = api("/api/status")
    code, resp = post_form(f"/renewal/{rid}/signback",
                           files={"cert_file": ("chain.pem", wrong_chain)})
    check("公钥不符的回签被拒(400)", code == 400 and "公钥" in resp.get("err", ""),
          f"code={code} {resp}")
    st = api("/api/status")
    check("失败回签不影响在用证书",
          st["active_version_id"] == before["active_version_id"]
          and st["served_fingerprint"] == before["served_fingerprint"]
          and st["active"]["fingerprint"] == before["active"]["fingerprint"])
    check("失败回签后申请仍 pending", api(f"/api/renewal/{rid}")["state"] == "pending")
    # 清理这条干扰申请
    post_form(f"/renewal/{other_id}/revoke")
    check("EC 申请撤销成功", api(f"/api/renewal/{other_id}")["state"] == "revoked")
    code, resp = post_form(f"/renewal/{other_id}/signback",
                           files={"cert_file": ("chain.pem", wrong_chain)})
    check("撤销后回签被拒(409)", code == 409, f"code={code} {resp}")

    # 5. 正确回签 -> 登记候选
    code, resp = post_form(f"/renewal/{rid}/signback",
                           files={"cert_file": ("chain.pem", chain)})
    vid = resp.get("version_id")
    check("回签校验通过并登记候选", code == 200 and resp.get("created") is True,
          f"code={code} {resp}")
    check("申请状态变为 submitted 并关联版本",
          api(f"/api/renewal/{rid}")["version_id"] == vid
          and api(f"/api/renewal/{rid}")["state"] == "submitted")

    # 6. 重复回签不重复登记
    code, resp = post_form(f"/renewal/{rid}/signback",
                           files={"cert_file": ("chain.pem", chain)})
    check("重复回签不重复登记", code == 200 and resp.get("created") is False
          and resp.get("version_id") == vid, f"code={code} {resp}")
    st = api("/api/status")
    same = [v for v in st["versions"] if v["fingerprint"] ==
            [x for x in st["versions"] if x["id"] == vid][0]["fingerprint"]]
    check("该证书仅存在一个版本记录", len(same) == 1)

    # 7. 已回签后的申请不能再撤销
    code, resp = post_form(f"/renewal/{rid}/revoke")
    check("已回签申请不能撤销(409)", code == 409, f"code={code} {resp}")

    # 8. 沿用原启用流程启用该候选，以 openssl 实测为准
    base = api("/api/status")["active_version_id"]
    code, resp = post_form("/activate", data={"version_id": vid, "base_version_id": base})
    check("候选可走原启用流程", code == 200 and resp.get("op", {}).get("state") == "succeeded",
          f"code={code} {resp}")
    st = api("/api/status")
    new_fp = [v for v in st["versions"] if v["id"] == vid][0]["fingerprint"]
    check("启用后续期证书在用(openssl 实测)", openssl_fp() == new_fp
          and st["served_fingerprint"] == new_fp)
    signed_not_after = subprocess.run(
        ["openssl", "x509", "-noout", "-enddate"],
        input=chain.decode(), capture_output=True, text=True, check=True,
    ).stdout.strip().split("=", 1)[1]
    from email.utils import parsedate_to_datetime
    signed_not_after_iso = parsedate_to_datetime(signed_not_after).isoformat()
    # 在用证书有效期应等于本申请回签证书的有效期（而不是旧证书）
    check("在用的是本次回签证书的有效期",
          st["active"]["not_after"] == signed_not_after_iso,
          f"active={st['active']['not_after']} signed={signed_not_after_iso}")

    # 9. 撤销与回签并发：撤销成功则绝不生成候选
    race_ok = 0
    for attempt in range(1, 4):
        code, resp = post_form("/renewal", data={"key_type": "ec"})
        race_id = resp["renewal_id"]
        _, race_csr = get_raw(f"/api/renewal/{race_id}/csr")
        rp = f"/tmp/renewal-race-{race_id}.csr"
        with open(rp, "wb") as f:
            f.write(race_csr)
        race_chain = sign_csr(rp, f"/tmp/renewal-race-signed-{race_id}")
        versions_before = len(api("/api/status")["versions"])
        barrier = threading.Barrier(2)
        out = {}

        def do_sign():
            barrier.wait()
            out["sign"] = post_form(f"/renewal/{race_id}/signback",
                                    files={"cert_file": ("chain.pem", race_chain)})

        def do_revoke():
            barrier.wait()
            out["revoke"] = post_form(f"/renewal/{race_id}/revoke")

        ts = [threading.Thread(target=do_sign), threading.Thread(target=do_revoke)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        final = api(f"/api/renewal/{race_id}")
        versions_after = len(api("/api/status")["versions"])
        if final["state"] == "revoked":
            ok = out["sign"][0] == 409 and versions_after == versions_before
        else:
            ok = (final["state"] == "submitted" and out["revoke"][0] == 409
                  and versions_after == versions_before + 1)
        check(f"并发撤销/回签（第 {attempt} 次）结果一致且无多余候选",
              ok, f"final={final['state']} out={out} dv={versions_after - versions_before}")
        race_ok += ok

    # 9b. 强制"撤销先赢"的交错：回签在服务端校验后延迟 2s 才落库，
    #     期间撤销先提交。回签必须被拒，且不能生成候选。
    restart_web({"SIGNBACK_DELAY_AFTER_VALIDATE": "2"})
    code, resp = post_form("/renewal", data={"key_type": "ec"})
    rev_id = resp["renewal_id"]
    _, rev_csr = get_raw(f"/api/renewal/{rev_id}/csr")
    rvp = f"/tmp/renewal-revwin-{rev_id}.csr"
    with open(rvp, "wb") as f:
        f.write(rev_csr)
    rev_chain = sign_csr(rvp, f"/tmp/renewal-revwin-signed-{rev_id}")
    versions_before = len(api("/api/status")["versions"])
    out = {}

    def sign_after_delay():
        out["sign"] = post_form(f"/renewal/{rev_id}/signback",
                                files={"cert_file": ("chain.pem", rev_chain)})

    t = threading.Thread(target=sign_after_delay)
    t.start()
    time.sleep(0.6)  # 回签已过校验、处于延迟窗口
    out["revoke"] = post_form(f"/renewal/{rev_id}/revoke")
    t.join()
    restart_web({"SIGNBACK_DELAY_AFTER_VALIDATE": "0"})
    final = api(f"/api/renewal/{rev_id}")
    versions_after = len(api("/api/status")["versions"])
    check("强制的撤销先赢交错：撤销成功、回签被拒、无新候选",
          out["revoke"][0] == 200 and out["sign"][0] == 409
          and final["state"] == "revoked" and versions_after == versions_before,
          f"revoke={out['revoke'][0]} sign={out['sign']} final={final['state']} "
          f"dv={versions_after - versions_before}")

    # 10. 重启后申请记录与私钥仍可找回：重启后继续对一个待签申请回签并启用
    code, resp = post_form("/renewal", data={"key_type": "rsa"})
    keep_id = resp["renewal_id"]
    _, keep_csr = get_raw(f"/api/renewal/{keep_id}/csr")
    kp = f"/tmp/renewal-keep-{keep_id}.csr"
    with open(kp, "wb") as f:
        f.write(keep_csr)
    restart_web()
    found = api(f"/api/renewal/{keep_id}")
    check("Web 重启后申请记录仍可找回", found["id"] == keep_id
          and found["state"] == "pending" and found["csr_pem"] == keep_csr.decode())
    keep_chain = sign_csr(kp, f"/tmp/renewal-keep-signed-{keep_id}")
    code, resp = post_form(f"/renewal/{keep_id}/signback",
                           files={"cert_file": ("chain.pem", keep_chain)})
    check("重启后仍能用原申请私钥登记候选", code == 200 and resp.get("created") is True,
          f"code={code} {resp}")
    keep_vid = resp.get("version_id")
    base = api("/api/status")["active_version_id"]
    code, resp = post_form("/activate", data={"version_id": keep_vid,
                                             "base_version_id": base})
    check("重启后登记的候选可正常启用",
          code == 200 and resp.get("op", {}).get("state") == "succeeded",
          f"code={code} {resp}")
    check("重启后启用证书实测一致", openssl_fp() ==
          [v for v in api("/api/status")["versions"] if v["id"] == keep_vid][0]["fingerprint"])

    print(f"\n== renewal e2e: {len(passed)} passed, {len(failed)} failed ==")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
