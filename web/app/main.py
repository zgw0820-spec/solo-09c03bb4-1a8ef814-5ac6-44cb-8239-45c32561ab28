"""FastAPI 入口：单站点证书启用管理页。"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from urllib.parse import quote

from fastapi import FastAPI, Form, Request, Response, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from . import certutil
from .service import BadRequest, CertService, Conflict, Config, NotFound

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
)

cfg = Config.from_env()
service = CertService(cfg)


@asynccontextmanager
async def lifespan(app: FastAPI):
    service.startup()
    yield
    service.shutdown()


app = FastAPI(title="证书启用管理", lifespan=lifespan)
templates = Jinja2Templates(directory=__file__.rsplit("/", 1)[0] + "/templates")


def _respond(request: Request, redirect: int, payload: dict, status_code: int = 200):
    """表单提交走 303 回页面；API 调用（redirect=0）返回 JSON。"""
    if redirect:
        key = "msg" if status_code < 400 else "err"
        target = f"/?{key}={quote(str(payload.get(key, payload)))}"
        return RedirectResponse(target, status_code=303)
    return JSONResponse(payload, status_code=status_code)


@app.get("/")
def index(request: Request, msg: str = "", err: str = ""):
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "st": service.status(),
            "msg": msg,
            "err": err,
        },
    )


@app.get("/api/status")
def api_status():
    return service.status()


@app.get("/api/op/{seq}")
def api_op(seq: int):
    try:
        return service.get_op(seq)
    except NotFound as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)


@app.get("/api/renewal/{renewal_id}")
def api_renewal(renewal_id: int):
    try:
        return service.get_renewal(renewal_id)
    except NotFound as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)


@app.get("/api/renewal/{renewal_id}/csr")
def api_renewal_csr(renewal_id: int):
    try:
        r = service.get_renewal(renewal_id)
    except NotFound as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)
    return Response(
        content=r["csr_pem"].encode(),
        media_type="application/pkcs10",
        headers={
            "Content-Disposition": f'attachment; filename="renewal-{renewal_id}.csr"'
        },
    )


@app.post("/renewal")
def create_renewal(request: Request, key_type: str = Form("rsa"),
                   redirect: int = Form(0)):
    try:
        r = service.create_renewal(key_type)
    except BadRequest as exc:
        return _respond(request, redirect, {"err": str(exc)}, 400)
    msg = (f"已生成续期申请 #{r['id']}（独立私钥留存在服务端）。"
           f"请下载 CSR 交给 CA，回签后在此上传 PEM 链。")
    return _respond(
        request, redirect,
        {"msg": msg, "renewal_id": r["id"], "renewal": r},
    )


@app.post("/renewal/{renewal_id}/revoke")
def revoke_renewal(request: Request, renewal_id: int, redirect: int = Form(0)):
    try:
        r = service.revoke_renewal(renewal_id)
    except NotFound as exc:
        return _respond(request, redirect, {"err": str(exc)}, 404)
    except Conflict as exc:
        return _respond(request, redirect, {"err": str(exc)}, 409)
    return _respond(
        request, redirect,
        {"msg": f"续期申请 #{renewal_id} 已撤销，该申请不能再登记候选。",
         "renewal": r},
    )


@app.post("/renewal/{renewal_id}/signback")
async def signback(
    request: Request,
    renewal_id: int,
    cert_file: UploadFile,
    redirect: int = Form(0),
):
    chain = await cert_file.read()
    try:
        # 校验与事务均为阻塞操作，放入线程池，避免阻塞事件循环
        # （否则并发撤销/回签请求会被串行化到回签完成后才处理）
        version, created = await run_in_threadpool(
            service.signback, renewal_id, chain
        )
    except certutil.CertError as exc:
        return _respond(request, redirect, {"err": f"回签校验失败：{exc}"}, 400)
    except NotFound as exc:
        return _respond(request, redirect, {"err": str(exc)}, 404)
    except Conflict as exc:
        return _respond(request, redirect, {"err": str(exc)}, 409)
    if created:
        msg = f"回签校验通过，已用申请私钥登记为候选版本 #{version['id']}"
    else:
        msg = f"该回签证书已登记（版本 #{version['id']}），未重复登记"
    return _respond(
        request, redirect,
        {"msg": msg, "version_id": version["id"], "created": created},
    )


@app.post("/upload")
async def upload(
    request: Request,
    cert_file: UploadFile,
    key_file: UploadFile,
    redirect: int = Form(0),
):
    chain = await cert_file.read()
    key = await key_file.read()
    try:
        version, created = await run_in_threadpool(service.upload, chain, key)
    except certutil.CertError as exc:
        return _respond(request, redirect, {"err": f"证书校验失败：{exc}"}, 400)
    if created:
        msg = f"上传成功，已登记为候选版本 #{version['id']}"
    else:
        msg = f"相同证书已存在（版本 #{version['id']}），未重复登记"
    return _respond(request, redirect, {"msg": msg, "version_id": version["id"]})


@app.post("/activate")
def activate(
    request: Request,
    version_id: int = Form(...),
    base_version_id: int = Form(...),
    redirect: int = Form(0),
):
    try:
        op = service.activate(version_id, base_version_id)
    except Conflict as exc:
        return _respond(request, redirect, {"err": str(exc)}, 409)
    except BadRequest as exc:
        return _respond(request, redirect, {"err": str(exc)}, 400)
    except NotFound as exc:
        return _respond(request, redirect, {"err": str(exc)}, 404)
    state_msg = {
        "succeeded": f"启用成功：版本 #{op['version_id']} 已在用，新 TLS 连接已核实",
        "pending_verify": "已提交，但回执不明/暂无法核实，状态待核实，系统会自动跟进",
        "failed": f"启用失败：{op.get('detail') or ''}",
    }
    msg = state_msg.get(op["state"], f"操作状态：{op['state']}")
    code = 200 if op["state"] == "succeeded" else (202 if op["state"] == "pending_verify" else 500)
    return _respond(
        request, redirect, {"msg": msg, "op": op}, code if not redirect else 200
    )
