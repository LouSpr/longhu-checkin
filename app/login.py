"""龙湖 App 端「手机号 + 短信验证码」登录。

用于添加新账号，不再需要抓包导 token。

签名算法与密钥来自 App 内嵌 H5 的前端脚本（getSignHeader）：
    params_str = 按 key 排序的 "k=v" 用 "|" 连接（跳过空值 / null）
    sign = md5( [params_str + "&"] + 毫秒时间戳 + "&" + SIGN_SECRET_APP )

注意 app/longhu.py 里的 SIGN_SECRET_MICRO_APP 是**小程序**密钥，
App 端（X-Client-Type: app）必须用本文件的 SIGN_SECRET_APP。

实测（2026-11-07）：
- 51 条抓包请求逐条复现，签名 51/51 一致；
- 现场生成签名调用 sendSmsCodeSecret 返回 909001 请操作图形验证；
- 调用 smsCodeSecret 返回 900004 验证码已过期（均为业务码，非签名错误 500）。
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any

import requests

BASE = "https://gw2c-hw-open.longfor.com"
API_VERSION = "v1_30_2"
BU_CODE = "L00602"
CHANNEL = "L0"
APP_VERSION = "1.30.2"

# App 前端写死的客户端签名密钥（与 microApp 密钥不同）。
# 公开下发常量，来自 App 内嵌 H5 前端 JS 的 getSignHeader；失效时到
# https://supera-h5.wan-prod.longfor.com 的主 JS 里搜 getSignHeader 重新提取。
SIGN_SECRET_APP = "20jtGtg5TQ9V1A3Q4RsxBzJqb@^WUS%m"

SEND_SMS_PATH = f"/supera/mine/{API_VERSION}/publicApi/login/sendSmsCodeSecret"
LOGIN_PATH = f"/supera/mine/{API_VERSION}/publicApi/login/smsCodeSecret"


class LoginError(Exception):
    """登录接口返回了业务错误。"""

    def __init__(self, code: str, message: str, extra_code: str = ""):
        self.code = str(code)
        self.message = message
        self.extra_code = str(extra_code or "")
        super().__init__(f"[{self.extra_code or self.code}] {self.message}")


def _js_str(value: Any) -> str:
    """对齐前端 String(v) 的表现（签名串里主要是字符串）。"""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def _normalize(params: dict) -> str:
    """对齐前端 n$3()：排序后 k=v 用 '|' 连接，跳过空值/null。"""
    parts = []
    for key in sorted(params.keys()):
        value = params[key]
        if isinstance(value, list):
            # 前端对数组是 "[a,b]" 形式，元素是对象时递归成 "{k=v|...}"
            chunks = ["["]
            if not value:
                chunks.append("]")
            else:
                for i, item in enumerate(value):
                    if isinstance(item, list):
                        chunks.append(json.dumps(item, separators=(",", ":")))
                    elif isinstance(item, dict):
                        chunks.append("{" + _normalize(item) + "}")
                    else:
                        chunks.append(_js_str(item))
                    chunks.append("," if i < len(value) - 1 else "]")
            value = "".join(chunks)
        elif isinstance(value, dict):
            value = "{" + _normalize(value) + "}"
        text = _js_str(value)
        if text.strip() and text != "null":
            parts.append(f"{key}={text}")
    return "|".join(parts)


def sign_headers(body: dict, client: str = "app", ts: str | None = None) -> dict:
    """生成 X-LONGZHU-* 签名头。client 传 app / microApp。"""
    secrets = {
        "app": SIGN_SECRET_APP,
        "microApp": "Q74eKtH5LePYfSjIiflUbCL2gxjTa7rF",
    }
    joined = _normalize(body)
    stamp = str(ts if ts is not None else int(time.time() * 1000))
    raw = (joined + "&" if joined else "") + stamp + "&" + secrets[client]
    return {
        "X-LONGZHU-TimeStamp": stamp,
        "X-Client-Type": client,
        "X-LONGZHU-Sign": hashlib.md5(raw.encode("utf-8")).hexdigest(),
    }


def _common_headers() -> dict:
    return {
        "Host": "gw2c-hw-open.longfor.com",
        "X-LF-Bucode": BU_CODE,
        "Accept": "*/*",
        "X-LF-Api-Version": API_VERSION,
        "X-LF-App-Version": APP_VERSION,
        "X-LF-Stage": "RELEASE",
        "X-Gaia-Api-Key": "98717e7a-a039-46af-8143-be7558a089c0",
        "X-LF-Channel": CHANNEL,
        "Accept-Language": "zh-Hans-CN;q=1.0",
        "User-Agent": f"com.longfor.supera/{APP_VERSION} iOS/26.6",
        "X-LF-Bundle-id": "com.longfor.supera",
        "Content-Type": "application/json",
    }


def _post(path: str, body: dict, timeout: int = 20) -> dict:
    headers = _common_headers()
    headers.update(sign_headers(body))
    # 与 app/longhu.py 一致：强制直连，别被宿主机/容器里的代理环境变量带偏。
    session = requests.Session()
    session.trust_env = False
    try:
        resp = session.post(BASE + path, headers=headers, json=body, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        raise LoginError("network", f"网络请求失败: {exc}") from exc
    except ValueError as exc:
        raise LoginError("parse", f"响应不是 JSON: {exc}") from exc
    finally:
        session.close()
    code = str(data.get("code", ""))
    extra = str(data.get("extraCode", "") or "")
    if code != "200":
        raise LoginError(code, data.get("message") or data.get("extraMessage") or "请求失败", extra)
    return data.get("data") or {}


def b64_mobile(mobile: str) -> str:
    """手机号 base64（App 的请求体格式）。"""
    return base64.b64encode(mobile.strip().encode()).decode()


def send_sms_code(mobile: str, fingerprint: str, risk_token: str = "",
                  prefix: str = "+86") -> dict:
    """发送短信验证码。

    fingerprint 必须是该账号自己的顶象设备指纹（一账号一指纹）。
    risk_token 是顶象滑块凭证，格式 "<token>:<指纹>"；服务端要求人机验证时必传，
    缺失会返回 909001「请操作图形验证」。
    """
    body = {
        "channel": CHANNEL,
        "buCode": BU_CODE,
        "mobile": b64_mobile(mobile),
        "prefix": prefix,
        "fingerprint": fingerprint,
    }
    if risk_token:
        body["riskToken"] = risk_token
    return _post(SEND_SMS_PATH, body)


def login_by_code(mobile: str, code: str, fingerprint: str,
                  prefix: str = "+86") -> dict:
    """用短信验证码登录，成功返回 {"token": ..., "lmid": ..., "isNew": ...}。"""
    body = {
        "buCode": BU_CODE,
        "channel": CHANNEL,
        "code": str(code).strip(),
        "fingerprint": fingerprint,
        "prefix": prefix,
        "mobile": b64_mobile(mobile),
    }
    return _post(LOGIN_PATH, body)
