# -*- coding: utf-8 -*-
"""请求重构上下文提取（精简版：只保留与参数 / API 路径相关的信息）。

从 bundle 中定位 axios 请求拦截器，提取两类信息：
- envelope_rewrite：拦截器运行时重写的信封字段（nonceStr/timestamp/sign）。
  这些字段是协议字段、不是业务参数，下游必须从 params 剥离。
- path_prefix / api_is_exempt / final_path：拦截器追加的 URL 前缀与目标 API 的最终请求路径。

设计（性能）：extract_reconstruction_bundle() 对整份 bundle 只扫描一次；
apply_reconstruction() 再按目标 API 判定豁免、产出该 API 的重构上下文。
签名算法、body 加密、X-Security 安全头等与"参数/路径"无关的信息不在此提取。
"""

import re
from typing import Dict, List

_INTERCEPTOR_RE = re.compile(r"interceptors\.request\.use")
_ENVELOPE_REWRITE_PATTERNS: List[tuple] = [
    ("nonceStr", re.compile(r"nonceStr\s*=\s*([^,\n;]{1,120})")),
    ("timestamp", re.compile(r"timestamp\s*=\s*([^,\n;]{1,120})")),
    ("sign", re.compile(r"(?:\.|e\.)?sign\s*=\s*([^,\n;]{1,200})")),
]
_PREFIX_RE = re.compile(r"baseURL\s*\+?=\s*[\"']([^\"']+)[\"']")
_EXEMPT_LIST_RE = re.compile(r"const\s+v\s*=\s*\[(.*?)\]", re.S)


def extract_reconstruction_bundle(code: str) -> Dict:
    """整份 bundle 扫描一次，返回共享重构信息；无拦截器时返回空 dict。"""
    ctx: Dict = {}
    matches = list(_INTERCEPTOR_RE.finditer(code))
    if not matches:
        return ctx

    off = matches[0].start()
    cb = code[off:off + 6000]

    envelope_rewrite = {}
    for name, pat in _ENVELOPE_REWRITE_PATTERNS:
        m = pat.search(cb)
        if m:
            envelope_rewrite[name] = m.group(1).strip()
    if envelope_rewrite:
        ctx["envelope_rewrite"] = envelope_rewrite

    m = _PREFIX_RE.search(cb)
    if m:
        ctx["path_prefix"] = m.group(1)

    window = code[max(0, off - 6000):off + 6000]
    m = _EXEMPT_LIST_RE.search(window)
    if m:
        ctx["exemption_list"] = re.findall(r"[\"']([^\"']+)[\"']", m.group(1))

    return ctx


def apply_reconstruction(rc: Dict, api_path: str) -> Dict:
    """按目标 API 判定豁免，产出该 API 的重构上下文（精简契约）。"""
    if not rc:
        return {}

    out: Dict = {}
    if "envelope_rewrite" in rc:
        out["envelope_rewrite"] = rc["envelope_rewrite"]

    exempt = False
    for prefix in rc.get("exemption_list", []):
        if prefix.endswith("/"):
            if api_path.startswith(prefix):
                exempt = True
                break
        else:
            if api_path == prefix or api_path.startswith(prefix + "/"):
                exempt = True
                break
    out["api_is_exempt"] = exempt

    prefix = rc.get("path_prefix", "")
    out["path_prefix"] = prefix
    out["final_path"] = (
        api_path
        if exempt or not prefix
        else prefix.rstrip("/") + "/" + api_path.lstrip("/")
    )
    return out
