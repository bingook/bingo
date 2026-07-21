"""Canonical target ownership for executor-built URLs.

The model may suggest a path or even an absolute URL, but the executor owns the
authoritative target host.  This module rewrites model-proposed request URLs so
their path/query can be reused without letting the model drift to a lookalike
host such as TARGET.kr -> TARGET.jp.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Callable
from urllib.parse import urlparse, urlunparse


HostPredicate = Callable[[str], bool]


URL_KEYS = {
    "url",
    "base_url",
    "target_url",
    "login_url",
    "admin_url",
    "webshell_url",
    "verify_url",
    "upload_url",
    "endpoint_url",
}

HEADER_URL_KEYS = {"referer", "origin"}
HEADER_HOST_KEYS = {"host"}

_COMMON_REGISTRABLE_SUFFIXES = {
    "ac.kr", "co.kr", "es.kr", "go.kr", "ne.kr", "or.kr", "pe.kr", "re.kr",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.jp", "ne.jp", "or.jp",
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au", "edu.au",
    "com.br", "net.br", "org.br",
    "com.tr", "net.tr", "org.tr",
    "github.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app",
    "herokuapp.com", "appspot.com", "firebaseapp.com", "web.app",
    "cloudfront.net", "azurewebsites.net",
}

_BARE_HOST_FILE_EXTENSIONS = {
    "asp", "aspx", "php", "html", "htm", "jsp", "cgi", "do", "action",
    "js", "css", "json", "xml", "txt", "png", "jpg", "jpeg", "gif", "svg",
}


def _clean_host(host: str) -> str:
    h = (host or "").strip().lower().rstrip(".,/")
    if h.startswith("[") and "]" in h:
        h = h[1:h.index("]")]
    elif ":" in h:
        h = h.split(":", 1)[0]
    return h.strip(".").removeprefix("www.")


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(_clean_host(host))
        return True
    except Exception:
        return False


def _registrable_domain(host: str) -> str:
    h = _clean_host(host)
    if not h or _is_ip_literal(h):
        return h
    labels = [part for part in h.split(".") if part]
    if len(labels) < 2:
        return h

    for suffix_len in (3, 2):
        if len(labels) <= suffix_len:
            continue
        suffix = ".".join(labels[-suffix_len:])
        if suffix in _COMMON_REGISTRABLE_SUFFIXES:
            return ".".join(labels[-(suffix_len + 1):])
    return ".".join(labels[-2:])


def _root_label(host: str) -> str:
    root = _registrable_domain(host)
    if not root or _is_ip_literal(root):
        return root
    return root.split(".", 1)[0]


@dataclass(frozen=True)
class Canonicalization:
    value: object
    changed: bool = False
    note: str = ""


@dataclass(frozen=True)
class TargetState:
    """Executor-owned canonical target identity."""

    canonical_url: str
    scheme: str
    netloc: str
    host: str

    @staticmethod
    def from_target(target: str) -> "TargetState | None":
        raw = (target or "").strip()
        if not raw:
            return None
        parse_raw = raw if "://" in raw else f"https://{raw}"
        parsed = urlparse(parse_raw)
        host = (parsed.hostname or "").lower().strip(".")
        if not host:
            return None
        scheme = parsed.scheme or "https"
        netloc = host
        try:
            if parsed.port:
                netloc = f"{host}:{parsed.port}"
        except ValueError:
            pass
        canonical_url = f"{scheme}://{netloc}"
        return TargetState(
            canonical_url=canonical_url,
            scheme=scheme,
            netloc=netloc,
            host=host,
        )

    def build_url(self, path_or_url: str) -> str:
        value = (path_or_url or "").strip()
        if not value:
            return self.canonical_url + "/"
        if value.startswith("//"):
            value = "/" + value.lstrip("/")
        if not value.startswith("/") and "://" not in value:
            value = "/" + value
        if value.startswith("/"):
            return self.canonical_url + value
        return value

    def canonicalize_url(
        self,
        value: str,
        *,
        allowed_host: HostPredicate | None = None,
        external_allowed_host: HostPredicate | None = None,
    ) -> Canonicalization:
        raw = value or ""
        stripped = raw.strip()
        if not stripped:
            return Canonicalization(raw)
        if stripped.startswith("/") and not stripped.startswith("//"):
            built = self.build_url(stripped)
            if built != raw:
                return Canonicalization(
                    built,
                    True,
                    f"path-only URL built with canonical target: {stripped} -> {built}",
                )
            return Canonicalization(raw)
        if not stripped.lower().startswith(("http://", "https://")):
            return Canonicalization(raw)

        parsed = urlparse(stripped)
        host = (parsed.hostname or "").lower().strip(".")
        if not host:
            return Canonicalization(raw)
        if host.rsplit(".", 1)[-1] in _BARE_HOST_FILE_EXTENSIONS:
            pseudo_path = "/" + parsed.netloc + (parsed.path or "")
            rewritten = urlunparse(
                (
                    self.scheme,
                    self.netloc,
                    pseudo_path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment,
                )
            )
            if rewritten == raw:
                return Canonicalization(raw)
            return Canonicalization(
                rewritten,
                True,
                "executor rebuilt malformed file-style URL under authoritative target",
            )
        if allowed_host and allowed_host(host):
            return Canonicalization(raw)
        if external_allowed_host and external_allowed_host(host):
            return Canonicalization(raw)

        rewritten = urlunparse(
            (
                self.scheme,
                self.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )
        if rewritten == raw:
            return Canonicalization(raw)
        return Canonicalization(
            rewritten,
            True,
            f"executor canonicalized model URL host to authoritative target: {self.host}",
        )

    def canonicalize_host(
        self,
        value: str,
        *,
        allowed_host: HostPredicate | None = None,
        external_allowed_host: HostPredicate | None = None,
        only_lookalike: bool = True,
    ) -> Canonicalization:
        raw = value or ""
        stripped = raw.strip()
        if not stripped or "/" in stripped or "://" in stripped:
            return Canonicalization(raw)

        host_part = stripped
        suffix = ""
        if ":" in stripped and not stripped.startswith("["):
            host_part, port_part = stripped.rsplit(":", 1)
            if port_part.isdigit():
                suffix = f":{port_part}"
            else:
                host_part = stripped
                suffix = ""

        host = _clean_host(host_part)
        if not host or "." not in host or _is_ip_literal(host):
            return Canonicalization(raw)
        if only_lookalike and host.rsplit(".", 1)[-1] in _BARE_HOST_FILE_EXTENSIONS:
            return Canonicalization(raw)
        if allowed_host and allowed_host(host):
            return Canonicalization(raw)
        if external_allowed_host and external_allowed_host(host):
            return Canonicalization(raw)
        if only_lookalike and _root_label(host) != _root_label(self.host):
            return Canonicalization(raw)

        replacement = self.netloc if suffix else self.host
        if replacement == stripped:
            return Canonicalization(raw)
        return Canonicalization(
            replacement,
            True,
            f"executor canonicalized model host token to authoritative target: {self.host}",
        )


def canonicalization_notice(notes: list[str]) -> str:
    unique = []
    seen = set()
    for note in notes:
        if not note or note in seen:
            continue
        seen.add(note)
        unique.append(note)
    if not unique:
        return ""
    body = "\n".join(f"  - {note}" for note in unique[:12])
    return (
        "[TARGET_CANONICALIZED]\n"
        "Executor owns target identity; model-proposed host was rewritten while preserving path/query.\n"
        f"{body}\n"
        "[/TARGET_CANONICALIZED]"
    )


def canonicalize_tool_args(
    args: dict,
    state: TargetState | None,
    *,
    allowed_host: HostPredicate | None = None,
    external_allowed_host: HostPredicate | None = None,
) -> tuple[dict, str]:
    if not state or not isinstance(args, dict):
        return args, ""

    notes: list[str] = []

    def rewrite_value(value: object, *, build_path: bool = False) -> object:
        if isinstance(value, str):
            if build_path or value.strip().lower().startswith(("http://", "https://")):
                result = state.canonicalize_url(
                    value,
                    allowed_host=allowed_host,
                    external_allowed_host=external_allowed_host,
                )
                if result.changed:
                    notes.append(result.note)
                return result.value
            return value
        if isinstance(value, list):
            return [rewrite_value(item, build_path=build_path) for item in value]
        if isinstance(value, tuple):
            return tuple(rewrite_value(item, build_path=build_path) for item in value)
        return value

    new_args: dict = dict(args)
    for key, value in list(new_args.items()):
        key_l = str(key).lower()
        if key_l in URL_KEYS:
            new_args[key] = rewrite_value(value, build_path=True)
        elif key_l in {"headers", "session_headers", "extra_headers"} and isinstance(value, dict):
            headers = dict(value)
            for h_key, h_value in list(headers.items()):
                h_key_l = str(h_key).lower()
                if h_key_l in HEADER_URL_KEYS:
                    headers[h_key] = rewrite_value(h_value, build_path=False)
                elif h_key_l in HEADER_HOST_KEYS and isinstance(h_value, str):
                    result = state.canonicalize_host(
                        h_value,
                        allowed_host=allowed_host,
                        external_allowed_host=external_allowed_host,
                        only_lookalike=False,
                    )
                    if result.changed:
                        notes.append(result.note)
                    headers[h_key] = result.value
            new_args[key] = headers

    return new_args, canonicalization_notice(notes)


def canonicalize_text_urls(
    text: str,
    state: TargetState | None,
    *,
    allowed_host: HostPredicate | None = None,
    external_allowed_host: HostPredicate | None = None,
    rewrite_bare_lookalike_hosts: bool = True,
) -> tuple[str, str]:
    if not state or not text:
        return text, ""

    notes: list[str] = []
    url_re = re.compile(r"https?://[A-Za-z0-9._-]+(?::\d+)?(?:/[^\s'\"<>)]*)?", re.IGNORECASE)

    def replace(match: re.Match[str]) -> str:
        original = match.group(0)
        result = state.canonicalize_url(
            original,
            allowed_host=allowed_host,
            external_allowed_host=external_allowed_host,
        )
        if result.changed:
            notes.append(result.note)
            return str(result.value)
        return original

    rewritten = url_re.sub(replace, text)
    if rewrite_bare_lookalike_hosts:
        host_re = re.compile(
            r"(?<![@/\w.-])([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+(?::\d+)?)(?![\w.-])"
        )

        def replace_host(match: re.Match[str]) -> str:
            original = match.group(1)
            result = state.canonicalize_host(
                original,
                allowed_host=allowed_host,
                external_allowed_host=external_allowed_host,
                only_lookalike=True,
            )
            if result.changed:
                notes.append(result.note)
                return str(result.value)
            return original

        rewritten = host_re.sub(replace_host, rewritten)
    return rewritten, canonicalization_notice(notes)
