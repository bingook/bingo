"""
bingo 중앙 다국어 시스템
========================
모든 파일에서:
    from .i18n import t
    print(t("key", "fallback"))

언어 설정:
    from .i18n import set_lang
    set_lang("zh")  # ko / zh / en

v6.2.178: zh 설정 시 한국어(Hangul) 누출 방지 가드.
  - zh 번역에 Hangul이 섞이면 en으로 폴백
  - default에 Hangul이 있고 lang!=ko 이면 en 우선
"""
from __future__ import annotations

import re

_lang: str = "en"
_HANGUL_RE = re.compile(r"[\uac00-\ud7a3]")


def set_lang(lang: str) -> None:
    """전역 언어 설정. BingoTerminal 초기화 시 호출."""
    global _lang
    if lang in ("ko", "zh", "en"):
        _lang = lang
    else:
        _lang = "en"


def get_lang() -> str:
    return _lang


def has_hangul(text: str) -> bool:
    """문자열에 한글(Hangul) 음절이 포함되어 있는지."""
    return bool(text and _HANGUL_RE.search(text))


def sanitize_lang_text(text: str, lang: str | None = None, en_fallback: str = "") -> str:
    """v6.2.178 Type A: lang=zh(또는 en)인데 Hangul이 있으면 en_fallback/원문 교정.

    - ko: 그대로
    - zh/en: Hangul 포함 시 en_fallback 사용 (없으면 원문 유지하되 호출측에서 en을 넘기는 게 원칙)
    """
    if not text:
        return text or en_fallback
    lang = lang or _lang
    if lang == "ko":
        return text
    if has_hangul(text):
        return en_fallback or text
    return text


def t(key: str, default: str = "") -> str:
    """현재 언어로 문자열 반환. 키 없으면 default 반환.

    v6.2.178: zh에서 Hangul 누출 시 en → (Hangul-free default) 순 폴백.
    """
    from .lang.strings import _STRINGS
    entry = _STRINGS.get(key)
    if entry is None:
        # default가 Hangul이고 lang!=ko → 빈/키 대신 default만 반환하되 경고성 방지:
        if _lang != "ko" and has_hangul(default):
            return key if not default else (default if _lang == "ko" else key)
        return default or key

    primary = entry.get(_lang) or ""
    en = entry.get("en") or ""
    if _lang == "zh" and has_hangul(primary):
        # 잘못된 zh 번역(한글 혼입) → en
        primary = en
    if not primary:
        primary = en or default or key
    if _lang == "zh" and has_hangul(primary):
        primary = en or key
    return primary
