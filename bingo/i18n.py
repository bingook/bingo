"""
bingo 중앙 다국어 시스템
========================
모든 파일에서:
    from .i18n import t
    print(t("key", "fallback"))

언어 설정:
    from .i18n import set_lang
    set_lang("zh")  # ko / zh / en
"""
from __future__ import annotations

_lang: str = "en"


def set_lang(lang: str) -> None:
    """전역 언어 설정. BingoTerminal 초기화 시 호출."""
    global _lang
    if lang in ("ko", "zh", "en"):
        _lang = lang
    else:
        _lang = "en"


def get_lang() -> str:
    return _lang


def t(key: str, default: str = "") -> str:
    """현재 언어로 문자열 반환. 키 없으면 default 반환."""
    from .lang.strings import _STRINGS
    entry = _STRINGS.get(key)
    if entry is None:
        return default or key
    return entry.get(_lang) or entry.get("en") or default or key
