"""
bingo/core/proxy_rotator.py — 프록시 풀 관리 + 자동 로테이션 (v4.2.0)

【역할】
  - 검증된 프록시를 풀(deque)에 보관
  - IP 차단 감지 → 자동으로 다음 프록시 교체
  - 풀 고갈 시 백그라운드에서 재수집/재검증
  - 블랙리스트: 실패 3회 이상인 프록시 자동 퇴출
  - 현재 활성 프록시를 환경변수(HTTP_PROXY/HTTPS_PROXY)에 주입

【스레드 모델】
  - _refill_worker: 데몬 스레드, 풀 부족 시 자동 재수집
  - rotate() 는 메인 스레드에서 호출 (동기)
  - is_blocked() 는 IPBlockDetector 위임

【외부 인터페이스】
  ProxyRotator.get_current()    → 현재 활성 ProxyInfo 또는 None
  ProxyRotator.rotate()         → 다음 프록시로 교체
  ProxyRotator.auto_rotate_if_blocked() → 차단 감지 시 자동 교체
  ProxyRotator.inject_env()     → os.environ 에 프록시 주입
  ProxyRotator.clear_env()      → os.environ 프록시 항목 제거
  ProxyRotator.status()         → dict (현황 요약)
"""
from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from typing import Deque, List, Optional, Set, Tuple

from .ip_block_detector import IPBlockDetector, BlockDetectResult, make_detector
from .proxy_hunter import ProxyInfo, ProxyHunter

logger = logging.getLogger(__name__)

# ── 풀 관리 상수 ─────────────────────────────────────────────────────────────
_POOL_MIN      = 5    # 풀 최소 유지 개수 → 이 아래로 떨어지면 재수집 트리거
_POOL_MAX      = 50   # 풀 최대 크기 (넘치면 낮은 점수부터 제거)
_BLACKLIST_TTL = 1800  # 블랙리스트 TTL (초): 30분 후 자동 해제
_MAX_FAIL      = 3     # 이 횟수 이상 실패 → 블랙리스트
_REFILL_SLEEP  = 30    # 재수집 쓰레드 대기 간격 (초)


class ProxyRotator:
    """
    프록시 풀 관리 + 자동 차단 감지 로테이션.

    사용법:
        rotator = ProxyRotator(target="https://example.com")
        rotator.start()          # 백그라운드 재수집 시작
        ...
        result = rotator.auto_rotate_if_blocked()
        if result.rotated:
            print(f"교체 → {rotator.get_current().url}")
    """

    def __init__(self, target: str, prefill: bool = True):
        self._target    = target
        self._pool:     Deque[ProxyInfo] = deque()
        self._current:  Optional[ProxyInfo] = None
        self._blacklist: Set[Tuple[str,int]] = set()
        self._blacklist_time: dict[Tuple[str,int], float] = {}
        self._lock      = threading.Lock()
        self._detector  = make_detector(target)
        self._stop_evt  = threading.Event()
        self._refill_t: Optional[threading.Thread] = None
        self._rotation_count = 0
        self._last_rotate_at = 0.0

        if prefill:
            self._initial_fill()

    # ── 초기 풀 채우기 ──────────────────────────────────────────────────────
    def _initial_fill(self) -> None:
        """최초 프록시 수집 (동기, 최대 8초 내)."""
        logger.info("[proxy_rotator] 초기 프록시 풀 수집 중...")
        try:
            hunter  = ProxyHunter(target=self._target, workers=15)
            proxies = hunter.hunt(min_count=_POOL_MIN, max_check=80)
            with self._lock:
                for p in proxies:
                    if len(self._pool) < _POOL_MAX:
                        self._pool.append(p)
            logger.info(f"[proxy_rotator] 초기 풀 크기: {len(self._pool)}")
        except Exception as e:
            logger.warning(f"[proxy_rotator] 초기 수집 실패: {e}")

    # ── 백그라운드 재수집 워커 ─────────────────────────────────────────────
    def _refill_worker(self) -> None:
        """풀이 _POOL_MIN 미만이면 자동 재수집."""
        while not self._stop_evt.is_set():
            time.sleep(_REFILL_SLEEP)
            with self._lock:
                pool_size = len(self._pool)
            if pool_size < _POOL_MIN and not self._stop_evt.is_set():
                logger.info(f"[proxy_rotator] 풀 부족 ({pool_size}) → 재수집")
                try:
                    hunter  = ProxyHunter(target=self._target, workers=15)
                    proxies = hunter.hunt(min_count=_POOL_MIN, max_check=80)
                    with self._lock:
                        self._evict_blacklist()
                        for p in proxies:
                            key = (p.host, p.port)
                            if key not in self._blacklist and len(self._pool) < _POOL_MAX:
                                self._pool.appendleft(p)  # 최신 프록시를 앞에 삽입
                    logger.info(f"[proxy_rotator] 재수집 완료 → 풀: {len(self._pool)}")
                except Exception as e:
                    logger.warning(f"[proxy_rotator] 재수집 오류: {e}")

    # ── 블랙리스트 TTL 만료 정리 ──────────────────────────────────────────
    def _evict_blacklist(self) -> None:
        """TTL 만료된 블랙리스트 항목 제거 (lock 내부에서 호출)."""
        now  = time.time()
        expired = [k for k, t in self._blacklist_time.items() if now - t > _BLACKLIST_TTL]
        for k in expired:
            self._blacklist.discard(k)
            self._blacklist_time.pop(k, None)

    # ── 시작 / 정지 ──────────────────────────────────────────────────────
    def start(self) -> "ProxyRotator":
        """백그라운드 재수집 데몬 스레드 시작."""
        if self._refill_t is None or not self._refill_t.is_alive():
            self._stop_evt.clear()
            self._refill_t = threading.Thread(
                target=self._refill_worker, daemon=True, name="bingo-proxy-refill"
            )
            self._refill_t.start()
        return self

    def stop(self) -> None:
        self._stop_evt.set()

    # ── 현재 프록시 ─────────────────────────────────────────────────────
    def get_current(self) -> Optional[ProxyInfo]:
        return self._current

    # ── 다음 프록시로 교체 ─────────────────────────────────────────────
    def rotate(self) -> Optional[ProxyInfo]:
        """
        풀에서 다음 검증된 프록시를 꺼내 활성화.
        현재 프록시 실패로 표시 후 블랙리스트 등록.
        """
        with self._lock:
            # 현재 프록시 실패 처리
            if self._current is not None:
                self._current.mark_failed()
                if self._current.fail_count >= _MAX_FAIL:
                    key = (self._current.host, self._current.port)
                    self._blacklist.add(key)
                    self._blacklist_time[key] = time.time()
                    logger.info(
                        f"[proxy_rotator] 블랙리스트 등록: "
                        f"{self._current.host}:{self._current.port}"
                    )
                else:
                    # 실패 횟수 미달이면 풀 뒤에 다시 삽입
                    self._pool.append(self._current)

            # 블랙리스트 아닌 다음 프록시 선택
            self._current = None
            self._evict_blacklist()
            while self._pool:
                candidate = self._pool.popleft()
                key = (candidate.host, candidate.port)
                if key not in self._blacklist:
                    self._current = candidate
                    break

            self._rotation_count += 1
            self._last_rotate_at  = time.time()

        if self._current:
            self.inject_env()
            self._detector.reset_baseline()
            logger.info(
                f"[proxy_rotator] 교체 → {self._current.host}:{self._current.port} "
                f"(latency={self._current.latency:.2f}s) "
                f"[pool={len(self._pool)}]"
            )
        else:
            logger.warning("[proxy_rotator] 사용 가능한 프록시 없음!")
        return self._current

    # ── 차단 감지 → 자동 교체 ─────────────────────────────────────────
    def auto_rotate_if_blocked(self) -> "RotateResult":
        """
        IP 차단 감지 시 자동으로 rotate() 호출.
        반환값: RotateResult(rotated, blocked_result, new_proxy)
        """
        result = self._detector.check()
        if not result.blocked:
            return RotateResult(rotated=False, block_result=result, new_proxy=None)

        logger.warning(
            f"[proxy_rotator] IP 차단 감지! "
            f"신호={result.signals_fired} (conf={result.confidence:.0%})"
        )
        new_proxy = self.rotate()
        return RotateResult(rotated=True, block_result=result, new_proxy=new_proxy)

    # ── 환경변수 주입 ─────────────────────────────────────────────────
    def inject_env(self) -> None:
        """현재 프록시를 os.environ HTTP_PROXY / HTTPS_PROXY 에 주입."""
        if self._current is None:
            self.clear_env()
            return
        proxy_url = f"http://{self._current.host}:{self._current.port}"
        os.environ["HTTP_PROXY"]  = proxy_url
        os.environ["HTTPS_PROXY"] = proxy_url
        os.environ["http_proxy"]  = proxy_url
        os.environ["https_proxy"] = proxy_url
        logger.debug(f"[proxy_rotator] env 주입: {proxy_url}")

    def clear_env(self) -> None:
        """환경변수에서 프록시 항목 제거."""
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            os.environ.pop(k, None)

    # ── 현황 요약 ─────────────────────────────────────────────────────
    def status(self) -> dict:
        with self._lock:
            return {
                "current": self._current.url if self._current else None,
                "pool_size": len(self._pool),
                "blacklist_size": len(self._blacklist),
                "rotation_count": self._rotation_count,
                "last_rotate_at": self._last_rotate_at,
            }


# ── RotateResult ─────────────────────────────────────────────────────────────
from dataclasses import dataclass

@dataclass
class RotateResult:
    rotated:      bool
    block_result: BlockDetectResult
    new_proxy:    Optional[ProxyInfo]


# ── 글로벌 싱글턴 관리 ───────────────────────────────────────────────────────
_rotator_instance: Optional[ProxyRotator] = None
_rotator_lock = threading.Lock()


def get_rotator(target: str, prefill: bool = True) -> ProxyRotator:
    """대상 타겟에 대한 싱글턴 ProxyRotator 반환."""
    global _rotator_instance
    with _rotator_lock:
        if _rotator_instance is None or _rotator_instance._target != target:
            if _rotator_instance is not None:
                _rotator_instance.stop()
                _rotator_instance.clear_env()
            _rotator_instance = ProxyRotator(target=target, prefill=prefill)
            _rotator_instance.start()
    return _rotator_instance


def reset_rotator() -> None:
    """싱글턴 초기화 (테스트/세션 리셋용)."""
    global _rotator_instance
    with _rotator_lock:
        if _rotator_instance is not None:
            _rotator_instance.stop()
            _rotator_instance.clear_env()
            _rotator_instance = None
