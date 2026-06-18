"""bingo/tools/webhook_reporter.py — Slack / Discord / Telegram 실시간 보고 (v2.9.0)

기능:
  - Slack webhook 으로 발견 즉시 알림
  - Discord webhook 지원
  - Telegram Bot API 지원
  - 내부 큐: 대량 발견 시 배치 전송 (Rate-limit 방지)
  - 심각도 필터: CRITICAL만 즉시 전송, 나머지 배치
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AlertMessage:
    title: str
    body: str
    severity: Severity = Severity.HIGH
    url: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_slack_block(self) -> dict:
        emoji = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFO: "⚪",
        }.get(self.severity, "⚪")
        text = f"{emoji} *[{self.severity}] {self.title}*\n{self.body}"
        if self.url:
            text += f"\nTarget: `{self.url}`"
        return {
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": text}}
            ]
        }

    def to_discord_embed(self) -> dict:
        color = {
            Severity.CRITICAL: 0xFF0000,
            Severity.HIGH: 0xFF8800,
            Severity.MEDIUM: 0xFFFF00,
            Severity.LOW: 0x00FF00,
            Severity.INFO: 0x888888,
        }.get(self.severity, 0x888888)
        return {
            "embeds": [{
                "title": f"[{self.severity}] {self.title}",
                "description": self.body + (f"\nTarget: {self.url}" if self.url else ""),
                "color": color,
            }]
        }

    def to_telegram_text(self) -> str:
        return f"[{self.severity}] {self.title}\n{self.body}" + (
            f"\n🎯 {self.url}" if self.url else ""
        )


def _http_post(url: str, payload: dict, headers: dict | None = None) -> bool:
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={**(headers or {}), "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10):
            return True
    except Exception:
        return False


class SlackReporter:
    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    def send(self, msg: AlertMessage) -> bool:
        if not self.webhook_url:
            return False
        return _http_post(self.webhook_url, msg.to_slack_block())


class DiscordReporter:
    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    def send(self, msg: AlertMessage) -> bool:
        if not self.webhook_url:
            return False
        return _http_post(self.webhook_url, msg.to_discord_embed())


class TelegramReporter:
    API_BASE = "https://api.telegram.org/bot{token}/sendMessage"

    def __init__(self, bot_token: str, chat_id: str) -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id

    def send(self, msg: AlertMessage) -> bool:
        if not self.bot_token or not self.chat_id:
            return False
        url = self.API_BASE.format(token=self.bot_token)
        payload = {
            "chat_id": self.chat_id,
            "text": msg.to_telegram_text(),
            "parse_mode": "Markdown",
        }
        return _http_post(url, payload)


class WebhookReporter:
    """통합 Webhook 리포터 (배치 큐 + 즉시 전송)"""

    def __init__(
        self,
        slack_url: str = "",
        discord_url: str = "",
        telegram_token: str = "",
        telegram_chat: str = "",
        instant_severities: set[Severity] | None = None,
        batch_interval: float = 30.0,
    ) -> None:
        self._reporters: list = []
        if slack_url:
            self._reporters.append(SlackReporter(slack_url))
        if discord_url:
            self._reporters.append(DiscordReporter(discord_url))
        if telegram_token and telegram_chat:
            self._reporters.append(TelegramReporter(telegram_token, telegram_chat))

        self.instant_severities = instant_severities or {Severity.CRITICAL, Severity.HIGH}
        self.batch_interval = batch_interval
        self._queue: list[AlertMessage] = []
        self._lock = threading.Lock()
        self._batch_thread = threading.Thread(target=self._batch_loop, daemon=True)
        self._batch_thread.start()

    def _send_all(self, msg: AlertMessage) -> None:
        for r in self._reporters:
            try:
                r.send(msg)
            except Exception:
                pass

    def _batch_loop(self) -> None:
        while True:
            time.sleep(self.batch_interval)
            with self._lock:
                if not self._queue:
                    continue
                msgs = self._queue[:]
                self._queue.clear()
            # 배치 요약 메시지 생성
            summary = "\n".join(f"• [{m.severity}] {m.title}" for m in msgs)
            batch_msg = AlertMessage(
                title=f"Bingo 배치 리포트 ({len(msgs)}건)",
                body=summary,
                severity=Severity.INFO,
            )
            self._send_all(batch_msg)

    def report(self, msg: AlertMessage) -> None:
        """심각도에 따라 즉시 전송 또는 큐 추가"""
        if msg.severity in self.instant_severities:
            self._send_all(msg)
        else:
            with self._lock:
                self._queue.append(msg)

    def report_finding(
        self,
        title: str,
        body: str,
        severity: str = "HIGH",
        url: str = "",
    ) -> None:
        sev = Severity(severity) if severity in Severity._value2member_map_ else Severity.HIGH
        self.report(AlertMessage(title=title, body=body, severity=sev, url=url))

    def flush(self) -> None:
        """강제 즉시 전송"""
        with self._lock:
            msgs = self._queue[:]
            self._queue.clear()
        for m in msgs:
            self._send_all(m)
