"""
mobile_recon.py — Mobile App Phase 0 Reconnaissance Engine
bingo v2.2.7

Android/iOS 앱 침투테스트 초기 정찰 자동화.
Cursor 동급 수준의 모바일 보안 분석 커버리지 제공.

커버리지:
  Android: APK 정적분석, ADB 열거, 매니페스트 파싱, 시크릿 스캔, Frida 설정
  iOS:     IPA 정적분석, plist 파싱, 바이너리 분석, 클래스덤프, SSL 피닝 탐지
  공통:    네트워크 엔드포인트 추출, 딥링크 열거, 인증서 분석, 공격면 맵핑

OWASP MASTG / Mobile Top 10 기준 구현.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import struct
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────
# 데이터 클래스
# ─────────────────────────────────────────────────────────────

@dataclass
class MobileReconResult:
    """Phase 0 정찰 결과 통합 컨테이너"""
    target: str                          # APK/IPA 경로 or 패키지명
    platform: str                        # "android" | "ios" | "unknown"
    app_id: str = ""                     # package name / bundle id
    app_name: str = ""
    app_version: str = ""
    min_sdk: str = ""
    target_sdk: str = ""

    permissions: list[str] = field(default_factory=list)
    exported_activities: list[str] = field(default_factory=list)
    exported_services: list[str] = field(default_factory=list)
    exported_receivers: list[str] = field(default_factory=list)
    exported_providers: list[str] = field(default_factory=list)
    deep_links: list[str] = field(default_factory=list)

    hardcoded_secrets: list[dict] = field(default_factory=list)  # [{type, value, file, line}]
    network_endpoints: list[str] = field(default_factory=list)
    third_party_sdks: list[str] = field(default_factory=list)
    native_libraries: list[str] = field(default_factory=list)

    ssl_pinning_detected: bool = False
    root_detection_detected: bool = False
    debuggable: bool = False
    backup_allowed: bool = False
    clear_text_traffic: bool = False

    frida_commands: list[str] = field(default_factory=list)
    objection_commands: list[str] = field(default_factory=list)
    adb_commands: list[str] = field(default_factory=list)

    vulnerabilities: list[dict] = field(default_factory=list)   # [{title, severity, detail}]
    attack_surface: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"[Mobile Phase 0 — {self.platform.upper()}] {self.target}",
            f"  App ID     : {self.app_id or 'N/A'}",
            f"  Version    : {self.app_version or 'N/A'}",
            f"  Debuggable : {'⚠️  YES' if self.debuggable else 'NO'}",
            f"  Backup     : {'⚠️  ALLOWED' if self.backup_allowed else 'DISABLED'}",
            f"  Clear Text : {'⚠️  YES' if self.clear_text_traffic else 'NO'}",
            f"  SSL Pinning: {'YES' if self.ssl_pinning_detected else '⚠️  NOT DETECTED'}",
            f"  Root Detect: {'YES' if self.root_detection_detected else '⚠️  NOT DETECTED'}",
            "",
            f"  Permissions      : {len(self.permissions)}",
            f"  Exported Comps   : Activities={len(self.exported_activities)} "
            f"Services={len(self.exported_services)} "
            f"Receivers={len(self.exported_receivers)} "
            f"Providers={len(self.exported_providers)}",
            f"  Deep Links       : {len(self.deep_links)}",
            f"  Network Endpoints: {len(self.network_endpoints)}",
            f"  Hardcoded Secrets: {len(self.hardcoded_secrets)}",
            f"  3rd Party SDKs   : {len(self.third_party_sdks)}",
            f"  Vulnerabilities  : {len(self.vulnerabilities)}",
        ]
        if self.hardcoded_secrets:
            lines.append("\n  [!] Hardcoded Secrets:")
            for s in self.hardcoded_secrets[:5]:
                lines.append(f"      [{s.get('type','?')}] {s.get('value','')[:60]} @ {s.get('file','?')}:{s.get('line','?')}")
        if self.vulnerabilities:
            lines.append("\n  [!] Vulnerabilities:")
            for v in self.vulnerabilities:
                lines.append(f"      [{v.get('severity','?')}] {v.get('title','?')}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# 시크릿 패턴 (OWASP MASTG 기준)
# ─────────────────────────────────────────────────────────────

SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS_ACCESS_KEY",      re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS_SECRET_KEY",      re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("GOOGLE_API_KEY",      re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("FIREBASE_URL",        re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")),
    ("FIREBASE_KEY",        re.compile(r"(?i)firebase.{0,10}key.{0,10}['\"][A-Za-z0-9_-]{20,}['\"]")),
    ("STRIPE_KEY",          re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("STRIPE_PK",           re.compile(r"pk_live_[0-9a-zA-Z]{24,}")),
    ("GITHUB_TOKEN",        re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("SLACK_TOKEN",         re.compile(r"xox[baprs]-[0-9A-Za-z]{10,48}")),
    ("PRIVATE_KEY",         re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("HARDCODED_PASSWORD",  re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]")),
    ("HARDCODED_TOKEN",     re.compile(r"(?i)(?:token|secret|api_key|apikey)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("BASIC_AUTH",          re.compile(r"(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}")),
    ("JWT_TOKEN",           re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("KAKAO_KEY",           re.compile(r"(?i)kakao.{0,10}(?:key|token).{0,10}['\"][0-9a-f]{32,}['\"]")),
    ("NAVER_KEY",           re.compile(r"(?i)naver.{0,10}(?:key|token|id).{0,10}['\"][A-Za-z0-9_-]{10,}['\"]")),
]

# 네트워크 엔드포인트 패턴
ENDPOINT_PATTERNS: list[re.Pattern] = [
    re.compile(r"https?://[a-zA-Z0-9.\-_]+(?::\d+)?(?:/[^\s\"'<>]{0,200})?"),
    re.compile(r"(?i)(?:api|endpoint|base.?url|server.?url)\s*[:=]\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"wss?://[a-zA-Z0-9.\-_]+(?::\d+)?(?:/[^\s\"'<>]{0,200})?"),
]

# 3rd Party SDK 핑거프린트
SDK_FINGERPRINTS: dict[str, str] = {
    "com.facebook":         "Facebook SDK",
    "com.google.firebase":  "Firebase",
    "com.google.ads":       "Google Ads",
    "io.sentry":            "Sentry",
    "com.amplitude":        "Amplitude Analytics",
    "com.mixpanel":         "Mixpanel",
    "com.appsflyer":        "AppsFlyer",
    "com.adjust":           "Adjust",
    "com.onesignal":        "OneSignal",
    "com.braze":            "Braze",
    "io.branch":            "Branch",
    "com.instabug":         "Instabug",
    "com.newrelic":         "New Relic",
    "com.datadog":          "Datadog",
    "okhttp3":              "OkHttp",
    "retrofit2":            "Retrofit",
    "com.squareup":         "Square",
    "io.realm":             "Realm DB",
    "com.airbnb.lottie":    "Lottie Animation",
    "com.squareup.leakcanary": "LeakCanary",
}

# SSL 피닝 탐지 패턴
SSL_PINNING_PATTERNS: list[str] = [
    "CertificatePinner", "TrustManagerImpl", "checkServerTrusted",
    "SSLContext", "TrustKit", "TrustKitConfiguration",
    "PublicKeyPin", "certificatePin", "ssl_pinning",
    "AFSSLPinningMode", "AFNetworking", "Alamofire",
    "SecCertificate", "SecTrustEvaluate", "kSecTrustResultProceed",
    "pinCertificate", "pinnedCertificates",
]

# 루트/탈옥 탐지 패턴
ROOT_DETECTION_PATTERNS: list[str] = [
    "isRooted", "detectRoot", "RootBeer", "RootDetection",
    "/system/app/Superuser.apk", "/sbin/su", "com.noshufou.android.su",
    "Cydia", "cydia.saurik.com", "/var/lib/cydia",
    "isJailbroken", "jailbreak", "/bin/bash", "/etc/apt",
    "JailMonkey", "DTTJailbreakDetection",
]

# 위험 권한 (OWASP MASTG)
DANGEROUS_PERMISSIONS: set[str] = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.USE_BIOMETRIC",
    "android.permission.BLUETOOTH",
}


# ─────────────────────────────────────────────────────────────
# 도구 가용성 확인
# ─────────────────────────────────────────────────────────────

def _has_tool(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """명령 실행 → (stdout, stderr, returncode)"""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return "", str(e), -1


# ─────────────────────────────────────────────────────────────
# Android APK 분석
# ─────────────────────────────────────────────────────────────

class AndroidAnalyzer:
    """APK 정적 분석 — aapt / apktool / jadx 활용"""

    def __init__(self, apk_path: str):
        self.apk_path = Path(apk_path)
        self.result = MobileReconResult(target=apk_path, platform="android")
        self._decompiled_dir: Optional[Path] = None

    # ── APK ZIP 직접 파싱 ──────────────────────────────────────
    def _list_apk_contents(self) -> list[str]:
        try:
            with zipfile.ZipFile(self.apk_path) as z:
                return z.namelist()
        except Exception:
            return []

    def _read_apk_file(self, name: str) -> Optional[bytes]:
        try:
            with zipfile.ZipFile(self.apk_path) as z:
                with z.open(name) as f:
                    return f.read()
        except Exception:
            return None

    # ── aapt 기반 매니페스트 파싱 ─────────────────────────────
    def _parse_with_aapt(self) -> None:
        if not _has_tool("aapt"):
            return
        out, _, _ = _run(["aapt", "dump", "badging", str(self.apk_path)], timeout=15)
        if not out:
            return

        m = re.search(r"package: name='([^']+)'", out)
        if m:
            self.result.app_id = m.group(1)
        m = re.search(r"versionName='([^']+)'", out)
        if m:
            self.result.app_version = m.group(1)
        m = re.search(r"application-label:'([^']+)'", out)
        if m:
            self.result.app_name = m.group(1)
        m = re.search(r"sdkVersion:'([^']+)'", out)
        if m:
            self.result.min_sdk = m.group(1)
        m = re.search(r"targetSdkVersion:'([^']+)'", out)
        if m:
            self.result.target_sdk = m.group(1)

        self.result.permissions = re.findall(r"uses-permission: name='([^']+)'", out)
        self.result.deep_links = re.findall(r"android:scheme='([^']+)'", out)

    # ── apktool 기반 디컴파일 ─────────────────────────────────
    def _decompile_with_apktool(self) -> Optional[Path]:
        if not _has_tool("apktool"):
            return None
        out_dir = Path("/tmp") / f"bingo_apktool_{self.apk_path.stem}"
        if out_dir.exists():
            return out_dir
        _, _, rc = _run(["apktool", "d", "-f", str(self.apk_path), "-o", str(out_dir)], timeout=120)
        return out_dir if rc == 0 and out_dir.exists() else None

    def _parse_manifest_xml(self, manifest_path: Path) -> None:
        try:
            text = manifest_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        # 보안 속성
        if 'android:debuggable="true"' in text:
            self.result.debuggable = True
            self.result.vulnerabilities.append({
                "title": "Debuggable Build",
                "severity": "HIGH",
                "detail": "android:debuggable=true — allows ADB/Frida attachment without root"
            })
        if 'android:allowBackup="true"' in text or 'android:allowBackup' not in text:
            self.result.backup_allowed = True
            self.result.vulnerabilities.append({
                "title": "Backup Allowed",
                "severity": "MEDIUM",
                "detail": "android:allowBackup enables ADB backup of app data"
            })
        if 'android:usesCleartextTraffic="true"' in text:
            self.result.clear_text_traffic = True
            self.result.vulnerabilities.append({
                "title": "Cleartext Traffic Allowed",
                "severity": "HIGH",
                "detail": "android:usesCleartextTraffic=true — HTTP traffic is unencrypted"
            })

        # exported 컴포넌트
        def extract_exported(tag: str) -> list[str]:
            comps = []
            for m in re.finditer(
                rf'<{tag}[^>]+android:name="([^"]+)"[^>]*(?:android:exported="true"[^>]*)?>',
                text, re.DOTALL
            ):
                comps.append(m.group(1))
            return comps

        self.result.exported_activities = extract_exported("activity")
        self.result.exported_services   = extract_exported("service")
        self.result.exported_receivers  = extract_exported("receiver")
        self.result.exported_providers  = extract_exported("provider")

        # 딥링크
        schemes = re.findall(r'android:scheme="([^"]+)"', text)
        hosts   = re.findall(r'android:host="([^"]+)"', text)
        paths   = re.findall(r'android:path(?:Prefix)?="([^"]+)"', text)
        for s in schemes:
            if s not in ("http", "https"):
                self.result.deep_links.append(f"{s}://{hosts[0] if hosts else ''}{"{}".format(paths[0]) if paths else ''}")

    # ── 소스코드/리소스 시크릿 스캔 ──────────────────────────
    def _scan_secrets(self, root_dir: Path) -> None:
        text_exts = {".java", ".kt", ".smali", ".xml", ".json", ".properties",
                     ".gradle", ".yaml", ".yml", ".txt", ".html", ".js", ".ts"}
        for fp in root_dir.rglob("*"):
            if not fp.is_file():
                continue
            if fp.suffix.lower() not in text_exts:
                continue
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for stype, pat in SECRET_PATTERNS:
                for m in pat.finditer(content):
                    val = m.group(0)
                    line_no = content[:m.start()].count("\n") + 1
                    self.result.hardcoded_secrets.append({
                        "type": stype,
                        "value": val[:80],
                        "file": str(fp.relative_to(root_dir)),
                        "line": line_no,
                    })
            # 네트워크 엔드포인트
            for pat in ENDPOINT_PATTERNS:
                for m in pat.finditer(content):
                    url = m.group(0).strip("'\"")
                    if url not in self.result.network_endpoints:
                        self.result.network_endpoints.append(url)

    # ── SDK / 보호 메커니즘 탐지 ─────────────────────────────
    def _detect_sdks_and_protections(self, root_dir: Path) -> None:
        all_text = ""
        for fp in root_dir.rglob("*.smali"):
            try:
                all_text += fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass
        for pkg, name in SDK_FINGERPRINTS.items():
            if pkg.replace(".", "/") in all_text and name not in self.result.third_party_sdks:
                self.result.third_party_sdks.append(name)
        for pat in SSL_PINNING_PATTERNS:
            if pat in all_text:
                self.result.ssl_pinning_detected = True
                break
        for pat in ROOT_DETECTION_PATTERNS:
            if pat in all_text:
                self.result.root_detection_detected = True
                break

    # ── native 라이브러리 탐지 ──────────────────────────────
    def _detect_native_libs(self) -> None:
        contents = self._list_apk_contents()
        self.result.native_libraries = [
            f for f in contents if f.startswith("lib/") and f.endswith(".so")
        ]

    # ── Frida / ADB 명령 생성 ───────────────────────────────
    def _generate_commands(self) -> None:
        pkg = self.result.app_id or "<package.name>"
        self.result.adb_commands = [
            f"adb shell pm list packages | grep {pkg.split('.')[0]}",
            f"adb shell pm path {pkg}",
            f"adb pull $(adb shell pm path {pkg} | cut -d: -f2) ./target.apk",
            f"adb shell am start -n {pkg}/.MainActivity",
            f"adb shell run-as {pkg} ls /data/data/{pkg}/",
            f"adb backup -apk -nosystem {pkg} -f backup.ab",
            "adb shell content query --uri content://com.android.contacts/contacts",
            "adb logcat | grep -E 'password|token|secret|api_key'",
        ]
        self.result.frida_commands = [
            f"frida-ps -Ua | grep {pkg.split('.')[-1]}",
            f"frida -U -l ssl-pinning-bypass.js -f {pkg}",
            f"frida -U -l root-detection-bypass.js -f {pkg}",
            f"frida -U -l method-trace.js {pkg}",
            f"frida-trace -U -i 'Java_*' {pkg}",
            f"frida -U -e \"Java.perform(function(){{ var Activity = Java.use('{pkg}.MainActivity'); Activity.onCreate.implementation = function(b){{ this.onCreate(b); console.log('onCreate hooked!'); }}; }})\" {pkg}",
        ]
        self.result.objection_commands = [
            f"objection -g {pkg} explore",
            f"objection -g {pkg} explore --startup-command 'android sslpinning disable'",
            "android hooking list classes",
            "android hooking list class_methods <ClassName>",
            "android heap search instances <ClassName>",
            "android intent launch_activity <ActivityName>",
            "file download /data/data/{pkg}/shared_prefs/*.xml",
            "sqlite connect /data/data/{pkg}/databases/*.db",
        ]

    # ── 공격면 정리 ──────────────────────────────────────────
    def _build_attack_surface(self) -> None:
        surface = []
        if self.result.debuggable:
            surface.append("Debuggable build — attach Frida without root")
        if self.result.backup_allowed:
            surface.append("ADB Backup enabled — extract app data via adb backup")
        if self.result.clear_text_traffic:
            surface.append("HTTP traffic allowed — MITM with mitmproxy/Burp")
        if not self.result.ssl_pinning_detected:
            surface.append("No SSL pinning detected — intercept HTTPS directly with Burp/mitmproxy")
        if not self.result.root_detection_detected:
            surface.append("No root detection — run Frida freely on rooted device")
        for act in self.result.exported_activities:
            surface.append(f"Exported Activity → adb shell am start -n {self.result.app_id}/{act}")
        for svc in self.result.exported_services:
            surface.append(f"Exported Service → adb shell am startservice -n {self.result.app_id}/{svc}")
        for dl in self.result.deep_links:
            surface.append(f"Deep Link → adb shell am start -a android.intent.action.VIEW -d '{dl}'")
        for sec in self.result.hardcoded_secrets:
            surface.append(f"Hardcoded {sec['type']} @ {sec['file']}:{sec['line']}")
        self.result.attack_surface = surface

    # ── 메인 분석 실행 ───────────────────────────────────────
    def analyze(self) -> MobileReconResult:
        if not self.apk_path.exists():
            self.result.errors.append(f"File not found: {self.apk_path}")
            return self.result

        self._parse_with_aapt()
        self._detect_native_libs()

        decompiled = self._decompile_with_apktool()
        if decompiled:
            self._decompiled_dir = decompiled
            manifest = decompiled / "AndroidManifest.xml"
            if manifest.exists():
                self._parse_manifest_xml(manifest)
            self._scan_secrets(decompiled)
            self._detect_sdks_and_protections(decompiled)
        else:
            self.result.errors.append(
                "apktool not found — install: brew install apktool / apt install apktool\n"
                "Limited analysis performed (aapt only)"
            )
            # APK 내부 직접 스캔 (zip)
            try:
                with zipfile.ZipFile(self.apk_path) as z:
                    for name in z.namelist():
                        if name.endswith((".xml", ".json", ".properties")):
                            try:
                                content = z.read(name).decode("utf-8", errors="ignore")
                                for stype, pat in SECRET_PATTERNS:
                                    for m in pat.finditer(content):
                                        self.result.hardcoded_secrets.append({
                                            "type": stype,
                                            "value": m.group(0)[:80],
                                            "file": name,
                                            "line": "?",
                                        })
                            except Exception:
                                pass
            except Exception:
                pass

        # 위험 권한 취약점 등록
        dangerous = [p for p in self.result.permissions if p in DANGEROUS_PERMISSIONS]
        if dangerous:
            self.result.vulnerabilities.append({
                "title": f"Dangerous Permissions ({len(dangerous)})",
                "severity": "MEDIUM",
                "detail": ", ".join(dangerous[:5]),
            })

        self._generate_commands()
        self._build_attack_surface()
        return self.result


# ─────────────────────────────────────────────────────────────
# iOS IPA 분석
# ─────────────────────────────────────────────────────────────

class IOSAnalyzer:
    """IPA 정적 분석 — class-dump / otool / strings / plutil 활용"""

    def __init__(self, ipa_path: str):
        self.ipa_path = Path(ipa_path)
        self.result = MobileReconResult(target=ipa_path, platform="ios")
        self._payload_dir: Optional[Path] = None

    def _extract_ipa(self) -> Optional[Path]:
        out_dir = Path("/tmp") / f"bingo_ipa_{self.ipa_path.stem}"
        if out_dir.exists():
            return out_dir
        try:
            with zipfile.ZipFile(self.ipa_path) as z:
                z.extractall(out_dir)
            return out_dir
        except Exception as e:
            self.result.errors.append(f"IPA extraction failed: {e}")
            return None

    def _find_app_bundle(self, root: Path) -> Optional[Path]:
        for p in (root / "Payload").iterdir():
            if p.suffix == ".app" and p.is_dir():
                return p
        return None

    def _parse_info_plist(self, plist_path: Path) -> None:
        # plutil으로 JSON 변환 시도
        if _has_tool("plutil"):
            out, _, rc = _run(["plutil", "-convert", "json", "-o", "-", str(plist_path)], timeout=10)
            if rc == 0 and out:
                try:
                    d = json.loads(out)
                    self.result.app_id      = d.get("CFBundleIdentifier", "")
                    self.result.app_name    = d.get("CFBundleDisplayName") or d.get("CFBundleName", "")
                    self.result.app_version = d.get("CFBundleShortVersionString", "")
                    self.result.min_sdk     = d.get("MinimumOSVersion", "")
                    # URL Schemes (딥링크)
                    for item in d.get("CFBundleURLTypes", []):
                        for scheme in item.get("CFBundleURLSchemes", []):
                            self.result.deep_links.append(f"{scheme}://")
                    # Privacy 권한 (NSxxUsageDescription)
                    self.result.permissions = [k for k in d if k.endswith("UsageDescription")]
                    # 보안 설정
                    ats = d.get("NSAppTransportSecurity", {})
                    if ats.get("NSAllowsArbitraryLoads", False):
                        self.result.clear_text_traffic = True
                        self.result.vulnerabilities.append({
                            "title": "NSAllowsArbitraryLoads = YES",
                            "severity": "HIGH",
                            "detail": "ATS disabled — allows HTTP traffic; easy MITM"
                        })
                    return
                except json.JSONDecodeError:
                    pass
        # fallback: strings 파싱
        try:
            text = plist_path.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r"<key>CFBundleIdentifier</key>\s*<string>([^<]+)</string>", text)
            if m:
                self.result.app_id = m.group(1)
            m = re.search(r"<key>CFBundleShortVersionString</key>\s*<string>([^<]+)</string>", text)
            if m:
                self.result.app_version = m.group(1)
        except Exception:
            pass

    def _analyze_binary(self, binary_path: Path) -> None:
        # otool — 링크된 라이브러리
        if _has_tool("otool"):
            out, _, _ = _run(["otool", "-L", str(binary_path)], timeout=15)
            for line in out.splitlines():
                if line.strip().startswith("/"):
                    lib = line.strip().split()[0]
                    self.result.native_libraries.append(lib)

        # strings — 시크릿 + 엔드포인트 스캔
        strings_tool = "strings" if _has_tool("strings") else None
        if strings_tool:
            out, _, _ = _run([strings_tool, str(binary_path)], timeout=30)
            self._scan_text_for_secrets(out, str(binary_path.name), "binary")
            for pat in ENDPOINT_PATTERNS:
                for m in pat.finditer(out):
                    url = m.group(0).strip("'\"")
                    if url not in self.result.network_endpoints:
                        self.result.network_endpoints.append(url)

        # 보안 플래그 확인 (otool -Iv)
        if _has_tool("otool"):
            out, _, _ = _run(["otool", "-Iv", str(binary_path)], timeout=15)
            for pat in SSL_PINNING_PATTERNS:
                if pat in out:
                    self.result.ssl_pinning_detected = True
                    break
            for pat in ROOT_DETECTION_PATTERNS:
                if pat in out:
                    self.result.root_detection_detected = True
                    break

        # PIE / Stack Canary / ARC 확인
        if _has_tool("otool"):
            out, _, _ = _run(["otool", "-hv", str(binary_path)], timeout=10)
            if "PIE" not in out:
                self.result.vulnerabilities.append({
                    "title": "No PIE (Position Independent Executable)",
                    "severity": "MEDIUM",
                    "detail": "Binary compiled without PIE — easier exploitation"
                })
            out2, _, _ = _run(["otool", "-Iv", str(binary_path)], timeout=15)
            if "stack_chk_guard" not in out2:
                self.result.vulnerabilities.append({
                    "title": "No Stack Canary",
                    "severity": "MEDIUM",
                    "detail": "Binary compiled without stack canary protection"
                })

    def _scan_text_for_secrets(self, content: str, filename: str, context: str) -> None:
        for stype, pat in SECRET_PATTERNS:
            for m in pat.finditer(content):
                val = m.group(0)
                self.result.hardcoded_secrets.append({
                    "type": stype,
                    "value": val[:80],
                    "file": f"{filename} ({context})",
                    "line": "?",
                })

    def _scan_bundle_files(self, app_bundle: Path) -> None:
        text_exts = {".json", ".plist", ".js", ".html", ".txt", ".xml", ".strings", ".stringsdict"}
        for fp in app_bundle.rglob("*"):
            if not fp.is_file() or fp.suffix.lower() not in text_exts:
                continue
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for stype, pat in SECRET_PATTERNS:
                for m in pat.finditer(content):
                    self.result.hardcoded_secrets.append({
                        "type": stype,
                        "value": m.group(0)[:80],
                        "file": str(fp.relative_to(app_bundle)),
                        "line": content[:m.start()].count("\n") + 1,
                    })
            for pat in ENDPOINT_PATTERNS:
                for m in pat.finditer(content):
                    url = m.group(0).strip("'\"")
                    if url not in self.result.network_endpoints:
                        self.result.network_endpoints.append(url)

    def _detect_sdks(self, app_bundle: Path) -> None:
        # 프레임워크 디렉토리에서 SDK 탐지
        fw_dir = app_bundle / "Frameworks"
        if fw_dir.exists():
            for fw in fw_dir.iterdir():
                name = fw.stem
                for pkg, sdk_name in SDK_FINGERPRINTS.items():
                    if pkg.split(".")[-1].lower() in name.lower():
                        if sdk_name not in self.result.third_party_sdks:
                            self.result.third_party_sdks.append(sdk_name)

    def _generate_commands(self) -> None:
        bid = self.result.app_id or "<bundle.id>"
        binary = self.result.app_name or "<AppName>"
        self.result.frida_commands = [
            f"frida-ps -Ua | grep {binary}",
            f"frida -U -l ssl-pinning-bypass.js -f {bid}",
            f"frida -U -l objection.js -f {bid} --no-pause",
            f"frida -U -e \"ObjC.choose(ObjC.classes.NSURLSession, {{ onMatch: function(i){{ console.log(i); }} }})\" {bid}",
            f"frida-trace -U -m '-[NSURLSession dataTaskWithRequest:*]' {bid}",
            f"frida -U --codeshare luander/frida-ios-dump -f {bid}",
        ]
        self.result.objection_commands = [
            f"objection -g {bid} explore",
            "ios sslpinning disable",
            "ios jailbreak disable",
            "ios keychain dump",
            "ios nsuserdefaults get",
            "ios cookies get",
            "ios pasteboard monitor",
            "ios bundles list_bundles",
            "ios hooking list classes",
            f"ios hooking watch class {binary}",
            "memory dump all mem.dump",
            "file download /var/mobile/Containers/Data/Application/ .",
        ]
        self.result.adb_commands = [
            f"# iOS — use ideviceinstaller / libimobiledevice",
            f"ideviceinstaller -l | grep {binary}",
            f"ideviceinfo -k CFBundleIdentifier",
            f"idevicesyslog | grep {binary}",
            f"ifuse /tmp/ios_mount && ls /tmp/ios_mount/",
            "scp -P 2222 root@localhost:/var/mobile/Containers/Data/Application/ .",
        ]

    def _build_attack_surface(self) -> None:
        surface = []
        if self.result.clear_text_traffic:
            surface.append("ATS disabled — HTTP traffic allows MITM intercept")
        if not self.result.ssl_pinning_detected:
            surface.append("No SSL pinning — intercept HTTPS with Burp + objection 'ios sslpinning disable'")
        if not self.result.root_detection_detected:
            surface.append("No jailbreak detection — use objection/Frida freely on jailbroken device")
        for dl in self.result.deep_links:
            surface.append(f"Deep Link → open '{dl}' from Safari or objection")
        for sec in self.result.hardcoded_secrets:
            surface.append(f"Hardcoded {sec['type']} @ {sec['file']}:{sec['line']}")
        if self.result.vulnerabilities:
            for v in self.result.vulnerabilities:
                surface.append(f"[{v['severity']}] {v['title']}: {v['detail']}")
        self.result.attack_surface = surface

    def analyze(self) -> MobileReconResult:
        if not self.ipa_path.exists():
            self.result.errors.append(f"File not found: {self.ipa_path}")
            return self.result

        root = self._extract_ipa()
        if not root:
            return self.result

        app_bundle = self._find_app_bundle(root)
        if not app_bundle:
            self.result.errors.append("Could not find .app bundle in Payload/")
            return self.result

        plist = app_bundle / "Info.plist"
        if plist.exists():
            self._parse_info_plist(plist)

        # 메인 바이너리 분석
        binary = app_bundle / (self.result.app_name or app_bundle.stem)
        if not binary.exists():
            binary = app_bundle / app_bundle.stem
        if binary.exists():
            self._analyze_binary(binary)

        self._scan_bundle_files(app_bundle)
        self._detect_sdks(app_bundle)
        self._generate_commands()
        self._build_attack_surface()
        return self.result


# ─────────────────────────────────────────────────────────────
# 패키지명 / URL 기반 원격 정보수집
# ─────────────────────────────────────────────────────────────

def recon_by_package(package_name: str) -> dict:
    """
    APK/IPA 없이 패키지명만으로 할 수 있는 정찰.
    Google Play / App Store 공개 정보 + 인증서 / 도메인 열거.
    """
    info: dict = {
        "package": package_name,
        "play_store_url": f"https://play.google.com/store/apps/details?id={package_name}",
        "app_store_search": f"https://itunes.apple.com/search?term={package_name}&entity=software",
        "apk_download_sources": [
            f"https://apkpure.com/search?q={package_name}",
            f"https://apkmirror.com/?post_type=app_release&searchtype=apk&s={package_name.split('.')[-1]}",
            f"https://apkcombo.com/search/{package_name}",
        ],
        "osint_commands": [
            f"python3 -m gplaycli -d {package_name} -f . -v",
            f"apkeep -a {package_name} .",
            f"curl -s 'https://itunes.apple.com/search?term={package_name}&entity=software' | python3 -m json.tool",
        ],
        "domain_recon": [
            f"subfinder -d {'.'.join(reversed(package_name.split('.')[:2]))}",
            f"amass enum -d {'.'.join(reversed(package_name.split('.')[:2]))}",
            f"httpx -l domains.txt -tech-detect -status-code -title",
        ],
        "certificate_transparency": [
            f"curl -s 'https://crt.sh/?q=%25.{'.'.join(reversed(package_name.split('.')[:2]))}&output=json' | python3 -m json.tool",
        ],
    }
    return info


def recon_by_store_url(url: str) -> dict:
    """
    앱스토어 URL에서 패키지/번들 정보 추출 및 정찰 명령 생성.
    """
    result: dict = {"url": url}

    # Android Play Store
    m = re.search(r"id=([a-z][a-z0-9._]+)", url)
    if m:
        pkg = m.group(1)
        result["platform"] = "android"
        result["package"] = pkg
        result.update(recon_by_package(pkg))
        return result

    # iOS App Store
    m = re.search(r"/app/[^/]+/id(\d+)", url)
    if m:
        aid = m.group(1)
        result["platform"] = "ios"
        result["app_store_id"] = aid
        result["osint_commands"] = [
            f"curl -s 'https://itunes.apple.com/lookup?id={aid}' | python3 -m json.tool",
            f"# Download IPA: use ipatool or AppStore API",
            f"# ipatool download -b <bundle_id>",
        ]
        return result

    result["error"] = "Could not parse store URL"
    return result


# ─────────────────────────────────────────────────────────────
# 메인 Phase 0 진입점
# ─────────────────────────────────────────────────────────────

def mobile_phase0(target: str) -> MobileReconResult | dict:
    """
    Phase 0 자동 실행.
    target:
      - /path/to/app.apk  → Android 정적 분석
      - /path/to/app.ipa  → iOS 정적 분석
      - com.example.app   → 패키지명 기반 OSINT
      - https://play.google.com/... → Play Store URL
      - https://apps.apple.com/...  → App Store URL
    """
    t = target.strip()

    if t.endswith(".apk"):
        return AndroidAnalyzer(t).analyze()
    elif t.endswith(".ipa"):
        return IOSAnalyzer(t).analyze()
    elif t.startswith("https://play.google.com") or t.startswith("https://apps.apple.com"):
        return recon_by_store_url(t)
    elif re.match(r"^[a-z][a-z0-9._]+\.[a-z][a-z0-9._]+$", t):
        return recon_by_package(t)
    else:
        return {"error": f"Unknown target format: {t}", "hint": "Use .apk/.ipa path, package name, or store URL"}


def quick_setup_guide(platform: str = "both") -> str:
    """Phase 0 환경 설정 가이드 출력"""
    android_tools = """
=== Android Phase 0 Setup ===
# 필수 도구
brew install apktool aapt android-platform-tools  # macOS
apt install apktool aapt adb                       # Ubuntu

# Frida
pip install frida-tools objection

# APK 다운로드
pip install gplaycli
# 또는: https://apkpure.com

# jadx (GUI + CLI)
brew install jadx
# 또는: https://github.com/skylot/jadx/releases

# MobSF (올인원 분석)
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
# http://localhost:8000

# SSL 피닝 우회 스크립트
wget https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/
"""
    ios_tools = """
=== iOS Phase 0 Setup ===
# 필수 도구 (macOS)
brew install libimobiledevice ideviceinstaller ifuse

# Frida (탈옥 기기에 frida-server 설치 필요)
pip install frida-tools objection

# class-dump
brew install class-dump

# Hopper / IDA Pro (바이너리 분석)
# https://www.hopperapp.com

# SSL 피닝 우회
objection -g <bundle.id> explore
# → ios sslpinning disable

# ipatool (IPA 다운로드)
brew install majd/repo/ipatool
ipatool auth login --email <apple-id> --password <pw>
ipatool download -b <bundle.id>
"""
    if platform == "android":
        return android_tools
    elif platform == "ios":
        return ios_tools
    return android_tools + "\n" + ios_tools
