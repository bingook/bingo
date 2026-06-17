"""
Path Dictionary — 스킬 라이브러리 지식을 스캔 단계에서 직접 활용
기술스택 기반 동적 경로 선택 + API 엔드포인트 탐색 + 약한 비밀번호 목록

문제: 기존에는 13개 하드코딩 경로만 사용 → 스킬 라이브러리 540개 지식이 AI 분석
      단계에서만 개입해서 실제 스캔에는 반영 안 됨.
해결: 이 모듈이 Phase 01 진입 전에 기술스택 기반 동적 경로를 공급.
"""
from __future__ import annotations

# ── 공통 관리자 패널 경로 ────────────────────────────────────────────────
ADMIN_PATHS_COMMON: list[str] = [
    # 기본 어드민
    "/admin/", "/admin", "/admin/login", "/admin/login/",
    "/admin/login.php", "/admin/login.html", "/admin/login.aspx",
    "/admin/index.php", "/admin/index.html", "/admin/index.aspx",
    "/admin/dashboard", "/admin/dashboard/", "/admin/home",
    "/admin/panel", "/admin/console",
    "/admin.php", "/admin.html", "/admin.aspx",
    # administrator
    "/administrator/", "/administrator/login", "/administrator/index.php",
    # manage
    "/manage/", "/manage/login", "/management/", "/management/login",
    "/manager/", "/manager/login",
    # panel / control
    "/panel/", "/panel/login", "/cpanel/", "/control/", "/controlpanel/",
    # backend
    "/backend/", "/backend/login", "/backend/admin",
    # dashboard
    "/dashboard/", "/dashboard/login", "/dashboard/admin",
    # portal
    "/portal/", "/portal/admin", "/portal/login",
    # member / user
    "/member/login.php", "/member/login", "/members/login",
    "/user/login", "/users/admin", "/user/admin",
    # login pages
    "/login", "/login/", "/login.php", "/login.html", "/login.aspx",
    "/signin", "/signin/", "/sign-in",
    "/auth/login", "/auth/signin",
    "/account/login", "/accounts/login",
    # WP
    "/wp-admin/", "/wp-login.php", "/wp-admin/admin-ajax.php",
    # Joomla
    "/joomla/administrator/", "/joomlaadmin/",
    # etc
    "/adm/", "/adm/login", "/adm.php",
    "/site/admin", "/site/login",
    "/web/admin", "/web/login",
    "/system/admin", "/system/login",
    "/secure/admin", "/secure/login",
    "/private/admin",
    "/cms/admin", "/cms/login",
    "/app/admin", "/app/login",
    "/api/admin", "/api/login",
    "/console", "/console/", "/webconsole/",
    "/phpmyadmin/", "/pma/", "/phpmyadmin",
    "/adminer.php", "/adminer/",
    "/config", "/config.php",
]

# ── 기술스택별 특화 경로 ────────────────────────────────────────────────
TECH_PATHS: dict[str, list[str]] = {
    "WordPress": [
        "/wp-admin/", "/wp-login.php", "/wp-admin/admin-ajax.php",
        "/wp-admin/edit.php", "/wp-admin/options-general.php",
        "/wp-content/debug.log", "/wp-config.php.bak",
        "/xmlrpc.php", "/?author=1", "/feed/", "/wp-json/wp/v2/users",
    ],
    "Gnuboard": [
        "/adm/", "/adm/login.php", "/adm/index.php",
        "/admin/", "/admin/index.php",
        "/bbs/login.php", "/bbs/register.php",
        "/bbs/ajax.latest.php", "/common/js/", "/data/",
        "/g5/adm/", "/g5/bbs/login.php",
    ],
    "PHP": [
        "/phpinfo.php", "/info.php", "/php.php", "/php_info.php",
        "/test.php", "/debug.php", "/dev.php",
        "/admin.php", "/manager.php", "/panel.php",
        "/config.php", "/configuration.php", "/database.php",
        "/install.php", "/setup.php", "/update.php", "/backup.php",
        "/api.php", "/api/index.php",
    ],
    "ASP.NET": [
        "/admin/", "/admin/login.aspx", "/admin/default.aspx",
        "/elmah.axd", "/elmah/", "/trace.axd", "/WebResource.axd",
        "/api/", "/api/values", "/api/account/login",
        "/_api/", "/swagger/", "/swagger/ui/index",
        "/swagger/v1/swagger.json",
    ],
    "Nginx": [
        "/nginx_status", "/server-status",
        "/.well-known/", "/.well-known/security.txt",
    ],
    "Apache": [
        "/server-status", "/server-info", "/.htaccess", "/.htpasswd",
    ],
    "Next.js": [
        "/_next/", "/__nextjs_original-stack-frames",
        "/api/auth/session", "/api/auth/csrf", "/api/auth/providers",
        "/api/user", "/api/me", "/api/profile",
        "/api/admin", "/api/v1/admin", "/api/v1/users",
        "/_next/static/chunks/", "/api/hello",
    ],
    "React": [
        "/static/js/", "/api/", "/api/v1/", "/api/v2/",
        "/graphql", "/graphiql", "/api/graphql",
    ],
    "Vue": [
        "/api/", "/api/v1/", "/api/v2/",
        "/_nuxt/", "/__nuxt/", "/api/coordinates",
        "/api/config", "/api/settings", "/api/location",
    ],
    "Spring": [
        "/actuator", "/actuator/", "/actuator/env", "/actuator/health",
        "/actuator/info", "/actuator/beans", "/actuator/heapdump",
        "/actuator/mappings", "/actuator/configprops",
        "/actuator/loggers", "/actuator/metrics",
        "/swagger-ui.html", "/v2/api-docs", "/v3/api-docs",
        "/api/", "/rest/", "/swagger-ui/index.html",
    ],
    "Laravel": [
        "/admin", "/admin/login", "/horizon/", "/telescope/",
        "/_ignition/health-check", "/api/user", "/api/v1/",
        "/storage/", "/storage/app/",
    ],
    "Django": [
        "/admin/", "/admin/login/", "/api/", "/api-auth/login/",
        "/api/v1/", "/api/v2/", "/django-admin/",
    ],
    "OpenResty": [
        "/nginx_status", "/api/", "/admin/",
        "/.well-known/", "/server-status",
    ],
}

# ── API 엔드포인트 탐색 경로 ───────────────────────────────────────────
API_PATHS: list[str] = [
    # REST API 기본
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/api/v1/users", "/api/v1/user", "/api/v1/me",
    "/api/v1/admin", "/api/v1/login", "/api/v1/auth",
    "/api/v1/config", "/api/v1/settings",
    "/api/v1/status", "/api/v1/health",
    "/api/v1/list", "/api/v1/data",
    # 미인증 접근 취약점 대상 (이용자 제보: /api/coordinates 미탐지)
    "/api/coordinates", "/api/location", "/api/gps", "/api/geo",
    "/api/users", "/api/accounts", "/api/members", "/api/profile",
    "/api/orders", "/api/payments", "/api/transactions",
    "/api/products", "/api/items", "/api/catalog",
    "/api/files", "/api/upload", "/api/download",
    "/api/search", "/api/query", "/api/filter",
    "/api/export", "/api/import", "/api/report", "/api/reports",
    "/api/logs", "/api/audit", "/api/history",
    "/api/debug", "/api/test", "/api/ping", "/api/health",
    "/api/internal", "/api/private", "/api/secret",
    "/api/admin/users", "/api/admin/config", "/api/admin/",
    "/api/token", "/api/refresh", "/api/verify",
    "/api/info", "/api/version", "/api/status",
    # GraphQL
    "/graphql", "/graphiql", "/graphql/console",
    "/graphql/playground", "/__graphql", "/api/graphql",
    # Swagger / OpenAPI
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api-docs/", "/swagger/", "/swagger-ui/",
    "/swagger/v1/swagger.json", "/v2/api-docs", "/v3/api-docs",
    # 기타
    "/rest/", "/rest/v1/", "/rest/api/",
    "/service/", "/services/", "/ws/", "/websocket/",
    "/.well-known/", "/.well-known/security.txt",
    "/.well-known/change-password",
]

# ── 공통 비밀번호 패턴 (아이디 무관) ─────────────────────────────────
# 이용자 제보: lahyl:lahy12025 패턴 → 아이디 첫4자+연도 패턴 반영
COMMON_PASSWORDS: list[str] = [
    "admin", "admin123", "admin1234", "admin12345",
    "Admin123", "Admin@123", "Admin1234",
    "password", "password123", "Password1",
    "12345", "123456", "1234567890", "123456789",
    "qwerty", "letmein", "welcome", "changeme",
    "111111", "000000", "654321",
    "iloveyou", "sunshine", "monkey",
    "admin2024", "admin2025", "admin2026",
    "test123", "test1234", "Test123",
    "korea123", "korea2025",
    "__USER__123",        # 아이디+123
    "__USER__1234",
    "__USER__12345",
    "__USER__2024",
    "__USER__2025",
    "__USER__2026",
    "__USER____USER__",   # 아이디+아이디
    "__USER__!@#",
    "__DOMAIN__123",      # 사이트명+123
    "__DOMAIN__2024",
    "__DOMAIN__2025",
    "__DOMAIN__2026",
    "__DOMAIN__@123",
    "__DOMAIN__!@#",
    # lahyl:lahy12025 계열 — 아이디 앞 4자+연도 패턴
    "__USERSHORT__2024",
    "__USERSHORT__2025",
    "__USERSHORT__2026",
    "__USERSHORT__123",
    "__USERSHORT__1234",
    "__USERSHORT__12345",
]

# ── 기본 아이디 목록 ──────────────────────────────────────────────────
COMMON_USERNAMES: list[str] = [
    "admin", "root", "administrator", "test", "guest",
    "user", "manager", "webmaster", "master", "operator",
    "info", "support", "system", "server", "web", "mail",
    "supervisor", "superuser", "su", "devops",
    "korea", "kr", "service", "cs",
]


def get_admin_paths(tech_stack: list[str]) -> list[str]:
    """기술스택 기반 동적 어드민 경로 생성 (중복 제거, 기술 특화 경로 우선)"""
    seen: set[str] = set()
    paths: list[str] = []

    # 기술스택 특화 경로 먼저 (높은 정확도)
    for tech in tech_stack:
        for p in TECH_PATHS.get(tech, []):
            if p not in seen:
                seen.add(p)
                paths.append(p)

    # 공통 경로 추가
    for p in ADMIN_PATHS_COMMON:
        if p not in seen:
            seen.add(p)
            paths.append(p)

    return paths


def get_api_paths(tech_stack: list[str] | None = None) -> list[str]:
    """API 엔드포인트 탐색 경로 (기술스택 특화 + 공통)"""
    seen: set[str] = set()
    paths: list[str] = []

    for tech in (tech_stack or []):
        for p in TECH_PATHS.get(tech, []):
            if any(kw in p.lower() for kw in ["/api", "swagger", "graphql", "actuator"]):
                if p not in seen:
                    seen.add(p)
                    paths.append(p)

    for p in API_PATHS:
        if p not in seen:
            seen.add(p)
            paths.append(p)

    return paths


def get_weak_credentials(
    domain: str = "",
    extra_usernames: list[str] | None = None,
) -> list[tuple[str, str]]:
    """동적 아이디+비밀번호 조합 생성

    전략:
    1. 표준 아이디 목록 (admin, root, test …)
    2. 사이트에서 수집한 아이디 (extra_usernames)
    3. 각 아이디 × 공통 비밀번호 패턴 크로스 조인
       - __USER__     → 실제 아이디로 치환
       - __USERSHORT__ → 아이디 앞 4글자 (lahyl → lahy)
       - __DOMAIN__   → 도메인명 (example.co.kr → example)

    이용자 제보 lahyl:lahy12025 패턴 커버:
      username = "lahyl"
      password = __USERSHORT__2025 → "lahy" + "2025" = "lahy2025"  ✓
    """
    parts = domain.replace("www.", "").split(".")
    domain_name = parts[0] if parts else ""

    # 아이디 풀 구성: 기본 + 수집
    usernames = list(COMMON_USERNAMES)
    if extra_usernames:
        for u in extra_usernames:
            u = u.strip().lower()
            if u and u not in usernames:
                usernames.append(u)
    # 도메인명 자체도 아이디로 시도
    if domain_name and domain_name not in usernames:
        usernames.append(domain_name)

    creds: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for user in usernames:
        user_short = user[:4]  # lahyl → lahy (4글자 슬라이싱)
        for pwd_tmpl in COMMON_PASSWORDS:
            pwd = (
                pwd_tmpl
                .replace("__USERSHORT__", user_short)
                .replace("__USER__", user)
                .replace("__DOMAIN__", domain_name)
            )
            # 도메인/유저 플레이스홀더가 비어 있으면 건너뜀
            if "__" in pwd:
                continue
            pair = (user, pwd)
            if pair not in seen:
                seen.add(pair)
                creds.append(pair)

    return creds
