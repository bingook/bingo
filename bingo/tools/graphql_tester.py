"""bingo/tools/graphql_tester.py — GraphQL 심층 보안 테스터 (v2.6.0)"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Callable

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name kind
      fields(includeDeprecated: true) {
        name
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""

BATCH_QUERY_TEMPLATE = "[{payloads}]"
ALIAS_BRUTE_TEMPLATE = "{{ {aliases} }}"


@dataclass
class GraphQLFinding:
    finding_type: str   # "introspection"|"batch_dos"|"alias_bypass"|"idor"|"injection"
    endpoint: str
    payload: str
    evidence: str
    severity: str
    confirmed: bool
    notes: str = ""


@dataclass
class GraphQLReport:
    endpoint: str
    schema: dict = field(default_factory=dict)
    findings: list[GraphQLFinding] = field(default_factory=list)
    query_types: list[str] = field(default_factory=list)
    mutation_types: list[str] = field(default_factory=list)
    sensitive_fields: list[str] = field(default_factory=list)

    @property
    def critical(self) -> list[GraphQLFinding]:
        return [f for f in self.findings if f.severity == "CRITICAL"]


SENSITIVE_FIELD_PATTERNS = [
    "password", "passwd", "secret", "token", "key", "api_key", "auth",
    "credit_card", "ssn", "dob", "salary", "balance", "admin", "role",
    "permission", "private", "internal",
]


class GraphQLTester:
    """GraphQL 인트로스펙션 + 배칭 DoS + 별칭 우회 + 인젝션"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        endpoint: str,
        headers: dict | None = None,
    ) -> None:
        self.req = request_fn
        self.endpoint = endpoint
        self.headers = {
            "Content-Type": "application/json",
            **(headers or {}),
        }

    def _gql(self, query: str, variables: dict | None = None) -> tuple[int, dict]:
        payload = json.dumps({"query": query, "variables": variables or {}})
        try:
            status, body = self.req(self.endpoint, "POST", self.headers, payload)
            return status, json.loads(body)
        except Exception:
            return 0, {}

    # ── 인트로스펙션 ─────────────────────────────────────────────────────────
    def test_introspection(self) -> GraphQLFinding | None:
        status, data = self._gql(INTROSPECTION_QUERY)
        if status == 200 and "__schema" in str(data):
            schema = data.get("data", {}).get("__schema", {})
            return GraphQLFinding(
                finding_type="introspection",
                endpoint=self.endpoint,
                payload=INTROSPECTION_QUERY[:100] + "...",
                evidence=f"Schema exposed: {len(schema.get('types', []))} types",
                severity="HIGH",
                confirmed=True,
                notes="Introspection enabled — full schema accessible to attackers",
            )
        return None

    def dump_schema(self) -> dict:
        _, data = self._gql(INTROSPECTION_QUERY)
        return data.get("data", {}).get("__schema", {})

    def extract_query_fields(self, schema: dict) -> tuple[list[str], list[str], list[str]]:
        """쿼리/뮤테이션/민감 필드 추출"""
        queries, mutations, sensitive = [], [], []
        for t in schema.get("types", []):
            name = t.get("name", "")
            if name == schema.get("queryType", {}).get("name"):
                queries = [f.get("name", "") for f in (t.get("fields") or [])]
            elif name == schema.get("mutationType", {}).get("name"):
                mutations = [f.get("name", "") for f in (t.get("fields") or [])]
            for field in (t.get("fields") or []):
                fname = field.get("name", "").lower()
                if any(p in fname for p in SENSITIVE_FIELD_PATTERNS):
                    sensitive.append(f"{name}.{field.get('name')}")
        return queries, mutations, sensitive

    # ── 배칭 DoS ─────────────────────────────────────────────────────────────
    def test_batch_dos(self, query: str = "{ __typename }", count: int = 100) -> GraphQLFinding | None:
        batch = json.dumps([{"query": query}] * count)
        try:
            import time
            t0 = time.time()
            status, body = self.req(self.endpoint, "POST", self.headers, batch)
            elapsed = time.time() - t0
            if elapsed > 3 or (isinstance(body, str) and body.count("__typename") > 50):
                return GraphQLFinding(
                    finding_type="batch_dos",
                    endpoint=self.endpoint,
                    payload=f"Array of {count} queries",
                    evidence=f"Response time: {elapsed:.2f}s",
                    severity="MEDIUM",
                    confirmed=True,
                    notes=f"Batch query ({count}x) took {elapsed:.2f}s — potential DoS",
                )
        except Exception:
            pass
        return None

    # ── 별칭 기반 레이트리밋 우회 ─────────────────────────────────────────────
    def test_alias_bypass(self, query_name: str, count: int = 50) -> GraphQLFinding | None:
        aliases = "\n".join(f"a{i}: {query_name}" for i in range(count))
        q = "{ " + aliases + " }"
        status, data = self._gql(q)
        if status == 200 and "errors" not in str(data):
            return GraphQLFinding(
                finding_type="alias_bypass",
                endpoint=self.endpoint,
                payload=q[:200],
                evidence=f"{count} aliases executed in single query",
                severity="MEDIUM",
                confirmed=True,
                notes="Rate limit bypass via GraphQL aliases",
            )
        return None

    # ── IDOR via GraphQL ──────────────────────────────────────────────────────
    def test_idor(self, query_template: str, field_name: str) -> list[GraphQLFinding]:
        """GraphQL 필드에서 IDOR 탐지"""
        findings = []
        test_ids = [1, 2, 3, 100, 9999, "admin", "root"]
        for id_val in test_ids:
            q = query_template.replace("{{ID}}", str(id_val))
            status, data = self._gql(q)
            if status == 200 and "errors" not in str(data).lower():
                result = data.get("data", {})
                if result and any(result.values()):
                    findings.append(GraphQLFinding(
                        finding_type="idor",
                        endpoint=self.endpoint,
                        payload=q,
                        evidence=str(result)[:200],
                        severity="HIGH",
                        confirmed=True,
                        notes=f"ID={id_val} returned data without authorization",
                    ))
        return findings

    # ── 종합 스캔 ─────────────────────────────────────────────────────────────
    def full_scan(self) -> GraphQLReport:
        report = GraphQLReport(endpoint=self.endpoint)

        # 인트로스펙션
        intro = self.test_introspection()
        if intro:
            report.findings.append(intro)
            schema = self.dump_schema()
            report.schema = schema
            report.query_types, report.mutation_types, report.sensitive_fields = \
                self.extract_query_fields(schema)

            # 배칭 DoS
            if report.query_types:
                dos = self.test_batch_dos(f"{{ {report.query_types[0]} }}")
                if dos:
                    report.findings.append(dos)

                # 별칭 우회
                alias = self.test_alias_bypass(report.query_types[0])
                if alias:
                    report.findings.append(alias)

            # 민감 필드 노출
            if report.sensitive_fields:
                report.findings.append(GraphQLFinding(
                    finding_type="sensitive_fields",
                    endpoint=self.endpoint,
                    payload="Schema introspection",
                    evidence=", ".join(report.sensitive_fields[:10]),
                    severity="HIGH",
                    confirmed=True,
                    notes=f"{len(report.sensitive_fields)} sensitive fields exposed in schema",
                ))

        return report
