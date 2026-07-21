from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from urllib.parse import urlparse
from uuid import uuid4


class ActionClass(str, Enum):
    LOCAL_READ = "local_read"
    PASSIVE_DISCOVERY = "passive_discovery"
    BOUNDED_NETWORK_READ = "bounded_network_read"
    AUTHENTICATED_READ = "authenticated_read"
    REVERSIBLE_STATE_CHANGE = "reversible_state_change"
    HIGH_IMPACT_STATE_CHANGE = "high_impact_state_change"
    PROHIBITED = "prohibited"


class ActionDecisionKind(str, Enum):
    ALLOW = "allow"
    REQUIRE_CONFIRMATION = "require_confirmation"
    DENY = "deny"


@dataclass(frozen=True)
class EngagementAuthorization:
    asserted: bool = False
    asserted_by: str = ""
    asserted_at: float = 0.0
    expires_at: float | None = None
    reference: str = ""

    def is_current(self, now: float) -> bool:
        return self.asserted and (self.expires_at is None or now < self.expires_at)


@dataclass(frozen=True)
class ScopeDefinition:
    target: str
    allowed_hosts: tuple[str, ...] = ()
    allowed_schemes: tuple[str, ...] = ("http", "https")
    allowed_ports: tuple[int, ...] = (80, 443)
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "OPTIONS")
    excluded_paths: tuple[str, ...] = ()
    allow_credentials: bool = False
    max_actions: int = 200
    max_concurrency: int = 4

    def normalized_hosts(self) -> tuple[str, ...]:
        primary = (urlparse(self.target).hostname or "").lower().rstrip(".")
        values = [primary, *(host.lower().rstrip(".") for host in self.allowed_hosts)]
        return tuple(dict.fromkeys(host for host in values if host))


@dataclass
class Engagement:
    scope: ScopeDefinition
    authorization: EngagementAuthorization = field(default_factory=EngagementAuthorization)
    goal: str = ""
    engagement_id: str = field(default_factory=lambda: uuid4().hex[:12])
    actions_used: int = 0


@dataclass(frozen=True)
class ActionRequest:
    capability: str
    url: str = ""
    method: str = "GET"
    arguments: dict[str, object] = field(default_factory=dict)
    action_class: ActionClass = ActionClass.BOUNDED_NETWORK_READ
    evidence_goal: str = ""
    summary: str = ""

    def identity_key(self) -> str:
        payload = repr((self.capability, self.method.upper(), self.url, sorted(self.arguments.items())))
        return sha256(payload.encode("utf-8", "replace")).hexdigest()


@dataclass(frozen=True)
class ApprovalRequest:
    approval_id: str
    action_identity: str
    summary: str
    action_class: ActionClass


@dataclass(frozen=True)
class ExecutionEnvelope:
    execution_id: str
    engagement_id: str
    action: ActionRequest
    normalized_url: str
    action_identity: str
    approval_id: str = ""


@dataclass(frozen=True)
class ActionDecision:
    kind: ActionDecisionKind
    reason: str
    envelope: ExecutionEnvelope | None = None
    approval: ApprovalRequest | None = None


class ActionAuthority:
    """Closed-default authority gate for every model-proposed action."""

    _CONFIRMATION_CLASSES = {
        ActionClass.REVERSIBLE_STATE_CHANGE,
        ActionClass.HIGH_IMPACT_STATE_CHANGE,
    }

    def evaluate(
        self,
        request: ActionRequest,
        engagement: Engagement,
        *,
        now: float,
        approved_identity: str = "",
    ) -> ActionDecision:
        if not engagement.authorization.is_current(now):
            return ActionDecision(ActionDecisionKind.DENY, "authorization_missing_or_expired")
        if request.action_class is ActionClass.PROHIBITED:
            return ActionDecision(ActionDecisionKind.DENY, "prohibited_action_class")
        if engagement.actions_used >= engagement.scope.max_actions:
            return ActionDecision(ActionDecisionKind.DENY, "engagement_action_budget_exhausted")

        normalized_url, reason = self._validate_scope(request, engagement.scope)
        if reason:
            return ActionDecision(ActionDecisionKind.DENY, reason)

        identity = request.identity_key()
        if request.action_class in self._CONFIRMATION_CLASSES and approved_identity != identity:
            return ActionDecision(
                ActionDecisionKind.REQUIRE_CONFIRMATION,
                "explicit_confirmation_required",
                approval=ApprovalRequest(
                    approval_id=uuid4().hex,
                    action_identity=identity,
                    summary=request.summary,
                    action_class=request.action_class,
                ),
            )

        return ActionDecision(
            ActionDecisionKind.ALLOW,
            "authorized",
            envelope=ExecutionEnvelope(
                execution_id=uuid4().hex,
                engagement_id=engagement.engagement_id,
                action=request,
                normalized_url=normalized_url,
                action_identity=identity,
                approval_id=identity if approved_identity == identity else "",
            ),
        )

    @staticmethod
    def _validate_scope(request: ActionRequest, scope: ScopeDefinition) -> tuple[str, str]:
        if not request.url:
            if request.action_class in {ActionClass.LOCAL_READ, ActionClass.PASSIVE_DISCOVERY}:
                return "", ""
            return "", "network_action_requires_url"

        parsed = urlparse(request.url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme.lower() not in scope.allowed_schemes:
            return "", "scheme_out_of_scope"
        if host not in scope.normalized_hosts():
            return "", "host_out_of_scope"
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        if port not in scope.allowed_ports:
            return "", "port_out_of_scope"
        if request.method.upper() not in scope.allowed_methods:
            return "", "method_out_of_scope"
        if any(parsed.path.startswith(prefix) for prefix in scope.excluded_paths):
            return "", "path_excluded_from_scope"
        if request.action_class is ActionClass.AUTHENTICATED_READ and not scope.allow_credentials:
            return "", "credential_use_not_authorized"
        return parsed.geturl(), ""
