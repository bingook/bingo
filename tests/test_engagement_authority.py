from bingo.core.authorization import create_auth_context
from bingo.core.engagement import (
    ActionAuthority,
    ActionClass,
    ActionDecisionKind,
    ActionRequest,
    Engagement,
    EngagementAuthorization,
    ScopeDefinition,
)


def _engagement(**scope_overrides):
    values = {
        "target": "https://example.test",
        "allowed_hosts": (),
        "allowed_methods": ("GET", "HEAD"),
        "max_actions": 3,
    }
    values.update(scope_overrides)
    return Engagement(
        scope=ScopeDefinition(**values),
        authorization=EngagementAuthorization(
            asserted=True,
            asserted_by="operator",
            asserted_at=10.0,
            expires_at=100.0,
        ),
    )


def test_legacy_authorization_context_is_closed_by_default():
    assert create_auth_context("https://example.test").scope.authorized is False


def test_action_authority_denies_missing_authorization():
    engagement = Engagement(scope=ScopeDefinition(target="https://example.test"))
    decision = ActionAuthority().evaluate(
        ActionRequest(capability="fetch", url="https://example.test/"),
        engagement,
        now=20.0,
    )

    assert decision.kind is ActionDecisionKind.DENY
    assert decision.reason == "authorization_missing_or_expired"


def test_action_authority_allows_exact_host_read():
    decision = ActionAuthority().evaluate(
        ActionRequest(capability="fetch", url="https://example.test/meta"),
        _engagement(),
        now=20.0,
    )

    assert decision.kind is ActionDecisionKind.ALLOW
    assert decision.envelope is not None
    assert decision.envelope.normalized_url == "https://example.test/meta"


def test_action_authority_denies_lookalike_host():
    decision = ActionAuthority().evaluate(
        ActionRequest(capability="fetch", url="https://example.test.attacker.invalid/"),
        _engagement(),
        now=20.0,
    )

    assert decision.kind is ActionDecisionKind.DENY
    assert decision.reason == "host_out_of_scope"


def test_state_change_approval_is_bound_to_exact_action():
    request = ActionRequest(
        capability="authenticated_check",
        url="https://example.test/profile",
        method="POST",
        action_class=ActionClass.REVERSIBLE_STATE_CHANGE,
        summary="Validate a reversible profile update",
    )
    engagement = _engagement(allowed_methods=("GET", "HEAD", "POST"))
    authority = ActionAuthority()

    pending = authority.evaluate(request, engagement, now=20.0)
    assert pending.kind is ActionDecisionKind.REQUIRE_CONFIRMATION
    assert pending.approval is not None

    allowed = authority.evaluate(
        request,
        engagement,
        now=20.0,
        approved_identity=pending.approval.action_identity,
    )
    assert allowed.kind is ActionDecisionKind.ALLOW


def test_prohibited_action_cannot_be_approved():
    request = ActionRequest(
        capability="destructive_action",
        url="https://example.test/",
        method="POST",
        action_class=ActionClass.PROHIBITED,
    )
    engagement = _engagement(allowed_methods=("GET", "HEAD", "POST"))

    decision = ActionAuthority().evaluate(
        request,
        engagement,
        now=20.0,
        approved_identity=request.identity_key(),
    )

    assert decision.kind is ActionDecisionKind.DENY
    assert decision.reason == "prohibited_action_class"
