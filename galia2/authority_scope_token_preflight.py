"""F22/F23 candidate-only preflight for ambiguous legacy P5 scope tokens.

P5 AuthorityScope.token is not injective when delimiters occur in components.
Reject ambiguous input; never rewrite historical tokens or establish authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import unicodedata
from typing import Any

from .authority import AuthorityScope


@dataclass(frozen=True, slots=True)
class ScopePreflightResult:
    legacy_token: str
    case_id: str
    target_type: str
    target_ids: tuple[str, ...]
    status: str = "PREVIEW_ONLY_NOT_AUTHORITY"
    canonical_effect: str = "NONE"
    master_promotion_state: str = "AUTHORITY_HOLD"


def _check_field(field: str, value: Any) -> None:
    if (not isinstance(value, str) or not value or value != value.strip()
        or unicodedata.normalize("NFC", value) != value
        or any(ch in "|," or unicodedata.category(ch) in {"Cc", "Cf", "Cs"} for ch in value)):
        raise ValueError(f"ambiguous legacy P5 scope component: {field}")


def preview_scope_token_preflight(scope: AuthorityScope) -> ScopePreflightResult:
    """Reject ambiguous scope tokens before F23 binding; no authority conferred."""
    if type(scope) is not AuthorityScope:
        raise ValueError("exact AuthorityScope required")
    _check_field("case_id", scope.case_id)
    _check_field("target_type", scope.target_type)
    if not isinstance(scope.target_ids, tuple) or not scope.target_ids:
        raise ValueError("nonempty target_ids tuple required")
    for value in scope.target_ids:
        _check_field("target_ids", value)
    if len(set(scope.target_ids)) != len(scope.target_ids):
        raise ValueError("duplicate target_ids")
    return ScopePreflightResult(scope.token, scope.case_id, scope.target_type, scope.target_ids)
