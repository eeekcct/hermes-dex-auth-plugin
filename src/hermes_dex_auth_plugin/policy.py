"""Match verified Dex identities against an explicit login allowlist."""

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Self, cast


def mapping(value: object, *, field: str, keys: Collection[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be a mapping")
    entries = cast(Mapping[object, object], value)
    unknown = set(entries) - set(keys)
    if unknown:
        raise ValueError(f"Unknown {field} setting: {', '.join(sorted(map(str, unknown)))}")
    return cast(Mapping[str, object], entries)


def text(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _rules(value: object, *, field: str, identity_key: str) -> frozenset[tuple[str, str]]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    result: list[tuple[str, str]] = []
    for item in cast(list[object], value):
        rule = mapping(item, field=field, keys=("connector_id", identity_key))
        result.append(
            (
                text(rule.get("connector_id"), field=f"{field}.connector_id"),
                text(rule.get(identity_key), field=f"{field}.{identity_key}"),
            )
        )
    return frozenset(result)


@dataclass(frozen=True)
class AccessPolicy:
    users: frozenset[tuple[str, str]] = frozenset()
    groups: frozenset[tuple[str, str]] = frozenset()

    def __post_init__(self) -> None:
        if not self.users and not self.groups:
            raise ValueError("Dex access requires at least one user or group rule")

    @classmethod
    def from_config(cls, value: object) -> Self:
        access = mapping(value, field="access", keys=("users", "groups"))
        return cls(
            users=_rules(access.get("users", []), field="access.users", identity_key="user_id"),
            groups=_rules(access.get("groups", []), field="access.groups", identity_key="name"),
        )

    def allows(self, claims: Mapping[str, object]) -> bool:
        identity = claims.get("federated_claims")
        if not isinstance(identity, dict):
            return False
        federated_claims = cast(dict[str, object], identity)
        connector_id = federated_claims.get("connector_id")
        user_id = federated_claims.get("user_id")
        if not isinstance(connector_id, str) or not isinstance(user_id, str) or not user_id:
            return False
        if (connector_id, user_id) in self.users:
            return True
        groups = claims.get("groups", [])
        if not isinstance(groups, list):
            return False
        group_names = cast(list[object], groups)
        if any(not isinstance(group, str) for group in group_names):
            return False
        return any((connector_id, group) in self.groups for group in group_names)
