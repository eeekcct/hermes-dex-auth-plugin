"""Login access rules must not cross Dex connector boundaries."""

import unittest

from support import AccessPolicy


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = AccessPolicy.from_config(
            {
                "users": [
                    {"connector_id": "github", "user_id": "123"},
                    {"connector_id": "oidc", "user_id": "employee-id"},
                ],
                "groups": [{"connector_id": "github", "name": "my-org:platform"}],
            }
        )

    def _claims(self, connector: object = "github", user: object = "123", groups: object = None) -> dict[str, object]:
        return {
            "federated_claims": {"connector_id": connector, "user_id": user},
            "groups": [] if groups is None else groups,
        }

    def test_multiple_users_and_non_numeric_ids(self) -> None:
        self.assertTrue(self.policy.allows(self._claims()))
        self.assertTrue(self.policy.allows(self._claims("oidc", "employee-id")))

    def test_users_or_groups_allow_access(self) -> None:
        self.assertTrue(self.policy.allows(self._claims(user="other", groups=["my-org:platform"])))
        self.assertFalse(self.policy.allows(self._claims(user="other", groups=["my-org:other"])))

    def test_same_user_or_group_in_another_connector_is_denied(self) -> None:
        self.assertFalse(self.policy.allows(self._claims("other", "123", ["my-org:platform"])))

    def test_group_matching_is_exact(self) -> None:
        for group in ("my-org", "my-org:platform-admin", "MY-ORG:PLATFORM", "*"):
            with self.subTest(group=group):
                self.assertFalse(self.policy.allows(self._claims(user="other", groups=[group])))

    def test_missing_or_malformed_claims_cannot_match_groups(self) -> None:
        for claims in (
            {},
            {"groups": ["my-org:platform"]},
            {
                "federated_claims": {"connector_id": "github"},
                "groups": ["my-org:platform"],
            },
            self._claims(user=123),
            self._claims(user="other", groups="my-org:platform"),
            self._claims(user="other", groups=["my-org:platform", 123]),
        ):
            with self.subTest(claims=claims):
                self.assertFalse(self.policy.allows(claims))

    def test_empty_policy_is_rejected(self) -> None:
        empty_policies: tuple[object, ...] = ({}, {"users": [], "groups": []})
        for value in empty_policies:
            with self.subTest(value=value), self.assertRaises(ValueError):
                AccessPolicy.from_config(value)

    def test_invalid_rules_are_rejected_instead_of_ignored(self) -> None:
        invalid_policies: tuple[object, ...] = (
            None,
            [],
            {"user": []},
            {"users": "123"},
            {"users": [{"connector_id": "github", "user_id": 123}]},
            {"users": [{"connector_id": "", "user_id": "123"}]},
            {"users": [{"user_id": "123"}]},
            {"groups": [{"connector_id": "github", "name": ""}]},
            {"groups": [{"connector_id": "github", "name": "team", "role": "admin"}]},
        )
        for value in invalid_policies:
            with self.subTest(value=value), self.assertRaises(ValueError):
                AccessPolicy.from_config(value)


if __name__ == "__main__":
    unittest.main()
