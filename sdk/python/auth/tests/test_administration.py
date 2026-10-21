import json
import unittest
import httpx
from platform93_auth import ApplicationAdministrationClient


class AdministrationTests(unittest.TestCase):
    def test_user_bearer_versions_and_invitation_copy(self):
        calls = []

        def transport(request):
            calls.append(request)
            self.assertEqual(request.headers["Authorization"], "Bearer user-token")
            self.assertNotIn("/control/", request.url.path)
            if request.method in {"PATCH", "DELETE"}:
                return httpx.Response(204)
            return httpx.Response(201, json={"id": "created", "version": 1, "invitation_url": "https://app.example/invite", "email_queued": False})

        api = ApplicationAdministrationClient("https://platform93.test", "application", lambda: "user-token", client=httpx.Client(transport=httpx.MockTransport(transport)))
        api.create_user({"email": "person@example.test", "reason": "Onboard"}, "create-key")
        api.update_user("created", {"first_name": "Person", "reason": "Correct profile"}, '"v1"')
        result = api.create_invitation({"email": "person@example.test", "onboarding_method": "google", "send_email": False, "reason": "Invite"}, "invite-key")
        self.assertFalse(result["email_queued"])
        self.assertEqual(calls[0].headers["Idempotency-Key"], "create-key")
        self.assertEqual(calls[1].headers["If-Match"], '"v1"')
        self.assertFalse(json.loads(calls[2].content)["send_email"])
        api.list_assignments("recipient", query="reader & owner", cursor="next", limit=15)
        self.assertEqual(calls[3].url.params["user_id"], "recipient")
        self.assertEqual(calls[3].url.params["query"], "reader & owner")
        self.assertEqual(calls[3].url.params["cursor"], "next")
        self.assertEqual(calls[3].url.params["limit"], "15")


if __name__ == "__main__":
    unittest.main()
