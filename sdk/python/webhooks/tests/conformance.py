import json
from pathlib import Path

from platform93_webhooks import assert_supported_platform_event, is_platform_event, verify_webhook


fixture = json.loads(
    (Path(__file__).parents[4] / "conformance" / "webhook.json").read_text()
)
event = verify_webhook(
    fixture["raw_body"].encode(),
    fixture["signature"],
    fixture["secret"],
    now=fixture["timestamp"],
)
assert event["id"] == "01900000-0000-7000-8000-000000000001"
assert is_platform_event(event)
assert_supported_platform_event(event)
