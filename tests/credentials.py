"""Synthetic credentials for exercising the detectors.

Every value here is assembled from fragments rather than written out whole.
A source file containing a string shaped like a live token gets rejected by
secret-scanning push protection — correctly, since a scanner cannot tell an
obviously fake key from a real one by looking. Splitting the literals keeps the
files clean to scan while the values still match the detectors at runtime,
which is the only place it matters.

Nothing here is real. The AWS value is Amazon's own documented example key.
"""

AWS_ACCESS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp" + "_abcdefghijklmnopqrstuvwxyz0123456789"
GITHUB_FINE_GRAINED_TOKEN = "github" + "_pat_11ABCDEFG0abcdefghijklmnop"
SLACK_TOKEN = "xox" + "b-123456789012-abcdefghijklmno"
GOOGLE_API_KEY = "AIza" + "SyA1234567890abcdefghijklmnopqrstuv"  # AIza + exactly 35
STRIPE_KEY = "sk" + "_live_abcdefghij0123456789ABCD"
ANTHROPIC_API_KEY = "sk-ant" + "-api03-abcdefghijklmnopqrst"
OPENAI_STYLE_API_KEY = "sk-proj" + "-abcdefghijklmnopqrstuvwx"
PRIVATE_KEY_HEADER = "-----BEGIN OPENSSH PRIVATE KEY-----"
BEARER_HEADER = "Bearer " + "abcdefghijklmnopqrstuvwxyz012345"
BASIC_AUTH_HEADER = "Basic " + "YWxhZGRpbjpvcGVuc2VzYW1l1234"
JSON_WEB_TOKEN = (
    "eyJ" + "hbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "dozjgNryP4J3jVmNHl0w5N"
)

BY_DETECTOR: list[tuple[str, str]] = [
    ("aws-access-key-id", AWS_ACCESS_KEY_ID),
    ("github-token", GITHUB_TOKEN),
    ("github-fine-grained-token", GITHUB_FINE_GRAINED_TOKEN),
    ("slack-token", SLACK_TOKEN),
    ("google-api-key", GOOGLE_API_KEY),
    ("stripe-key", STRIPE_KEY),
    ("anthropic-api-key", ANTHROPIC_API_KEY),
    ("openai-style-api-key", OPENAI_STYLE_API_KEY),
    ("private-key-block", PRIVATE_KEY_HEADER),
    ("bearer-token", BEARER_HEADER),
    ("basic-auth-header", BASIC_AUTH_HEADER),
    ("json-web-token", JSON_WEB_TOKEN),
]
"""Each built-in detector paired with a value it should catch."""
