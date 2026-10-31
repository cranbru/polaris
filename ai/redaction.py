import re

EMAIL_PATTERN = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
JWT_OR_KEY_PATTERN = r"(?:ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|(?:sk|ak|ghp|gho)_[A-Za-z0-9]{16,})"
BEARER_PATTERN = r"(?i)bearer\s+[A-Za-z0-9\-_=.]+"
PASSWORD_PATTERN = r"(?i)(?:password|pwd|passwd|secret)\s*[:=]\s*[^\s,;]+"


class RedactionManager:
    @staticmethod
    def redact(text: str) -> str:
        if not text:
            return ""

        redacted = text
        redacted = re.sub(EMAIL_PATTERN, "[REDACTED_EMAIL]", redacted)
        redacted = re.sub(JWT_OR_KEY_PATTERN, "[REDACTED_API_KEY]", redacted)
        redacted = re.sub(BEARER_PATTERN, "Bearer [REDACTED_TOKEN]", redacted)
        redacted = re.sub(PASSWORD_PATTERN, "password=[REDACTED_SECRET]", redacted)

        return redacted
