import base64
import json


def make_token(user_id: str = "u888", role: str | None = None, user_name: str = "张三") -> str:
    payload = {"user_id": user_id, "user_name": user_name}
    if role:
        payload["role"] = role
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"stub.{body}.sig"
