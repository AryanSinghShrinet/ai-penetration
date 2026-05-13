import requests

def apply_auth(session: requests.Session, auth_config):
    if not auth_config.get("enabled"):
        return session

    auth_type = auth_config.get("type")

    if auth_type == "cookie":
        raw = auth_config.get("cookie", {}).get("raw", "")
        cookies = {}
        if raw:
            for part in raw.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    cookies[k] = v
            session.cookies.update(cookies)

    elif auth_type == "bearer":
        token = auth_config.get("bearer", {}).get("token")
        if token:
            session.headers.update({
                "Authorization": f"Bearer {token}"
            })

    elif auth_type == "header":
        h = auth_config.get("header", {})
        if h.get("name") and h.get("value"):
            session.headers.update({
                h["name"]: h["value"]
            })

    # FIX A1: Support HTTP Basic Auth (username:password)
    elif auth_type == "basic":
        creds = auth_config.get("basic", {})
        username = creds.get("username", "")
        password = creds.get("password", "")
        if username:
            session.auth = (username, password)

    return session
