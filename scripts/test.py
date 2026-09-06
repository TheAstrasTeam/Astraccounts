#!/usr/bin/env python3

from __future__ import annotations

import getpass
import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_BASE_URL = "http://127.0.0.1:8080"
TIMEOUT_SECONDS = 10

REGISTER_ERRORS = {
    0: "invalid JSON",
    1: "invalid Username",
    2: "invalid or already exist ID",
    3: "invalid or already used e-mail address",
    4: "invalid password",
}

# Holds the token from the most recent successful login.
SESSION: dict[str, str] = {"token": ""}


def request(base_url: str, method: str, path: str, payload: dict | None = None) -> tuple[int, object]:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        url=f"{base_url.rstrip('/')}{path}",
        data=data,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as response:
            return response.status, decode(response.read())
    except urllib.error.HTTPError as error:
        return error.code, decode(error.read())


def decode(raw: bytes) -> object:
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def show(status: int, body: object) -> None:
    print(f"  HTTP {status}")
    if isinstance(body, (dict, list)):
        print("  " + json.dumps(body, ensure_ascii=False, indent=2).replace("\n", "\n  "))
    else:
        print(f"  {body}")


def ask(prompt: str) -> str:
    return input(prompt).strip()


def ask_password(prompt: str) -> str:
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return input(prompt).strip()


def do_health(base_url: str) -> None:
    status, body = request(base_url, "GET", "/api/health")
    show(status, body)


def do_register(base_url: str) -> None:
    payload = {
        "username": ask("Username: "),
        "id": ask("ID: "),
        "email": ask("E-mail address: "),
        "password": ask_password("Password: "),
    }
    status, body = request(base_url, "POST", "/api/register", payload)
    show(status, body)

    if isinstance(body, dict):
        if status == 201:
            print(f"  Register succeeded, UID = {body.get('UID')}")
        elif "err" in body:
            code = body["err"]
            print(f"  Register failed: {REGISTER_ERRORS.get(code, 'Unknown error code')}")


def do_login(base_url: str) -> None:
    payload = {
        "query": ask("ID or E-mail Adress: "),
        "password": ask_password("Password: "),
    }
    status, body = request(base_url, "POST", "/api/login", payload)
    show(status, body)

    if status == 200 and isinstance(body, dict):
        SESSION["token"] = body.get("token", "")
        print("  Login succeeded, token remembered for profile calls")
    else:
        print("  Login failed: User does not exist or wrong password")


def parse_value(raw: str) -> object:
    """Turn console input into a JSON string, number or bool.

    123 -> number, true/false -> bool, anything else -> string.
    Wrap in double quotes to force a string, e.g. "123".
    """
    text = raw.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1]
    if text.lower() == "true":
        return True
    if text.lower() == "false":
        return False
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return text


def ask_uid(prompt: str) -> int | None:
    raw = ask(prompt)
    try:
        return int(raw)
    except ValueError:
        print("  UID must be a number")
        return None


def ask_token(base_url: str) -> str:
    """Reuse the remembered token unless another one is typed in."""
    remembered = SESSION.get("token", "")
    if remembered:
        entered = ask("Token (Enter to reuse the one from login): ")
        return entered or remembered
    return ask("Token: ")


def do_profile_edit(base_url: str) -> None:
    uid = ask_uid("UID: ")
    if uid is None:
        return
    token = ask_token(base_url)

    print("  Enter key/value pairs, empty key to finish.")
    print("  Values: 123 -> number, true/false -> bool, \"123\" -> string")
    content = []
    while True:
        key = ask(f"  content[{len(content)}].key: ")
        if not key:
            break
        value = parse_value(ask(f"  content[{len(content)}].value: "))
        content.append({"key": key, "value": value})
        print(f"    staged {key} = {json.dumps(value, ensure_ascii=False)}")

    if not content:
        print("  Nothing to send")
        return

    status, body = request(
        base_url, "POST", "/api/profile/edit",
        {"UID": uid, "token": token, "content": content},
    )
    show(status, body)

    if status == 200:
        print("  Profile updated")
    elif isinstance(body, dict) and "invalid" in body:
        rejected = ", ".join(json.dumps(k, ensure_ascii=False) for k in body["invalid"])
        print(f"  Rejected keys: {rejected}")
        print("  Nothing was written; check ALLOWED_PROFILE_KEY and value types")
    else:
        print("  Failed: unknown UID, or token missing/invalid/belongs to another user")


def do_profile_view(base_url: str) -> None:
    uid = ask_uid("UID: ")
    if uid is None:
        return

    payload: dict[str, object] = {"UID": uid}
    remembered = SESSION.get("token", "")
    hint = "Token (Enter to reuse the one from login, '-' for anonymous): " if remembered \
        else "Token (Enter for anonymous): "
    token = ask(hint)
    if token == "-":
        token = ""
    elif not token:
        token = remembered
    if token:
        payload["token"] = token

    status, body = request(base_url, "POST", "/api/profile/view", payload)
    show(status, body)

    if status == 200:
        print("  Private keys are only included when the token belongs to this UID")
    else:
        print("  Failed: user does not exist")


MENU = """
==== Astraccounts Test ====
Current API URL: {base_url}
Token: {token}
1) Helath Check   GET  /api/health
2) Register       POST /api/register
3) Login          POST /api/login
4) Edit Profile   POST /api/profile/edit
5) View Profile   POST /api/profile/view
6) Edit API URL
0) Exit
"""


def token_hint() -> str:
    token = SESSION.get("token", "")
    if not token:
        return "(none, log in first)"
    return token if len(token) <= 28 else f"{token[:24]}..."


def main() -> int:
    base_url = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.getenv("ASTRACCOUNTS_BASE_URL", DEFAULT_BASE_URL)
    )

    actions = {
        "1": do_health,
        "2": do_register,
        "3": do_login,
        "4": do_profile_edit,
        "5": do_profile_view,
    }

    while True:
        print(MENU.format(base_url=base_url, token=token_hint()))
        try:
            choice = ask("Please choose: ")
        except EOFError:
            print()
            return 0

        if choice == "0":
            return 0
        if choice == "6":
            entered = ask(f"New API URL（Enter to use {base_url}）: ")
            if entered:
                base_url = entered
            continue

        action = actions.get(choice)
        if action is None:
            print("  Invalid choice")
            continue

        try:
            action(base_url)
        except urllib.error.URLError as error:
            print(f"  Request failed: Cannot connect to {base_url} ({error.reason})")
        except KeyboardInterrupt:
            print("\n  Canceled")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
