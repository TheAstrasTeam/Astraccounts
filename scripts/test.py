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
    print("  Login succeeded" if status == 200 else "  Login failed: User does not exist or wrong password")


MENU = """
==== Astraccounts Test ====
Current API URL: {base_url}
1) Helath Check  GET  /api/health
2) Register      POST /api/register
3) Login      POST /api/login
4) Edit API URL
0) Exit
"""


def main() -> int:
    base_url = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.getenv("ASTRACCOUNTS_BASE_URL", DEFAULT_BASE_URL)
    )

    actions = {"1": do_health, "2": do_register, "3": do_login}

    while True:
        print(MENU.format(base_url=base_url))
        try:
            choice = ask("Please choose: ")
        except EOFError:
            print()
            return 0

        if choice == "0":
            return 0
        if choice == "4":
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
