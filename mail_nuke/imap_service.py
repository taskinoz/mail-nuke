from __future__ import annotations

from typing import Any

from imapclient import IMAPClient


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def connect(account: dict, password: str) -> IMAPClient:
    client = IMAPClient(
        host=account["imap_host"],
        port=int(account["imap_port"]),
        ssl=bool(account["imap_use_ssl"]),
        use_uid=True,
        timeout=15,
    )
    client.login(account["imap_username"], password)
    return client


def test_connection(account: dict, password: str) -> dict[str, Any]:
    client = connect(account, password)
    try:
        capabilities = sorted(_text(value) for value in client.capabilities())
        return {"ok": True, "capabilities": capabilities}
    finally:
        client.logout()


def discover_folders(account: dict, password: str) -> list[dict[str, Any]]:
    client = connect(account, password)
    try:
        result = []
        for attributes, delimiter, path in client.list_folders():
            result.append(
                {
                    "path": _text(path),
                    "delimiter": _text(delimiter) if delimiter is not None else None,
                    "attributes": sorted(_text(value) for value in attributes),
                }
            )
        return sorted(result, key=lambda item: item["path"].casefold())
    finally:
        client.logout()
