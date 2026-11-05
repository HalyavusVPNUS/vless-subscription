#!/usr/bin/env python3
"""Fetch an Xray JSON subscription and export its VLESS outbounds as links."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote, urlencode

SOURCE_URL = (
    "https://raw.githubusercontent.com/OceaniaVPN/StekloVPN/refs/heads/main/"
    "configs/okeania_auto.txt"
)
OUTPUT_FILE = Path("hysteria.txt")
TIMEOUT_SECONDS = 40
USER_AGENT = "VLESS-JSON-Subscription-Converter/1.0"


def fetch_source() -> str:
    request = urllib.request.Request(
        SOURCE_URL,
        headers={"User-Agent": USER_AGENT, "Accept": "text/plain, application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise RuntimeError(f"Исходная подписка вернула HTTP {response.status}")
            return response.read().decode("utf-8-sig")
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"Не удалось скачать исходную подписку: {exc}") from exc


def parse_documents(raw_text: str) -> list[dict]:
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Исходный файл не является корректным JSON-массивом. "
            f"Ошибка возле строки {exc.lineno}, столбца {exc.colno}."
        ) from exc

    if isinstance(data, dict):
        documents = [data]
    elif isinstance(data, list):
        documents = data
    else:
        raise RuntimeError("Ожидался JSON-объект или массив JSON-объектов.")

    return [item for item in documents if isinstance(item, dict)]


def add_param(params: dict[str, str], key: str, value) -> None:
    """Add a non-empty URI query parameter, formatting lists safely."""
    if value is None or value == "":
        return
    if isinstance(value, bool):
        params[key] = "1" if value else "0"
    elif isinstance(value, (list, tuple)):
        if value:
            params[key] = ",".join(str(item) for item in value if item is not None)
    else:
        params[key] = str(value)


def make_vless_link(address: str, port: int, user: dict, stream: dict, name: str) -> str:
    user_id = str(user.get("id", "")).strip()
    if not user_id:
        raise ValueError("у пользователя VLESS отсутствует id")

    host = address.strip()
    if not host:
        raise ValueError("у сервера отсутствует address")
    # IPv6 addresses must be enclosed in square brackets in a URI authority.
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        host = f"[{host}]"

    params: dict[str, str] = {}
    add_param(params, "encryption", user.get("encryption", "none"))
    add_param(params, "flow", user.get("flow"))

    security = str(stream.get("security", "none") or "none").lower()
    add_param(params, "security", security)

    if security == "reality":
        reality = stream.get("realitySettings") or {}
        add_param(params, "sni", reality.get("serverName"))
        add_param(params, "fp", reality.get("fingerprint"))
        add_param(params, "pbk", reality.get("publicKey"))
        add_param(params, "sid", reality.get("shortId"))
        add_param(params, "spx", reality.get("spiderX"))
    elif security == "tls":
        tls = stream.get("tlsSettings") or {}
        add_param(params, "sni", tls.get("serverName"))
        add_param(params, "fp", tls.get("fingerprint"))
        add_param(params, "alpn", tls.get("alpn"))
        add_param(params, "allowInsecure", tls.get("allowInsecure"))

    network = str(stream.get("network", "tcp") or "tcp").lower()
    network_aliases = {"raw": "tcp", "splithttp": "xhttp"}
    transport = network_aliases.get(network, network)
    add_param(params, "type", transport)

    if network in ("tcp", "raw"):
        tcp = stream.get("tcpSettings") or {}
        header = tcp.get("header") or {}
        header_type = header.get("type")
        if header_type and header_type != "none":
            add_param(params, "headerType", header_type)

    elif network == "ws":
        ws = stream.get("wsSettings") or {}
        add_param(params, "path", ws.get("path"))
        headers = ws.get("headers") or {}
        add_param(params, "host", headers.get("Host") or headers.get("host"))

    elif network == "grpc":
        grpc = stream.get("grpcSettings") or {}
        add_param(params, "serviceName", grpc.get("serviceName"))
        add_param(params, "authority", grpc.get("authority"))
        if grpc.get("multiMode") is True:
            add_param(params, "mode", "multi")

    elif network == "xhttp":
        xhttp = stream.get("xhttpSettings") or stream.get("splithttpSettings") or {}
        add_param(params, "path", xhttp.get("path"))
        add_param(params, "host", xhttp.get("host"))
        add_param(params, "mode", xhttp.get("mode"))

    elif network == "httpupgrade":
        httpupgrade = stream.get("httpupgradeSettings") or {}
        add_param(params, "path", httpupgrade.get("path"))
        add_param(params, "host", httpupgrade.get("host"))

    elif network == "kcp":
        kcp = stream.get("kcpSettings") or {}
        header = kcp.get("header") or {}
        add_param(params, "headerType", header.get("type"))
        add_param(params, "seed", kcp.get("seed"))

    query = urlencode(params)
    fragment = quote(name or "VLESS", safe="")
    return f"vless://{quote(user_id, safe='')}@{host}:{port}?{query}#{fragment}"


def is_generic_name(name: str) -> bool:
    lowered = name.casefold()
    return any(token in lowered for token in ("балансировщик", "balancer", "auto", "proxy-"))


def convert_documents(documents: list[dict]) -> tuple[list[str], int, int]:
    # key -> (link, label quality). Keeping insertion order preserves source order.
    unique: dict[tuple, tuple[str, int]] = {}
    total_vless_outbounds = 0
    skipped = 0

    for document in documents:
        outbounds = document.get("outbounds") or []
        if not isinstance(outbounds, list):
            continue

        vless_outbounds = [
            item for item in outbounds
            if isinstance(item, dict) and str(item.get("protocol", "")).lower() == "vless"
        ]
        total_vless_outbounds += len(vless_outbounds)
        remarks = str(document.get("remarks", "")).strip()

        for outbound in vless_outbounds:
            tag = str(outbound.get("tag", "")).strip()
            settings = outbound.get("settings") or {}
            servers = settings.get("vnext") or []
            stream = outbound.get("streamSettings") or {}
            if not isinstance(servers, list):
                skipped += 1
                continue

            if len(vless_outbounds) == 1 and remarks:
                name = remarks
                quality = 1 if is_generic_name(remarks) else 10
            elif tag:
                name = tag
                quality = 0 if is_generic_name(tag) else 4
            else:
                name = remarks or "VLESS"
                quality = 0

            for server in servers:
                if not isinstance(server, dict):
                    skipped += 1
                    continue
                address = str(server.get("address", "")).strip()
                try:
                    port = int(server.get("port"))
                except (TypeError, ValueError):
                    skipped += 1
                    continue
                if not address or not (1 <= port <= 65535):
                    skipped += 1
                    continue

                users = server.get("users") or []
                if not isinstance(users, list):
                    skipped += 1
                    continue

                for user in users:
                    if not isinstance(user, dict):
                        skipped += 1
                        continue
                    try:
                        link = make_vless_link(address, port, user, stream, name)
                    except (TypeError, ValueError):
                        skipped += 1
                        continue

                    # Include transport/security settings in the key: same IP with
                    # a different UUID or Reality/TLS setup is a different profile.
                    dedupe_key = (
                        address,
                        port,
                        str(user.get("id", "")),
                        str(user.get("encryption", "none")),
                        str(user.get("flow", "")),
                        json.dumps(stream, sort_keys=True, ensure_ascii=False, separators=(",", ":")),
                    )
                    previous = unique.get(dedupe_key)
                    if previous is None or quality > previous[1]:
                        unique[dedupe_key] = (link, quality)

    links = [item[0] for item in unique.values()]
    return links, total_vless_outbounds, skipped


def main() -> int:
    try:
        raw_text = fetch_source()
        documents = parse_documents(raw_text)
        links, outbound_count, skipped = convert_documents(documents)

        # Do not replace a working subscription with an empty file after an
        # upstream format change or an unexpected source response.
        if not links:
            raise RuntimeError(
                "Не найдено ни одной пригодной VLESS-конфигурации. "
                "Старый hysteria.txt оставлен без изменений."
            )

        new_content = "\n".join(links) + "\n"
        OUTPUT_FILE.write_text(new_content, encoding="utf-8", newline="\n")

        print(f"JSON-профилей: {len(documents)}")
        print(f"VLESS-outbounds: {outbound_count}")
        print(f"Уникальных VLESS-ссылок: {len(links)}")
        print(f"Пропущено некорректных элементов: {skipped}")
        print(f"Файл обновлён: {OUTPUT_FILE}")
        return 0

    except Exception as exc:  # GitHub Actions should show a clear failure.
        print(f"ОШИБКА: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
