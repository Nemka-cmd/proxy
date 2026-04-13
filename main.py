#!/usr/bin/env python3
"""
Автоматический генератор Clash Meta подписки.
Проверяет прокси, фильтрует мёртвые, сортирует по пингу.
"""

import asyncio
import base64
import time
import urllib.parse
import yaml
import sys
from pathlib import Path

# 🔧 НАСТРОЙКИ
TIMEOUT = 5  # Таймаут проверки (сек)
MAX_LATENCY = 800  # Макс. пинг (мс)
INPUT_FILE = "proxies.txt"
OUTPUT_FILE = "subscription.yaml"
TEST_HOST = "1.1.1.1"
TEST_PORT = 53  # DNS порт открыт почти всегда, быстро отвечает


async def check_latency(host: str, port: int) -> int | None:
    """Возвращает пинг в мс или None, если хост недоступен."""
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=TIMEOUT
        )
        writer.close()
        await writer.wait_closed()
        return int((time.monotonic() - start) * 1000)
    except Exception:
        return None


def parse_proxy(url: str) -> dict | None:
    """Базовый парсер ss://, vless://, trojan:// для Clash Meta."""
    try:
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        name = urllib.parse.unquote(parsed.fragment or f"{scheme}-{int(time.time())}")
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return None

        base = {"name": name, "server": host, "port": port, "udp": True}

        if scheme == "ss":
            auth = parsed.username
            if not auth:
                return None
            try:
                decoded = base64.b64decode(auth).decode()
                cipher, password = decoded.split(":", 1)
            except Exception:
                return None
            base.update({"type": "ss", "cipher": cipher, "password": password})

        elif scheme == "vless":
            uuid = parsed.username
            qs = urllib.parse.parse_qs(parsed.query)
            base.update({
                "type": "vless",
                "uuid": uuid,
                "network": qs.get("type", ["tcp"])[0],
                "tls": True if "tls" in qs.get("security", [""]) or "reality" in qs.get("security", [""]) else False,
                "sni": qs.get("sni", [host])[0],
                "udp": True,
                "flow": qs.get("flow", [""])[0] or "",
                "reality_opts": {
                    "public_key": qs.get("pbk", [""])[0],
                    "short_id": qs.get("sid", [""])[0]
                } if "reality" in qs.get("security", [""]) else {}
            })

        elif scheme == "trojan":
            password = parsed.username
            qs = urllib.parse.parse_qs(parsed.query)
            base.update({
                "type": "trojan",
                "password": password,
                "sni": qs.get("sni", [host])[0],
                "skip_cert_verify": False
            })
        else:
            return None  # Пропускаем неподдерживаемые схемы

        return base
    except Exception:
        return None


async def main():
    input_path = Path(INPUT_FILE)
    if not input_path.exists():
        print(f"❌ Файл {INPUT_FILE} не найден.")
        sys.exit(1)

    raw_urls = [u.strip() for u in input_path.read_text(encoding="utf-8").splitlines() if u.strip()]
    print(f"📥 Загружено {len(raw_urls)} прокси. Тестирую...")

    tasks = []
    for url in raw_urls:
        parsed = urllib.parse.urlparse(url)
        tasks.append((url, check_latency(parsed.hostname, parsed.port)))

    results = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)

    alive_proxies = []
    for (url, _), latency in zip(tasks, results):
        if isinstance(latency, (int, float)) and latency <= MAX_LATENCY:
            proxy_cfg = parse_proxy(url)
            if proxy_cfg:
                proxy_cfg["latency"] = latency
                alive_proxies.append(proxy_cfg)

    alive_proxies.sort(key=lambda x: x["latency"])
    print(f"✅ Рабочих прокси: {len(alive_proxies)}")

    if not alive_proxies:
        print("⚠️ Нет живых прокси. Файл не обновлён.")
        return

    # Генерация Clash Meta конфига
    clash_config = {
        "proxies": [
            {k: v for k, v in p.items() if k != "latency"} for p in alive_proxies
        ],
        "proxy-groups": [
            {
                "name": "🌐 AUTO-SELECT",
                "type": "url-test",
                "proxies": [p["name"] for p in alive_proxies],
                "url": "https://www.google.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "lazy": True
            }
        ],
        "rules": [
            "MATCH,🌐 AUTO-SELECT"
        ]
    }

    output_path = Path(OUTPUT_FILE)
    output_path.write_text(yaml.dump(clash_config, allow_unicode=True, default_flow_style=False), encoding="utf-8")
    print(f"📤 Конфиг сохранён в {OUTPUT_FILE}")


if __name__ == "__main__":
    asyncio.run(main())