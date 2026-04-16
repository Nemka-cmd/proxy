import yaml
import base64
import urllib.parse
import asyncio
import time
import requests
from datetime import datetime

# Источники прокси (публичные репозитории)
PROXY_SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/a2470982985/getNode/main/clash.yaml",
    "https://raw.githubusercontent.com/mianfeifljq/free_proxy/main/proxy.txt",
]

# Время ожидания ответа от сервера (секунды)
CHECK_TIMEOUT = 3 

async def check_proxy_alive(host, port):
    """Асинхронная проверка доступности хоста"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=CHECK_TIMEOUT
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

def parse_proxy(line):
    line = line.strip()
    if not line or line.startswith('#') or '://' not in line:
        return None

    try:
        scheme, rest = line.split('://', 1)
        scheme = scheme.lower()
        
        # Временный ID для дедупликации
        proxy_id = f"{scheme}-{int(datetime.now().timestamp())}"
        proxy = {'name': f'{scheme}-{proxy_id}', 'type': scheme}

        host = None
        port = None

        if scheme == 'ss':
            if '#' in rest:
                rest, name = rest.split('#', 1)
                proxy['name'] = urllib.parse.unquote(name)
            
            if '@' in rest:
                auth_host, port = rest.rsplit(':', 1)
                auth, host = auth_host.rsplit('@', 1)
                try:
                    decoded = base64.b64decode(auth).decode()
                    method, password = decoded.split(':', 1)
                    proxy.update({
                        'cipher': method, 
                        'password': password, 
                        'server': host, 
                        'port': int(port)
                    })
                except:
                    return None
        
        elif scheme == 'trojan':
            if '#' in rest:
                rest, name = rest.split('#', 1)
                proxy['name'] = urllib.parse.unquote(name)
            
            address = rest.split('?')[0] # Убираем параметры для хоста
            if '@' in address:
                password, host_port = address.split('@', 1)
                host, port = host_port.rsplit(':', 1)
                proxy.update({
                    'password': password, 
                    'server': host, 
                    'port': int(port)
                })
                # SNI (важно для trojan)
                if '?' in rest:
                     params = urllib.parse.parse_qs(rest.split('?', 1)[1])
                     proxy['sni'] = params.get('sni', [host])[0]

        elif scheme == 'vless':
            if '#' in rest:
                rest, name = rest.split('#', 1)
                proxy['name'] = urllib.parse.unquote(name)
            
            if '@' in rest:
                uuid, host_port_query = rest.split('@', 1)
                host_port = host_port_query.split('?')[0]
                host, port = host_port.rsplit(':', 1)
                
                params = {}
                if '?' in host_port_query:
                    params = urllib.parse.parse_qs(host_port_query.split('?', 1)[1])

                proxy.update({
                    'uuid': uuid,
                    'server': host,
                    'port': int(port),
                    'tls': params.get('security', ['none'])[0] != 'none',
                    'sni': params.get('sni', [host])[0],
                    'network': params.get('type', ['tcp'])[0]
                })

        else:
            return None

        # Сохраняем хост и порт для проверки
        if host and port:
            proxy['_check_host'] = host
            proxy['_check_port'] = int(port)
            return proxy
        return None

    except Exception:
        return None

def fetch_proxies_from_sources():
    all_proxies = []
    for url in PROXY_SOURCES:
        try:
            print(f"📥 Fetching {url}...")
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                content = response.text
                try:
                    # Попытка декодировать Base64
                    decoded = base64.b64decode(content).decode('utf-8')
                    lines = decoded.strip().split('\n')
                    all_proxies.extend(lines)
                except:
                    # Обычный текст
                    all_proxies.extend(content.strip().split('\n'))
        except Exception as e:
            print(f"❌ Error: {e}")
    return all_proxies

async def main():
    print("🌍 Загрузка списков...")
    raw_lines = fetch_proxies_from_sources()
    
    # Добавляем ручные прокси, если есть файл
    try:
        with open('manual.txt', 'r', encoding='utf-8') as f:
            manual_lines = [l.strip() for l in f.readlines() if l.strip()]
            raw_lines.extend(manual_lines)
            print(f"➕ Добавлено {len(manual_lines)} ручных прокси")
    except FileNotFoundError:
        pass

    print("🔍 Парсинг прокси...")
    parsed_proxies = []
    seen_urls = set()
    
    for line in raw_lines:
        p = parse_proxy(line)
        if p:
            unique_key = f"{p['server']}:{p['port']}"
            if unique_key not in seen_urls:
                parsed_proxies.append(p)
                seen_urls.add(unique_key)
    
    print(f"✅ Распарсено {len(parsed_proxies)} уникальных прокси.")
    print(f"⏳ Проверка доступности (может занять до 30 сек)...")

    # Асинхронная проверка всех прокси
    tasks = []
    for p in parsed_proxies:
        tasks.append(check_proxy_alive(p['_check_host'], p['_check_port']))
    
    results = await asyncio.gather(*tasks)

    # Фильтрация
    alive_proxies = []
    for p, is_alive in zip(parsed_proxies, results):
        if is_alive:
            # Удаляем служебные поля перед сохранением
            del p['_check_host']
            del p['_check_port']
            alive_proxies.append(p)
            
    print(f"🟢 Живых прокси: {len(alive_proxies)}")

    # Генерация конфига
    config = {
        'proxies': alive_proxies,
        'proxy-groups': [
            {
                'name': '🚀 Auto-Select',
                'type': 'url-test',
                'proxies': [p['name'] for p in alive_proxies],
                'url': 'https://www.gstatic.com/generate_204',
                'interval': 300,
                'tolerance': 50
            }
        ],
        'rules': ['MATCH,🚀 Auto-Select']
    }
    
    if not alive_proxies:
        config['proxies'].append({'name': 'Direct', 'type': 'direct'})
        config['proxy-groups'][0]['proxies'].append('Direct')

    with open('subscription.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    
    print("💾 Файл subscription.yaml обновлен!")

if __name__ == '__main__':
    asyncio.run(main())
