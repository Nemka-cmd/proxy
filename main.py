import yaml
import base64
import urllib.parse
import requests
import sys
from datetime import datetime

# Источники прокси (публичные репозитории и подписки)
PROXY_SOURCES = [
    # GitHub raw файлы
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/a2470982985/getNode/main/clash.yaml",
    "https://raw.githubusercontent.com/mianfeifljq/free_proxy/main/proxy.txt",
    # Публичные подписки (base64 encoded)
    # Можешь добавлять свои найденные ссылки
]

def fetch_proxies_from_sources():
    """Скачивает прокси из публичных источников"""
    all_proxies = []
    
    for url in PROXY_SOURCES:
        try:
            print(f"Fetching from {url}...")
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                content = response.text
                
                # Пробуем декодировать base64 (если это подписка)
                try:
                    decoded = base64.b64decode(content).decode('utf-8')
                    lines = decoded.strip().split('\n')
                    all_proxies.extend(lines)
                    print(f"  ✓ Decoded base64: {len(lines)} proxies")
                except:
                    # Если не base64, берем как есть
                    lines = content.strip().split('\n')
                    all_proxies.extend(lines)
                    print(f"  ✓ Plain text: {len(lines)} proxies")
        except Exception as e:
            print(f"  ✗ Error fetching {url}: {e}")
    
    return all_proxies

def parse_proxy(line):
    line = line.strip()
    if not line or line.startswith('#') or '://' not in line:
        return None

    try:
        scheme, rest = line.split('://', 1)
        scheme = scheme.lower()
        proxy = {'name': f'{scheme}-{int(datetime.now().timestamp())}', 'type': scheme}

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
            else:
                return None

        elif scheme == 'trojan':
            if '#' in rest:
                rest, name = rest.split('#', 1)
                proxy['name'] = urllib.parse.unquote(name)
            
            if '?' in rest:
                address, query = rest.split('?', 1)
                params = urllib.parse.parse_qs(query)
                proxy['sni'] = params.get('sni', [''])[0]
            else:
                address = rest
            
            if '@' in address:
                password, host_port = address.split('@', 1)
                host, port = host_port.rsplit(':', 1)
                proxy.update({
                    'password': password, 
                    'server': host, 
                    'port': int(port)
                })

        elif scheme == 'vless':
            # Упрощенный парсинг VLESS
            if '#' in rest:
                rest, name = rest.split('#', 1)
                proxy['name'] = urllib.parse.unquote(name)
            
            if '@' in rest:
                uuid, host_port = rest.split('@', 1)
                if '?' in host_port:
                    host_p, query = host_port.split('?', 1)
                    params = urllib.parse.parse_qs(query)
                    proxy.update({
                        'uuid': uuid,
                        'server': host_p.split(':')[0],
                        'port': int(host_p.split(':')[1]),
                        'tls': params.get('security', ['none'])[0] != 'none',
                        'sni': params.get('sni', [''])[0],
                        'network': params.get('type', ['tcp'])[0]
                    })
                else:
                    host, port = host_port.rsplit(':', 1)
                    proxy.update({
                        'uuid': uuid,
                        'server': host,
                        'port': int(port)
                    })

        else:
            return None

        return proxy

    except Exception as e:
        print(f"Parse error: {e}")
        return None

def main():
    # Шаг 1: Скачиваем прокси из источников
    print("📥 Fetching proxies from sources...")
    raw_proxies = fetch_proxies_from_sources()
    
    # Если хочешь добавить ручные прокси, создай файл manual.txt
    try:
        with open('manual.txt', 'r', encoding='utf-8') as f:
            manual = [l.strip() for l in f.readlines() if l.strip()]
            raw_proxies.extend(manual)
            print(f"➕ Added {len(manual)} manual proxies")
    except FileNotFoundError:
        pass
    
    # Шаг 2: Парсим и фильтруем
    print("🔍 Parsing proxies...")
    proxies = []
    seen = set()
    
    for line in raw_proxies:
        p = parse_proxy(line)
        if p and p['name'] not in seen:
            proxies.append(p)
            seen.add(p['name'])
    
    print(f"✅ Parsed {len(proxies)} valid proxies")
    
    # Шаг 3: Создаем конфиг
    config = {
        'proxies': proxies,
        'proxy-groups': [
            {
                'name': 'Auto',
                'type': 'url-test',
                'proxies': [p['name'] for p in proxies] if proxies else ['Direct'],
                'url': 'https://www.gstatic.com/generate_204',
                'interval': 300,
                'tolerance': 100
            }
        ],
        'rules': ['MATCH,Auto']
    }
    
    if not proxies:
        config['proxies'].append({'name': 'Direct', 'type': 'direct'})
    
    with open('subscription.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    
    print(f"💾 Saved to subscription.yaml")

if __name__ == '__main__':
    main()
