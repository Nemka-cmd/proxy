import yaml
import base64
import urllib.parse
import sys

def parse_proxy(line):
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    try:
        if '://' not in line:
            return None
        
        scheme, rest = line.split('://', 1)
        scheme = scheme.lower()
        
        # Базовая структура для Clash Meta
        proxy = {'name': f'Proxy-{scheme}', 'type': scheme}

        if scheme == 'ss':
            # ss://method:pass@host:port#name
            if '#' in rest:
                rest, name = rest.split('#', 1)
                proxy['name'] = urllib.parse.unquote(name)
            
            # Декодирование base64 части (иногда бывает полностью в base64)
            if '@' in rest:
                auth_host, port = rest.rsplit(':', 1)
                auth, host = auth_host.rsplit('@', 1)
                try:
                    decoded = base64.b64decode(auth).decode()
                    method, password = decoded.split(':', 1)
                    proxy.update({'cipher': method, 'password': password, 'server': host, 'port': int(port)})
                except:
                    return None # Пропускаем, если не получилось раскодировать
            else:
                return None

        elif scheme == 'trojan':
            # trojan://pass@host:port?sni=...#name
            if '#' in rest:
                rest, name = rest.split('#', 1)
                proxy['name'] = urllib.parse.unquote(name)
            
            if '?' in rest:
                address, query = rest.split('?', 1)
                params = urllib.parse.parse_qs(query)
                proxy['sni'] = params.get('sni', [address.split('@')[1] if '@' in address else ''])[0]
            else:
                address = rest
            
            if '@' in address:
                password, host_port = address.split('@', 1)
                host, port = host_port.rsplit(':', 1)
                proxy.update({'password': password, 'server': host, 'port': int(port)})

        elif scheme in ['vless', 'vmess']:
            # Упрощенная обработка для примера. 
            # VLESS/Vmess сложные, часто лучше использовать готовые ссылки
            # Для простоты здесь создаем заглушку, если парсинг сложен
            return None 

        else:
            return None # Поддерживаем только ss и trojan для простоты скрипта

        return proxy

    except Exception:
        return None

def main():
    proxies = []
    try:
        with open('proxies.txt', 'r', encoding='utf-8') as f:
            lines = f.readlines()
            for line in lines:
                p = parse_proxy(line)
                if p:
                    proxies.append(p)
    except FileNotFoundError:
        print("proxies.txt not found")

    # Создаем структуру конфига Clash Meta
    config = {
        'proxies': proxies,
        'proxy-groups': [
            {
                'name': 'Auto',
                'type': 'url-test',
                'proxies': [p['name'] for p in proxies],
                'url': 'https://www.gstatic.com/generate_204',
                'interval': 300,
                'tolerance': 100
            }
        ],
        'rules': [
            'MATCH,Auto'
        ]
    }

    # Если прокси нет, добавляем фейковый, чтобы файл был валидным
    if not proxies:
        config['proxies'].append({'name': 'No-Proxy', 'type': 'direct'})
        config['proxy-groups'][0]['proxies'].append('No-Proxy')

    with open('subscription.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    
    print(f"Generated {len(proxies)} proxies.")

if __name__ == '__main__':
    main()
