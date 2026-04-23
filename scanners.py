import requests
import shodan
import socket

# Глобальный таймаут (для shodan тоже помогает)
socket.setdefaulttimeout(10)


def scan_ip_shodan(ip, api_key):
    """Получение данных о хосте из Shodan"""
    
    if not api_key:
        return {"error": "Shodan API key missing"}

    try:
        api = shodan.Shodan(api_key)
        results = api.host(ip)

        return {
            "city": results.get('city', 'N/A'),
            "isp": results.get('isp', 'N/A'),
            "ports": results.get('ports', []),
            "os": results.get('os', 'N/A'),
            "hostnames": results.get('hostnames', []),
            "org": results.get('org', 'N/A')
        }

    except shodan.APIError as e:
        return {"error": f"Shodan API error: {str(e)}"}

    except socket.timeout:
        return {"error": "Shodan timeout"}

    except Exception as e:
        return {"error": f"Shodan: {str(e)}"}


def scan_ip_vt(ip, api_key):
    """Проверка репутации IP в VirusTotal"""

    if not api_key:
        return {"error": "VirusTotal API key missing"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            attr = data['data']['attributes']
            stats = attr['last_analysis_stats']

            return {
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "harmless": stats.get('harmless', 0),
                "reputation": attr.get('reputation', 0),
                "as_owner": attr.get('as_owner', 'N/A')
            }

        elif response.status_code == 401:
            return {"error": "VT invalid API key"}

        elif response.status_code == 429:
            return {"error": "VT rate limit exceeded"}

        return {"error": f"VT status: {response.status_code}"}

    except requests.exceptions.Timeout:
        return {"error": "VirusTotal timeout"}

    except requests.exceptions.ConnectionError:
        return {"error": "VirusTotal connection error"}

    except Exception as e:
        return {"error": f"VirusTotal: {str(e)}"}
