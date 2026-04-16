import requests
import shodan

def scan_ip_shodan(ip, api_key):
    """Получение данных о хосте из Shodan"""
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
    except Exception as e:
        return {"error": f"Shodan: {str(e)}"}

def scan_ip_vt(ip, api_key):
    """Проверка репутации IP в VirusTotal"""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            attr = data['data']['attributes']
            stats = attr['last_analysis_stats']
            return {
                "malicious": stats['malicious'],
                "suspicious": stats['suspicious'],
                "harmless": stats['harmless'],
                "reputation": attr.get('reputation', 0),
                "as_owner": attr.get('as_owner', 'N/A')
            }
        return {"error": f"VT Status: {response.status_code}"}
    except Exception as e:
        return {"error": f"VirusTotal: {str(e)}"}
