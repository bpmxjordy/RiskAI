# helpers.py
import requests
from config import ABUSEIPDB_KEY

CHECKED_IPS = {}

def check_ip_threat(ip_address):
    if ip_address in CHECKED_IPS and 'threat_score' in CHECKED_IPS[ip_address]: return CHECKED_IPS[ip_address]['threat_score']
    if ip_address.startswith(('192.168.', '10.')): return 0
    try:
        response = requests.get('https://api.abuseipdb.com/api/v2/check',
            params={'ipAddress': ip_address, 'maxAgeInDays': '90'},
            headers={'Accept': 'application/json', 'Key': ABUSEIPDB_KEY})
        score = response.json().get('data', {}).get('abuseConfidenceScore', 0)
        if ip_address not in CHECKED_IPS: CHECKED_IPS[ip_address] = {}
        CHECKED_IPS[ip_address]['threat_score'] = score
        return score
    except requests.RequestException: return 0

def get_geoip_details(ip_address):
    if ip_address in CHECKED_IPS and 'geoip' in CHECKED_IPS[ip_address]: return CHECKED_IPS[ip_address]['geoip']
    if ip_address.startswith(('192.168.', '10.')): return {"country": "Private Network", "city": "-", "isp": "Local"}
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()
        details = {"country": data.get("country", "N/A"), "city": data.get("city", "N/A"), "isp": data.get("isp", "N/A")}
        if ip_address not in CHECKED_IPS: CHECKED_IPS[ip_address] = {}
        CHECKED_IPS[ip_address]['geoip'] = details
        return details
    except requests.RequestException: return {"country": "Error", "city": "Error", "isp": "Error"}