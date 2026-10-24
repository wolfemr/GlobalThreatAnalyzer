from dotenv import load_dotenv
import json
import os
import requests
import sys

load_dotenv('.env')

apiKey = os.getenv('ABUSEIPDB_API_KEY')
reportCategories = {
    "1": "DNS Compromise",
    "2": "DNS Poisoning",
    "3": "Fraud Orders",
    "4": "DDoS Attack",
    "5": "FTP Brute-Force",
    "6": "Ping of Death",
    "7": "Phishing",
    "8": "Fraud VoIP",
    "9": "Open Proxy",
    "10": "Web Spam",
    "11": "Email Spam",
    "12": "Blog Spam",
    "13": "VPN IP",
    "14": "Port Scan",
    "15": "Hacking",
    "16": "SQL Injection",
    "17": "Spoofing",
    "18": "Brute-Force",
    "19": "Bad Web Bot",
    "20": "Exploited Host",
    "21": "Web App Attack",
    "22": "SSH",
    "23": "IoT Targeted"
}

def getBlacklist():
    blackListApiURL = 'https://api.abuseipdb.com/api/v2/blacklist'

    headers = {
        'Accept': 'application/json',
        'Key': apiKey
    }

    response = requests.request("GET", blackListApiURL, headers=headers)

    # Formatted output
    decodedResponse = json.loads(response.text)
    print (json.dumps(decodedResponse, indent=4, sort_keys=True))

def checkIP(ip):
    checkApiURL = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '30',
        'verbose': 'true'
    }

    headers = {
        'Accept': 'application/json',
        'Key': apiKey
    }

    response = requests.request("GET", checkApiURL, headers=headers, params=querystring)

    decodedResponse = json.loads(response.text)
    print (json.dumps(decodedResponse, indent=4, sort_keys=True))

def getAsn(ip):
    response = requests.get('https://ip2asn.net/json?ip=8.8.8.8')
    data = response.json()
    print(f"ASNs: {data['origins']}")
# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    checkIP('35.226.148.10')
