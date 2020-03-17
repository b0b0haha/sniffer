import requests
def get_public_ip():
    from json import load
    ip = None
    # four methods to get my public ip
    try:
        ip = requests.get('http://ip.42.pl/raw', timeout=3).text()
        print(ip)

        return ip
    except:
        ip = None

    try:
        ip = load(requests.get('http://jsonip.com', timeout=3))['ip']
        return ip
    except:
        ip = None

    try:
        ip = load(requests.get('http://httpbin.org/ip', timeout=3))['origin']
        return ip
    except:
        ip = None
    try:
        ip = load(
            requests.get('https://api.ipify.org/?format=json', timeout=3))['ip']
        return ip
    except:
        ip = None
    return ip
text= requests.get('http://ip.42.pl/raw').text()
print("text",text)