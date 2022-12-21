import shodan
import requests
from bs4 import BeautifulSoup

def findCve():
    apiKey = 'gpnY8SPlZ28ff4FcUyuC1AXbQiY4GIvj'
    api = shodan.Shodan(apiKey)
    target = input("Enter target\t:")
    dnsResolve = ('https://api.shodan.io/dns/resolve?q=' + target + '&key=' + apiKey)
    try:
        resolved = requests.get(dnsResolve)
        hostIP = resolved.json()[target]
        host = api.host(hostIP)
        for item in host['vulns']:
            CVE = item.replace('!', '')
            print('Vulns: %s' % item)
            with open("/Users/abdulrahmankandil/Documents/Github/Smart-TVs-Vulnerabilities-Investigation/vuln.txt", "a+") as f:
                f.write(CVE + "\n")
            exploits = api.exploits.search(CVE)
            for item in (exploits['matches']):
                if item.get('cve')[0] == CVE:
                    print(item.get('description'))

    except Exception as err:
        print(err)


def exploitFind():
    try:
        with open("/Users/abdulrahmankandil/Documents/Github/Smart-TVs-Vulnerabilities-Investigation/vuln.txt", "r") as f:
            for i in f:
                vuln = i.rstrip("\n")
                for x in range(1, 2):
                    url = f"https://exploits.shodan.io/?q={vuln}&p={x}"
                    print(vuln)
                    headers_param = {
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.167 Safari/537.36"}
                    r = requests.get(url, headers=headers_param)
                    s = BeautifulSoup(r.content, "lxml")
                    c = s.find_all("a", attrs={"class": "bold"})
                    count = 1
                    for j in c:
                        print(">>>" + j["href"] + j.text)
                        count += 1
    except Exception as e:
        print(f"Please check the target: {e}")


findCve()
exploitFind()
