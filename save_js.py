"""Save login.js - correct path this time"""
import truststore, requests, re, base64, random
from urllib.parse import urljoin
from pathlib import Path
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

truststore.inject_into_ssl()
s = requests.Session()
s.trust_env = False
s.proxies.clear()
s.headers.update({"User-Agent": "Mozilla/5.0"})
AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
VPN = "https://webvpn.sylu.edu.cn"

def rs(n):
    return "".join(random.SystemRandom().choice(AES_CHARS) for _ in range(n))

# login
e = f"{VPN}/login?cas_login=true"
f = s.get(e, timeout=15, allow_redirects=False)
c = urljoin(f.url, f.headers.get("Location"))
p = s.get(c, timeout=15)
sp = BeautifulSoup(p.text, "html.parser")
fm = sp.select_one("#pwdFromId")
sa = fm.select_one("#pwdEncryptSalt").get("value")
ex = fm.select_one("#execution").get("value")
ac = fm.get("action", "").strip()
au = urljoin(p.url, ac)
k = sa.encode()
iv = rs(16).encode()
pt = (rs(64) + "@Zhoukangwu0").encode()
ci = AES.new(k, AES.MODE_CBC, iv=iv)
ct = ci.encrypt(pad(pt, AES.block_size))
ep = base64.b64encode(ct).decode()
lr = s.post(au, params={"service": f"{VPN}/login?cas_login=true"},
    data={"username": "2403060128", "password": ep, "_eventId": "submit",
          "cllt": "userNameLogin", "dllt": "generalLogin", "lt": "", "execution": ex},
    timeout=15, allow_redirects=False)
nu = urljoin(lr.url, lr.headers.get("Location"))
for _ in range(5):
    cur = s.get(nu, timeout=15, allow_redirects=False)
    if cur.status_code in (301, 302, 303, 307, 308):
        nu = urljoin(cur.url, cur.headers.get("Location", ""))
    else:
        break

ticket = s.cookies.get("wengine_vpn_ticketwebvpn_sylu_edu_cn")
print(f"Ticket: {bool(ticket)}")

# CORRECT: jscript/ relative to UserLogin.aspx = /SyluTW/Sys/jscript/
erke_base = f"{VPN}/http/77726476706e69737468656265737421e8f00f8f3e3c7d1e7b0c9ce29b5b/SyluTW/Sys/"
r = s.get(f"{erke_base}jscript/login.js", timeout=15)
print(f"Status: {r.status_code}, CT: {r.headers.get('Content-Type','')[:60]}, Len: {len(r.text)}")

if r.status_code == 200:
    Path("debug/login.js").write_text(r.text, encoding="utf-8")
    print("Saved to debug/login.js!")
    print("=" * 60)
    print(r.text[:5000])
