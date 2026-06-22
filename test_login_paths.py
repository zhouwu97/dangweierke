"""Test SystemForm/Login.aspx with working VPN session"""
import truststore, requests, re, base64, random, binascii
from urllib.parse import urljoin
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

# VPN login
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
print(f"VPN OK: {bool(ticket)}")

# Build VPN URL
cipher = AES.new(b"wrdvpnisthebest!", AES.MODE_CFB, b"wrdvpnisthebest!", segment_size=128)
enc = cipher.encrypt(b"xg.sylu.edu.cn")
host_hex = b"wrdvpnisthebest!".hex() + enc.hex()

for path in ["/SyluTW/Sys/SystemForm/Login.aspx", "/SyluTW/Sys/UserLogin.aspx"]:
    url = f"{VPN}/http/{host_hex}{path}"
    r = s.get(url, timeout=15)
    print(f"\n{path}: HTTP {r.status_code}")
    if r.status_code == 200:
        soup = BeautifulSoup(r.text, "html.parser")
        has_user = bool(soup.select_one('input[name="UserName"]'))
        has_pubkey = bool(soup.select_one('input[name="pubKey"]'))
        print(f"  UserName={has_user}, pubKey={has_pubkey}")

        # Check for image captcha
        captcha_src = None
        for img in soup.find_all("img"):
            src = (img.get("src") or "").lower()
            if any(kw in src for kw in ("code", "check", "valid", "captcha")):
                captcha_src = img.get("src")
                print(f"  CAPTCHA IMG: {captcha_src}")
                break

        if not captcha_src:
            # Check #code-box
            cb = soup.select_one("#code-box")
            if cb:
                print(f"  code-box exists, text: {repr(cb.get_text()[:50])}")

        # Print all img srcs
        imgs = [(i.get("id",""), i.get("src","")[:60]) for i in soup.find_all("img")]
        print(f"  All imgs: {imgs}")
