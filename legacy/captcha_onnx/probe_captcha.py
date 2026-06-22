"""Probe Erke login page - find captcha loading mechanism"""
import truststore, requests, re, base64, random
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

truststore.inject_into_ssl()
s = requests.Session()
s.trust_env = False
s.proxies.clear()
s.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})

AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
VPN = "https://webvpn.sylu.edu.cn"
USER = "2403060128"
PASS = "@Zhoukangwu0"

def rs(n):
    return "".join(random.SystemRandom().choice(AES_CHARS) for _ in range(n))

# --- WebVPN login ---
print("[1] WebVPN login...")
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
pt = (rs(64) + PASS).encode()
ci = AES.new(k, AES.MODE_CBC, iv=iv)
ct = ci.encrypt(pad(pt, AES.block_size))
ep = base64.b64encode(ct).decode()

lr = s.post(au, params={"service": f"{VPN}/login?cas_login=true"},
    data={"username": USER, "password": ep, "_eventId": "submit",
          "cllt": "userNameLogin", "dllt": "generalLogin", "lt": "", "execution": ex},
    timeout=15, allow_redirects=False)

nu = urljoin(lr.url, lr.headers.get("Location"))
for _ in range(3):
    cur = s.get(nu, timeout=15, allow_redirects=False)
    if cur.status_code in (301, 302, 303, 307, 308):
        nu = urljoin(cur.url, cur.headers.get("Location", ""))
    else:
        break

print(f"  Ticket: {bool(s.cookies.get('wengine_vpn_ticketwebvpn_sylu_edu_cn'))}")

# --- Erke login page ---
print("[2] Fetch Erke login page...")
erke = s.get(f"{VPN}/http/77726476706e69737468656265737421e8f00f8f3e3c7d1e7b0c9ce29b5b/SyluTW/Sys/UserLogin.aspx", timeout=15)
es = BeautifulSoup(erke.text, "html.parser")

print("\n=== ALL SCRIPTS (src + content) ===")
for i, sc in enumerate(es.find_all("script")):
    src = sc.get("src", "")
    txt = sc.get_text()[:600] if sc.string else ""
    print(f"\n[{i}] src={src[:120]}")
    if txt.strip():
        print(f"    content: {txt[:500]}")

# --- Try to fetch login.js ---
print("\n\n[3] Fetching login.js...")
try:
    r = s.get(f"{VPN}/http/77726476706e69737468656265737421e8f00f8f3e3c7d1e7b0c9ce29b5b/SyluTW/Jscript/login.js", timeout=10)
    ct = r.headers.get("Content-Type", "")
    print(f"  Status: {r.status_code}, Content-Type: {ct[:60]}, Length: {len(r.text)}")
    if "javascript" in ct.lower() or r.text.strip().startswith(("var", "function", "(function", "$(function")):
        print("\n=== login.js CONTENT ===")
        print(r.text[:5000])
    else:
        print("  NOT JavaScript - first 500 chars:")
        print(r.text[:500])
except Exception as ex:
    print(f"  Error: {ex}")

print("\n[DONE]")
