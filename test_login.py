"""Quick test: login WebVPN, access Erke, find captcha"""
import truststore, requests, re, base64
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random

truststore.inject_into_ssl()

s = requests.Session()
s.trust_env = False
s.proxies.clear()
s.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})

VPN_BASE = "https://webvpn.sylu.edu.cn"
AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
USER = "2403060128"
PASS = "@Zhoukangwu0"

def random_str(n):
    return "".join(random.SystemRandom().choice(AES_CHARS) for _ in range(n))

# Step 1: WebVPN login
print("[1] Logging into WebVPN...")
entry = f"{VPN_BASE}/login?cas_login=true"
first = s.get(entry, timeout=15, allow_redirects=False)
loc = first.headers.get("Location", "")
cas_url = urljoin(first.url, loc)
page = s.get(cas_url, timeout=15)
soup = BeautifulSoup(page.text, "html.parser")
form = soup.select_one("#pwdFromId")
salt = form.select_one("#pwdEncryptSalt").get("value", "")
execution = form.select_one("#execution").get("value", "")
action = form.get("action", "").strip()
action_url = urljoin(page.url, action)

key = salt.encode("utf-8")
iv = random_str(16).encode("utf-8")
pt = (random_str(64) + PASS).encode("utf-8")
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
ct = cipher.encrypt(pad(pt, AES.block_size))
epwd = base64.b64encode(ct).decode()

lr = s.post(action_url,
    params={"service": "https://webvpn.sylu.edu.cn/login?cas_login=true"},
    data={"username": USER, "password": epwd, "_eventId": "submit",
          "cllt": "userNameLogin", "dllt": "generalLogin", "lt": "", "execution": execution},
    timeout=15, allow_redirects=False)
print(f"  Login response: {lr.status_code}")

next_url = urljoin(lr.url, lr.headers.get("Location", ""))
for _ in range(12):
    cur = s.get(next_url, timeout=15, allow_redirects=False)
    if cur.status_code in (301, 302, 303, 307, 308):
        next_url = urljoin(cur.url, cur.headers.get("Location", ""))
        continue
    break

ticket = s.cookies.get("wengine_vpn_ticketwebvpn_sylu_edu_cn")
print(f"  Ticket obtained: {bool(ticket)}")

# Step 2: Access Erke login page
print("[2] Accessing Erke login page...")
erke = s.get(f"{VPN_BASE}/http/77726476706e69737468656265737421e8f00f8f3e3c7d1e7b0c9ce29b5b/SyluTW/Sys/UserLogin.aspx", timeout=15)
print(f"  Status: {erke.status_code}")
print(f"  Final URL: {erke.url[:120]}")

esoup = BeautifulSoup(erke.text, "html.parser")
print(f"  Has UserName: {bool(esoup.select_one('input[name=UserName]'))}")
cb = esoup.select_one("#code-box")
print(f"  code-box innerHTML: {repr(cb.decode_contents() if cb else 'NONE')[:200]}")

# Step 3: Check all imgs
imgs = esoup.find_all("img")
print(f"[3] Img tags: {len(imgs)}")
for img in imgs:
    src = img.get("src", "")[:120]
    idd = img.get("id", "")
    print(f"  id={idd} src={src}")

# Step 4: Check for captcha in script blocks
scripts = esoup.find_all("script")
print(f"[4] Script blocks: {len(scripts)}")
for i, script in enumerate(scripts):
    text = script.get_text() if script.string else ""
    if any(kw in text.lower() for kw in ["captcha", "code", "img", "validate", "verify"]):
        print(f"  Script #{i}: {text[:300]}...")
        print("---")

# Step 5: Try common captcha URLs
print("[5] Trying captcha URLs...")
captcha_paths = [
    "/SyluTW/Sys/ValidateCode.aspx",
    "/SyluTW/Sys/CheckCode.aspx",
    "/SyluTW/ValidateCode.aspx",
    "/SyluTW/CheckCode.aspx",
    "/SyluTW/code.aspx",
    "/SyluTW/Sys/code.aspx",
]
for path in captcha_paths:
    try:
        r = s.get(f"{VPN_BASE}/http/77726476706e69737468656265737421e8f00f8f3e3c7d1e7b0c9ce29b5b{path}", timeout=10)
        ct = r.headers.get("Content-Type", "")
        print(f"  {path}: status={r.status_code}, content-type={ct[:60]}, len={len(r.content)}")
        if "image" in ct or r.status_code == 200 and len(r.content) > 100:
            print(f"    >>> LIKELY CAPTCHA!")
    except:
        print(f"  {path}: error")

print("[DONE]")
