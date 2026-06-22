"""Fetch all external JS and search for captcha logic"""
import truststore, requests, re, base64, random, sys
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

def rs(n):
    return "".join(random.SystemRandom().choice(AES_CHARS) for _ in range(n))

# WebVPN login
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
k = sa.encode(); iv = rs(16).encode(); pt = (rs(64) + "@Zhoukangwu0").encode()
ci = AES.new(k, AES.MODE_CBC, iv=iv); ct = ci.encrypt(pad(pt, AES.block_size))
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
print(f"  OK, ticket={bool(s.cookies.get('wengine_vpn_ticketwebvpn_sylu_edu_cn'))}")

# Fetch Erke login page
print("[2] Fetching Erke login page...")
erke_url = f"{VPN}/http/77726476706e69737468656265737421e8f00f8f3e3c7d1e7b0c9ce29b5b/SyluTW/Sys/UserLogin.aspx"
erke = s.get(erke_url, timeout=15)
erke_html = erke.text
erke_soup = BeautifulSoup(erke_html, "html.parser")
print(f"  Status: {erke.status_code}")

# Find all script src URLs
print("\n[3] Fetching external scripts...")
scripts = erke_soup.find_all("script")
urls_to_fetch = []
for sc in scripts:
    src = sc.get("src", "")
    if src:
        if src.startswith("/"):
            # VPN path
            url = VPN + src
        elif src.startswith("http"):
            url = src
        else:
            # Relative path
            url = urljoin(erke_url, src)
        urls_to_fetch.append((src, url))

print(f"  Found {len(urls_to_fetch)} external scripts")

for src, url in urls_to_fetch:
    try:
        r = s.get(url, timeout=10)
        ct = r.headers.get("Content-Type", "")
        is_js = "javascript" in ct.lower() or "ecmascript" in ct.lower()
        print(f"\n  [{src[:80]}]")
        print(f"    status={r.status_code}, ct={ct[:50]}, len={len(r.text)}")
        if is_js or r.status_code == 200:
            text = r.text
            # Search for captcha/check/code
            for kw in ["check()", "$(\"#code-box\")", "code-box", "append", ".html(", ".attr(\"src\"",
                         "ValidateCode", "CheckCode", "captcha", "getElementById(\"code", "src="]:
                if kw.lower() in text.lower():
                    idx = text.lower().find(kw.lower())
                    start = max(0, idx - 100)
                    end = min(len(text), idx + 200)
                    snippet = text[start:end].replace("\n", " ").replace("\r", "")
                    print(f"    >>> FOUND '{kw}' at {idx}: ...{snippet}...")
    except Exception as ex:
        print(f"    ERROR: {ex}")

# Also search the HTML for check function
print("\n[4] Searching HTML for check/captcha...")
for kw in ["function check", "check()", "code-box", ".src", ".html("]:
    idx = erke_html.lower().find(kw.lower())
    if idx >= 0:
        start = max(0, idx - 80)
        end = min(len(erke_html), idx + 300)
        snippet = erke_html[start:end].replace("\n", " ").replace("\r", "")
        print(f"  '{kw}' at {idx}: {snippet}...")

# Print all inline script blocks that have content
print("\n[5] All inline script blocks:")
for i, sc in enumerate(erke_soup.find_all("script")):
    if sc.get("src"):
        continue
    txt = sc.get_text()
    if txt.strip():
        print(f"\n  Block {i}: ({len(txt)} chars)")
        print(txt[:2000])

print("\n[DONE]")
