"""Detailed login response analysis"""
import truststore, requests, re, base64, random
from urllib.parse import urljoin, urlparse, quote_plus
from bs4 import BeautifulSoup
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

truststore.inject_into_ssl()
s = requests.Session()
s.trust_env = False
s.proxies.clear()
s.headers.update({"User-Agent": "Mozilla/5.0"})
AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
VPN = "https://webvpn.sylu.edu.cn"
U = "2403060128"
P = "@Zhoukangwu0"

def rsn(n):
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
iv = rsn(16).encode()
pt = (rsn(64) + P).encode()
ci = AES.new(k, AES.MODE_CBC, iv=iv)
ct = ci.encrypt(pad(pt, AES.block_size))
ep = base64.b64encode(ct).decode()
lr = s.post(au, params={"service": f"{VPN}/login?cas_login=true"},
    data={"username": U, "password": ep, "_eventId": "submit",
          "cllt": "userNameLogin", "dllt": "generalLogin", "lt": "", "execution": ex},
    timeout=15, allow_redirects=False)
nu = urljoin(lr.url, lr.headers.get("Location"))
for _ in range(5):
    cur = s.get(nu, timeout=15, allow_redirects=False)
    if cur.status_code in (301, 302, 303, 307, 308):
        nu = urljoin(cur.url, cur.headers.get("Location", ""))
    else:
        break

print(f"WebVPN OK: {bool(s.cookies.get('wengine_vpn_ticketwebvpn_sylu_edu_cn'))}")

# Erke login page
APP = "77726476706e69737468656265737421e8f00f8f3e3c7d1e7b0c9ce29b5b"
erke = s.get(f"{VPN}/http/{APP}/SyluTW/Sys/UserLogin.aspx", timeout=15)
es = BeautifulSoup(erke.text, "html.parser")

# Extract ALL form fields
fd = {}
for inp in es.select("form input[name]"):
    n = inp.get("name", "").strip()
    if not n:
        continue
    t = (inp.get("type") or "text").lower()
    if t in ("button", "reset", "file"):
        continue
    if t in ("checkbox", "radio") and not inp.has_attr("checked"):
        continue
    fd[n] = inp.get("value", "")

print(f"Form fields: {len(fd)}")

# RSA encrypt
pk = fd.get("pubKey", "")
kt = pk.strip()
if "BEGIN PUBLIC KEY" not in kt:
    kt = "-----BEGIN PUBLIC KEY-----\n" + kt + "\n-----END PUBLIC KEY-----"
rk = RSA.import_key(kt)
rc = PKCS1_v1_5.new(rk)
epwd = base64.b64encode(rc.encrypt(P.encode())).decode()

fd["UserName"] = U
fd["Password"] = P
fd["pwd"] = epwd
fd["pubKey"] = pk
fd["codeInput"] = "aaaa"
qb = es.select_one('input[name="queryBtn"]')
if qb:
    fd["queryBtn"] = qb.get("value", "")

# Build body
parts = []
for kk, vv in fd.items():
    ek = quote_plus(str(kk).encode("gb18030"), safe="")
    ev = quote_plus(str(vv).encode("gb18030"), safe="")
    parts.append(f"{ek}={ev}")
body = "&".join(parts)

# Submit
fa = es.select_one("form")
lu = erke.url
if fa and fa.get("action"):
    a = fa.get("action", "").strip()
    if a:
        lu = urljoin(erke.url, a)

lr = s.post(lu, data=body,
    headers={"Content-Type": "application/x-www-form-urlencoded",
             "Referer": erke.url, "Origin": VPN},
    timeout=15, allow_redirects=True)

print(f"Submit status: {lr.status_code}")
print(f"URL: {lr.url[-120:]}")

rs = BeautifulSoup(lr.text, "html.parser")
still = bool(rs.select_one('input[name="UserName"]'))
print(f"Still login: {still}")

# Check JS alerts in response
for pat in [
    r"""layer\.alert\(\s*['"]([^'"]+)['"]""",
    r"""alert\(\s*['"]([^'"]+)['"]\s*\)""",
    r"""layer\.tips\(['"]([^'"]+)['"]""",
]:
    m = re.search(pat, lr.text, re.IGNORECASE)
    if m:
        print(f"Alert/Tips: {m.group(1)}")

# Check redirect
redirects = re.findall(r"""location\.href\s*=\s*['"]([^'"]+)['"]""", lr.text)
if redirects:
    print(f"JS redirects: {redirects}")

# Check for __doPostBack target
evt = rs.select_one('#__EVENTTARGET')
if evt:
    print(f"PostBack target: {evt.get('value','')}")

# Save response for inspection
from pathlib import Path
Path("debug/login_response.html").write_text(lr.text, encoding="utf-8")
print(f"Saved to debug/login_response.html ({len(lr.text)} bytes)")

# Dump key parts
cb = rs.select_one("#code-box")
print(f"code-box text: {repr(cb.get_text() if cb else 'NONE')}")

# Check for specific error patterns
html_lower = lr.text.lower()
for kw in ["验证码错误", "密码错误", "用户名", "账号", "captcha", "code"]:
    if kw in html_lower:
        idx = html_lower.index(kw)
        print(f"Found '{kw}' at {idx}: {lr.text[max(0,idx-50):idx+100]}")
