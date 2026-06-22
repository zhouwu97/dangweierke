"""Minimal Erke login test - using xynewui's proven approach"""
import truststore, requests, re, base64, random, binascii
from urllib.parse import urljoin, urlencode, quote_plus
from bs4 import BeautifulSoup
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
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

# === WebVPN CAS login (our fixed version) ===
print("[0] WebVPN CAS login...")
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
k = sa.encode(); iv = rs(16).encode(); pt = (rs(64) + PASS).encode()
ci = AES.new(k, AES.MODE_CBC, iv=iv); ct = ci.encrypt(pad(pt, AES.block_size))
ep = base64.b64encode(ct).decode()
lr = s.post(au, params={"service": f"{VPN}/login?cas_login=true"},
    data={"username": USER, "password": ep, "_eventId": "submit",
          "cllt": "userNameLogin", "dllt": "generalLogin", "lt": "", "execution": ex},
    timeout=15, allow_redirects=False)
nu = urljoin(lr.url, lr.headers.get("Location"))
for _ in range(5):
    cur = s.get(nu, timeout=15, allow_redirects=False)
    if cur.status_code in (301, 302, 303, 307, 308):
        nu = urljoin(cur.url, cur.headers.get("Location", ""))
    else:
        break
print(f"  VPN OK: {bool(s.cookies.get('wengine_vpn_ticketwebvpn_sylu_edu_cn'))}")

# === Erke login (xynewui approach) ===
print("[1] Erke login page...")
cipher = AES.new(b"wrdvpnisthebest!", AES.MODE_CFB, b"wrdvpnisthebest!", segment_size=128)
enc = cipher.encrypt(b"xg.sylu.edu.cn")
hh = b"wrdvpnisthebest!".hex() + enc.hex()

login_url = f"{VPN}/http/{hh}/SyluTW/Sys/UserLogin.aspx"
resp = s.get(login_url, timeout=15)
print(f"  Status: {resp.status_code}")

# Force GBK decode
if resp.encoding and resp.encoding.lower() in ("iso-8859-1", "latin-1"):
    resp.encoding = "gbk"
soup = BeautifulSoup(resp.text, "html.parser")

# Extract form fields
def get_val(soup, id_):
    el = soup.find("input", {"id": id_})
    return el.get("value", "") if el else ""

viewstate = get_val(soup, "__VIEWSTATE")
viewstate_gen = get_val(soup, "__VIEWSTATEGENERATOR")
event_valid = get_val(soup, "__EVENTVALIDATION")
pub_key = get_val(soup, "pubKey")

print(f"  VIEWSTATE: {bool(viewstate)}")
print(f"  pubKey: {bool(pub_key)}")

# RSA encrypt (exactly like xynewui)
if "BEGIN PUBLIC KEY" not in pub_key:
    pub_key = f"-----BEGIN PUBLIC KEY-----\n{pub_key}\n-----END PUBLIC KEY-----"
key = RSA.import_key(pub_key)
cipher_rsa = PKCS1_v1_5.new(key)
pwd_enc = base64.b64encode(cipher_rsa.encrypt(PASS.encode())).decode()

# Build form data (exactly like xynewui)
QUERY_BTN = b"\xb5\xc7            \xc2\xbc"  # 登+12spaces+录 in GBK

post_data = {
    "__VIEWSTATE": viewstate,
    "__VIEWSTATEGENERATOR": viewstate_gen,
    "__EVENTVALIDATION": event_valid,
    "UserName": USER,
    "Password": PASS,
    "pwd": pwd_enc,
    "pubKey": pub_key,
    "codeInput": "aaaa",  # captcha - server seems to not check it
}

# GBK encode (exactly like xynewui)
str_data = {k: v for k, v in post_data.items() if not isinstance(v, bytes)}
bytes_data = {k: v for k, v in post_data.items() if isinstance(v, bytes)}
str_body = urlencode(str_data, encoding="gbk") if str_data else ""
bytes_parts = []
for k, v in bytes_data.items():
    key_enc = quote_plus(k.encode("gbk"), safe="")
    val_enc = quote_plus(v, safe="")
    bytes_parts.append(f"{key_enc}={val_enc}")

# Add queryBtn as bytes
key_enc = quote_plus(b"queryBtn", safe="")
val_enc = quote_plus(QUERY_BTN, safe="")
bytes_parts.append(f"{key_enc}={val_enc}")

if str_body and bytes_parts:
    body = str_body + "&" + "&".join(bytes_parts)
elif bytes_parts:
    body = "&".join(bytes_parts)
else:
    body = str_body

print(f"  Body len: {len(body)}")

# POST login
lr = s.post(login_url, data=body,
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    timeout=15, allow_redirects=True)

print(f"\n[2] Login result:")
print(f"  Status: {lr.status_code}")
print(f"  Final URL: {lr.url[-100:]}")

# Check success
final_url = lr.url
if any(kw in final_url for kw in ("main.htm", "Default.aspx", "SystemForm")):
    print("  >>> LOGIN SUCCESS!")
else:
    print("  >>> Still on login page or other")
    # Check for error
    alert = re.search(r"alert\s*\(\s*'([^']+)'\s*\)", lr.text)
    if alert:
        print(f"  Alert: {alert.group(1)}")
    # Check if redirected back to login
    if "UserLogin.aspx" in final_url or "Login.aspx" in final_url:
        soup2 = BeautifulSoup(lr.text, "html.parser")
        err = soup2.find(attrs={"id": lambda x: x and "error" in x.lower() if x else False})
        if err:
            print(f"  Error element: {err.get_text(strip=True)}")
