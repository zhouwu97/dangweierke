"""Full Erke login test - bypass client-side captcha"""
import truststore, requests, re, base64, random
from urllib.parse import urljoin, urlparse, quote_plus
from pathlib import Path
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

# === WebVPN login ===
print("[0] WebVPN login...")
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
for _ in range(5):
    cur = s.get(nu, timeout=15, allow_redirects=False)
    if cur.status_code in (301, 302, 303, 307, 308):
        nu = urljoin(cur.url, cur.headers.get("Location", ""))
    else:
        break
print(f"  Ticket: {bool(s.cookies.get('wengine_vpn_ticketwebvpn_sylu_edu_cn'))}")

# === Erke login ===
APP_HOST = "77726476706e69737468656265737421e8f00f8f3e3c7d1e7b0c9ce29b5b"
login_paths = [
    f"{VPN}/http/{APP_HOST}/SyluTW/Sys/UserLogin.aspx",
    f"{VPN}/http/{APP_HOST}/SyluTW/Sys/SystemForm/Login.aspx",
]

for path in login_paths:
    print(f"\n[1] Fetching: ...{path[-40:]}")
    erke = s.get(path, timeout=15)
    print(f"  Status: {erke.status_code}, URL ends: ...{erke.url[-50:]}")

    if erke.status_code != 200:
        continue

    # Check if we're on login page or redirected
    if "/login" in urlparse(erke.url).path.lower() and "UserLogin.aspx" not in erke.url:
        print("  >>> Redirected to WebVPN login - Ticket expired")
        continue

    esoup = BeautifulSoup(erke.text, "html.parser")
    
    # Check for login form
    uname = esoup.select_one('input[name="UserName"]')
    if not uname:
        print("  >>> No UserName field - not a login page")
        continue

    print("  Found login form!")

    # Extract all form inputs
    all_inputs = {}
    for inp in esoup.select("form input[name]"):
        name = inp.get("name", "").strip()
        if not name:
            continue
        itype = (inp.get("type") or "text").lower()
        if itype in ("button", "reset", "file"):
            continue
        if itype in ("checkbox", "radio") and not inp.has_attr("checked"):
            continue
        all_inputs[name] = inp.get("value", "")

    print(f"  Form fields: {list(all_inputs.keys())}")

    # Get pubKey
    pubkey = all_inputs.get("pubKey", "")
    if not pubkey:
        pubkey_node = esoup.select_one('input[name="pubKey"]')
        if pubkey_node:
            pubkey = pubkey_node.get("value", "")

    print(f"  pubKey: {'present' if pubkey else 'MISSING'}")

    # RSA encrypt password
    if pubkey:
        key_text = pubkey.strip()
        if "BEGIN PUBLIC KEY" not in key_text:
            key_text = "-----BEGIN PUBLIC KEY-----\n" + key_text + "\n-----END PUBLIC KEY-----"
        try:
            rsa_key = RSA.import_key(key_text)
            cipher = PKCS1_v1_5.new(rsa_key)
            encrypted_pwd = base64.b64encode(cipher.encrypt(PASS.encode("utf-8"))).decode("ascii")
        except Exception as e:
            print(f"  RSA error: {e}")
            continue
    else:
        encrypted_pwd = PASS

    # Build form data
    form_data = dict(all_inputs)
    form_data["UserName"] = USER
    form_data["Password"] = PASS
    form_data["pwd"] = encrypted_pwd
    form_data["pubKey"] = pubkey
    form_data["codeInput"] = "aaaa"  # random captcha - server may ignore

    # Get queryBtn value
    query_btn = esoup.select_one('input[name="queryBtn"]')
    if query_btn:
        form_data["queryBtn"] = query_btn.get("value", "登 录")

    # Ensure required hidden fields
    for h in ("__VIEWSTATE", "__VIEWSTATEGENERATOR", "__EVENTVALIDATION"):
        if h not in form_data:
            node = esoup.select_one(f'input[name="{h}"]')
            if node:
                form_data[h] = node.get("value", "")

    print(f"  Submitting with {len(form_data)} fields...")

    # Build the login URL (same as form action or current page)
    form_action = esoup.select_one("form")
    login_url = path
    if form_action and form_action.get("action"):
        action = form_action.get("action", "").strip()
        if action:
            login_url = urljoin(erke.url, action)

    # GBK encode form data
    parts = []
    for key, value in form_data.items():
        ek = quote_plus(str(key).encode("gb18030"), safe="")
        if isinstance(value, bytes):
            ev = quote_plus(value, safe="")
        else:
            ev = quote_plus(str(value).encode("gb18030"), safe="")
        parts.append(f"{ek}={ev}")
    body = "&".join(parts)

    login_resp = s.post(login_url, data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": erke.url,
            "Origin": VPN,
        },
        timeout=15, allow_redirects=True)

    print(f"  Login response: {login_resp.status_code}")
    print(f"  Final URL: ...{login_resp.url[-80:]}")

    # Check if still on login page
    resp_soup = BeautifulSoup(login_resp.text, "html.parser")
    still_login = bool(resp_soup.select_one('input[name="UserName"]'))

    # Extract error message
    error = None
    for pattern in [r"layer\.alert\(\s*['\"]([^'\"]+)['\"]", r"alert\(\s*['\"]([^'\"]+)['\"]\s*\)"]:
        m = re.search(pattern, login_resp.text, re.IGNORECASE)
        if m:
            error = m.group(1)
            break
    if not error:
        for sel in ("[id*=error]", "[class*=error]", ".validation-summary-errors"):
            node = resp_soup.select_one(sel)
            if node:
                error = node.get_text(" ", strip=True)
                if error:
                    break

    if still_login:
        print(f"  >>> Still on login page. Error: {error or 'none detected'}")
    else:
        print(f"  >>> SUCCESS! Not on login page anymore!")
        # Save the response
        Path("debug/02_login_response.html").write_text(login_resp.text, encoding="utf-8")
        break

    # Also try the alternate path
    continue

print("\n[DONE]")
