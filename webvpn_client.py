import base64
import json
import random
import re
import string
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

import requests
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


VPN_BASE = "https://webvpn.sylu.edu.cn"
AES_KEY = b"wrdvpnisthebest!"
AES_IV = b"wrdvpnisthebest!"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0"
)

class WebVpnError(RuntimeError):
    pass

class WebVpnAuthenticationFailed(WebVpnError):
    pass

class WebVpnPageChanged(WebVpnError):
    pass


class WebVpnClient:
    def __init__(
        self,
        *,
        vpn_ticket: str | None = None,
        timeout: float = 15.0,
        debug_dir: Path | None = None,
    ) -> None:
        self.timeout = timeout
        self.debug_dir = debug_dir

        self.session = requests.Session()
        self.session.trust_env = False
        self.session.proxies.clear()

        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
            }
        )

        if vpn_ticket:
            self.session.cookies.set(
                "wengine_vpn_ticketwebvpn_sylu_edu_cn",
                vpn_ticket,
                domain="webvpn.sylu.edu.cn",
                path="/",
            )

        if debug_dir:
            debug_dir.mkdir(parents=True, exist_ok=True)

    def url_for(self, host: str, path: str, scheme: str = "http") -> str:
        """
        生成通过 WebVPN 代理访问目标 host 和 path 的 URL。
        """
        if not path.startswith("/"):
            path = "/" + path

        cipher = AES.new(
            AES_KEY,
            AES.MODE_CFB,
            AES_IV,
            segment_size=128,
        )
        encrypted = cipher.encrypt(host.encode("utf-8"))
        encrypted_host = AES_KEY.hex() + encrypted.hex()

        return f"{VPN_BASE}/{scheme}/{encrypted_host}{path}"

    def _save_debug(
        self,
        name: str,
        response: requests.Response,
    ) -> None:
        if not self.debug_dir:
            return

        safe_name = re.sub(r"[^0-9A-Za-z_.-]", "_", name)
        path = self.debug_dir / safe_name

        content_type = response.headers.get("Content-Type", "").lower()

        if "html" in content_type or not content_type:
            path.with_suffix(".html").write_text(
                self.response_text(response),
                encoding="utf-8",
                errors="replace",
            )

        metadata = {
            "status_code": response.status_code,
            "url": response.url,
            "content_type": content_type,
            "location": response.headers.get("Location"),
        }
        path.with_suffix(".json").write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    @staticmethod
    def response_text(response: requests.Response) -> str:
        content_type = response.headers.get("Content-Type", "")
        charset_match = re.search(r"charset\s*=\s*([-\w]+)", content_type, re.IGNORECASE)
        encoding = charset_match.group(1) if charset_match else (response.encoding or "")

        if not encoding or encoding.lower() in {"iso-8859-1", "latin-1"}:
            for candidate in ("gb18030", "utf-8"):
                try:
                    return response.content.decode(candidate)
                except UnicodeDecodeError:
                    continue
            return response.content.decode("utf-8", errors="replace")

        try:
            return response.content.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            return response.content.decode("gb18030", errors="replace")

    _AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"

    @classmethod
    def _vpn_random_string(cls, length: int) -> str:
        return "".join(random.SystemRandom().choice(cls._AES_CHARS) for _ in range(length))

    @classmethod
    def _vpn_encrypt_password(
        cls,
        password: str,
        salt: str,
        *,
        test_iv: bytes | None = None,
        test_random_prefix: str | None = None,
    ) -> str:
        key = salt.strip().encode("utf-8")
        if len(key) not in {16, 24, 32}:
            raise WebVpnPageChanged(f"pwdEncryptSalt 长度异常：{len(key)}")

        iv = test_iv if test_iv else cls._vpn_random_string(16).encode("utf-8")
        prefix = test_random_prefix if test_random_prefix is not None else cls._vpn_random_string(64)
        plaintext = (prefix + password).encode("utf-8")

        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        encrypted = cipher.encrypt(pad(plaintext, AES.block_size))
        return base64.b64encode(encrypted).decode("ascii")

    @staticmethod
    def _form_value(form: BeautifulSoup, name_or_id: str) -> str:
        node = form.select_one(f'[name="{name_or_id}"], #{name_or_id}')
        return str(node.get("value", "")) if node else ""

    def login_cas(self, username: str, password: str) -> bool:
        """
        通过 CAS 登录 WebVPN。
        如果当前会话已有有效 Cookie，会自动验证或跳过。
        成功返回 True。
        """
        entry = f"{VPN_BASE}/login?cas_login=true"
        first = self.session.get(entry, timeout=self.timeout, allow_redirects=False)
        self._save_debug("00_vpn_entry", first)

        if first.status_code in {301, 302, 303, 307, 308}:
            location = first.headers.get("Location", "")
            if location == "/":
                return True
            if not location:
                raise WebVpnAuthenticationFailed("WebVPN 登录入口没有返回 Location")
            cas_url = urljoin(first.url, location)
        elif first.status_code == 200:
            cas_url = first.url
        else:
            raise WebVpnAuthenticationFailed(f"WebVPN 登录入口 HTTP {first.status_code}")

        page = self.session.get(cas_url, timeout=self.timeout, allow_redirects=True)
        self._save_debug("00_vpn_cas_page", page)
        html = self.response_text(page)
        soup = BeautifulSoup(html, "html.parser")
        form = soup.select_one("#pwdFromId")

        if form is None:
            if self.session.cookies.get("wengine_vpn_ticketwebvpn_sylu_edu_cn"):
                return True
            raise WebVpnPageChanged("WebVPN CAS 页面缺少 #pwdFromId")

        salt = self._form_value(form, "pwdEncryptSalt")
        execution = self._form_value(form, "execution")
        if not salt or not execution:
            raise WebVpnPageChanged("WebVPN CAS 页面缺少 pwdEncryptSalt 或 execution")

        action = str(form.get("action", "")).strip()
        action_url = urljoin(page.url, action)
        encrypted_password = self._vpn_encrypt_password(password, salt)

        login_response = self.session.post(
            action_url,
            params={"service": f"{VPN_BASE}/login?cas_login=true"},
            data={
                "username": username,
                "password": encrypted_password,
                "_eventId": "submit",
                "cllt": "userNameLogin",
                "dllt": "generalLogin",
                "lt": "",
                "execution": execution,
            },
            timeout=self.timeout,
            allow_redirects=False,
        )
        self._save_debug("00_vpn_login_response", login_response)

        if login_response.status_code not in {301, 302, 303, 307, 308}:
            error_html = self.response_text(login_response)
            error_soup = BeautifulSoup(error_html, "html.parser")
            node = error_soup.select_one("#showErrorTip")
            message = node.get_text(" ", strip=True) if node else "WebVPN 用户名或密码验证失败"
            raise WebVpnAuthenticationFailed(message)

        next_url = urljoin(login_response.url, login_response.headers.get("Location", ""))
        for _ in range(12):
            current = self.session.get(next_url, timeout=self.timeout, allow_redirects=False)
            self._save_debug("00_vpn_redirect", current)
            if current.status_code in {301, 302, 303, 307, 308}:
                next_url = urljoin(current.url, current.headers.get("Location", ""))
            else:
                break

        if not self.session.cookies.get("wengine_vpn_ticketwebvpn_sylu_edu_cn"):
            raise WebVpnAuthenticationFailed("登录流程完成，但未获得 WebVPN Ticket")

        return True
