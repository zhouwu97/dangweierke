from __future__ import annotations

"""
沈阳理工大学二课系统：本地登录与数据抓取测试

功能：
1. 使用浏览器中已登录 WebVPN 后的 VPN Ticket；
2. 访问二课登录页；
3. 直接读取 DOM 中 #code-box 的四位验证码文本；
4. 提取 ASP.NET 隐藏字段与 RSA 公钥；
5. 使用 RSA PKCS#1 v1.5 加密密码并提交登录；
6. 通过受保护的成绩页面验证登录是否真正成功；
7. 获取五项分类分数、总分；
8. 获取活动明细并模拟 ASP.NET 翻页；
9. 保存为 JSON。

安全：
- 不输出密码、Ticket 或学校 Session Cookie；
- 默认通过 getpass 读取密码，不进入 PowerShell 历史；
- 只供本人有权访问的账号测试。
"""

import argparse
import base64
import binascii
import csv
import getpass
import json
import os
import random
import re
import string
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote_plus, urlencode, urljoin, urlparse

# 强制使用 Windows 系统证书库。
# 不再静默忽略 truststore 导入失败，否则会回退到 certifi 并再次触发学校证书链错误。
try:
    import truststore
except ImportError as exc:
    raise SystemExit(
        "缺少 truststore，请先执行："
        r".\.venv\Scripts\python.exe -m pip install truststore"
    ) from exc

truststore.inject_into_ssl()

import requests
from bs4 import BeautifulSoup, Tag
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad


VPN_BASE = "https://webvpn.sylu.edu.cn"
TARGET_DOMAIN = "xg.sylu.edu.cn"
AES_KEY = b"wrdvpnisthebest!"
AES_IV = b"wrdvpnisthebest!"

LOGIN_PATHS = (
    "/SyluTW/Sys/UserLogin.aspx",
    "/SyluTW/Sys/SystemForm/Login.aspx",
)

SUMMARY_PATH = (
    "/SyluTW/Sys/SystemForm/FinishExam/"
    "StuFinishStudentScore.aspx"
)
ACTIVITY_PATH = (
    "/SyluTW/Sys/SystemForm/StuAction/"
    "StuActionSearch.aspx"
)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0"
)

# 仅在当前页面没有下发 pubKey 时备用。
# 优先使用页面中的 input[name=pubKey]，避免服务端换密钥后失效。
FALLBACK_PUBLIC_KEY = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3hzrH91c0OKgtaSB7GWGfDuUJ"
    "sMrtiYThDXtJdrCr7exKt2fmIZngoFk71Dv/BPVQCHSuohNNvEV9VVDFSBhsP9xK"
    "EDAM4/2Lv+wlzN9CuZtLpV3Elo8VacjwMHcjTRmTchRBmijQzZRFrA2LM+qsH3U5"
    "tRM1uJFbfRMkBq24AwIDAQAB"
)

CATEGORY_NAMES = {
    "A": "思想成长",
    "B": "实践实习",
    "C": "创新创业",
    "D": "志愿公益",
    "E": "文体活动",
}


class ErkeError(RuntimeError):
    """可展示给用户的二课错误。"""


class LoginPageChanged(ErkeError):
    """登录页面结构发生变化。"""


class AuthenticationFailed(ErkeError):
    """账号、密码或登录状态错误。"""


@dataclass
class Activity:
    name: str
    organizer: str
    date: str
    category: str
    role: str
    participant_count: int | None
    score: float | None
    raw_columns: list[str]


@dataclass
class CrawlResult:
    student_id: str
    summary: dict[str, float]
    activities: list[Activity]
    pages_fetched: int
    fetched_at: str


def clean_text(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def safe_float(value: str) -> float | None:
    normalized = clean_text(value).replace(",", "")
    if not normalized:
        return None
    match = re.search(r"-?\d+(?:\.\d+)?", normalized)
    return float(match.group(0)) if match else None


def safe_int(value: str) -> int | None:
    normalized = clean_text(value).replace(",", "")
    if not normalized:
        return None
    match = re.search(r"-?\d+", normalized)
    return int(match.group(0)) if match else None


class ErkeClient:
    def __init__(
        self,
        *,
        mode: str,
        vpn_ticket: str | None = None,
        direct_base: str = "",
        timeout: float = 15.0,
        debug_dir: Path | None = None,
        session: requests.Session | None = None,
        url_builder = None,
    ) -> None:
        if mode not in {"webvpn", "direct"}:
            raise ValueError("mode 必须是 webvpn 或 direct")
        self.mode = mode
        self.vpn_ticket = vpn_ticket
        self.direct_base = direct_base.rstrip("/")
        self.timeout = timeout
        self.debug_dir = debug_dir
        self.login_path: str | None = None
        self.url_builder = url_builder

        self.session = session if session else requests.Session()

        if not session:
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

        self._encrypted_host = self._encrypt_domain(TARGET_DOMAIN)

        if debug_dir:
            debug_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _encrypt_domain(domain: str) -> str:
        cipher = AES.new(
            AES_KEY,
            AES.MODE_CFB,
            AES_IV,
            segment_size=128,
        )
        encrypted = cipher.encrypt(domain.encode("utf-8"))
        return AES_KEY.hex() + encrypted.hex()

    def url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path

        if self.mode == "direct":
            return self.direct_base + path

        if self.url_builder:
            return self.url_builder(TARGET_DOMAIN, path)

        return (
            f"{VPN_BASE}/http/"
            f"{self._encrypted_host}{path}"
        )

    def _save_debug(
        self,
        name: str,
        response: requests.Response,
    ) -> None:
        if not self.debug_dir:
            return

        safe_name = re.sub(r"[^0-9A-Za-z_.-]", "_", name)
        path = self.debug_dir / safe_name

        content_type = response.headers.get(
            "Content-Type",
            "",
        ).lower()

        if "html" in content_type or not content_type:
            path.with_suffix(".html").write_text(
                self._response_text(response),
                encoding="utf-8",
            )

        metadata = {
            "status_code": response.status_code,
            "url": response.url,
            "content_type": content_type,
            "location": response.headers.get("Location"),
            # 故意不保存 Set-Cookie。
        }
        path.with_suffix(".json").write_text(
            json.dumps(
                metadata,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _response_text(
        response: requests.Response,
    ) -> str:
        content_type = response.headers.get(
            "Content-Type",
            "",
        )

        charset_match = re.search(
            r"charset\s*=\s*([-\w]+)",
            content_type,
            re.IGNORECASE,
        )
        if charset_match:
            encoding = charset_match.group(1)
        else:
            encoding = response.encoding or ""

        if not encoding or encoding.lower() in {
            "iso-8859-1",
            "latin-1",
        }:
            # 二课 ASP.NET 页面通常为 GBK/GB2312。
            for candidate in ("gb18030", "utf-8"):
                try:
                    return response.content.decode(candidate)
                except UnicodeDecodeError:
                    continue
            return response.content.decode(
                "utf-8",
                errors="replace",
            )

        try:
            return response.content.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            return response.content.decode(
                "gb18030",
                errors="replace",
            )

    def _get(
        self,
        path: str,
        *,
        referer: str | None = None,
        allow_redirects: bool = True,
    ) -> requests.Response:
        headers: dict[str, str] = {}
        if referer:
            headers["Referer"] = referer

        response = self.session.get(
            self.url(path),
            headers=headers,
            timeout=self.timeout,
            allow_redirects=allow_redirects,
        )
        return response

    @staticmethod
    def _all_form_inputs(
        soup: BeautifulSoup,
    ) -> dict[str, str]:
        result: dict[str, str] = {}
        for node in soup.select("form input[name]"):
            name = str(node.get("name", "")).strip()
            if not name:
                continue

            input_type = str(
                node.get("type", "text")
            ).lower()

            if input_type in {
                "button",
                "reset",
                "file",
            }:
                continue

            if input_type in {"checkbox", "radio"}:
                if not node.has_attr("checked"):
                    continue

            result[name] = str(node.get("value", ""))
        return result

    @staticmethod
    def _input_value(
        soup: BeautifulSoup,
        name_or_id: str,
    ) -> str:
        selector = (
            f'input[name="{name_or_id}"],'
            f'input[id="{name_or_id}"]'
        )
        node = soup.select_one(selector)
        if not node:
            return ""
        return str(node.get("value", ""))

    @staticmethod
    def _captcha_from_dom(
        soup: BeautifulSoup,
    ) -> str:
        selectors = (
            "#code-box",
            ".code-img",
            "[id*=code-box]",
        )

        for selector in selectors:
            node = soup.select_one(selector)
            if not node:
                continue

            code = re.sub(
                r"[^0-9A-Za-z]",
                "",
                node.get_text("", strip=True),
            )
            if re.fullmatch(
                r"[0-9A-Za-z]{4}",
                code,
            ):
                return code
            
            # 由于 python requests 不会执行 JS，#code-box 可能为空。
            # 而 JS 生成的验证码服务端也无法校验，所以可以直接发送任意 4 位字符。
            return "aaaa"

        # 如果连验证码的 DOM 都找不到，说明不是期望的页面结构。
        raise LoginPageChanged(
            "登录页未找到验证码容器 #code-box"
        )

    @staticmethod
    def _rsa_encrypt(
        password: str,
        public_key: str,
    ) -> str:
        key_text = clean_text(public_key)

        if "BEGIN PUBLIC KEY" not in key_text:
            key_text = (
                "-----BEGIN PUBLIC KEY-----\n"
                f"{key_text}\n"
                "-----END PUBLIC KEY-----"
            )

        key = RSA.import_key(key_text)
        cipher = PKCS1_v1_5.new(key)
        encrypted = cipher.encrypt(
            password.encode("utf-8")
        )
        return base64.b64encode(
            encrypted
        ).decode("ascii")

    @staticmethod
    def _gbk_form_body(
        data: dict[str, str | bytes],
    ) -> str:
        parts: list[str] = []

        for key, value in data.items():
            encoded_key = quote_plus(
                str(key).encode("gb18030"),
                safe="",
            )
            if isinstance(value, bytes):
                encoded_value = quote_plus(
                    value,
                    safe="",
                )
            else:
                encoded_value = quote_plus(
                    str(value).encode("gb18030"),
                    safe="",
                )
            parts.append(
                f"{encoded_key}={encoded_value}"
            )

        return "&".join(parts)

    @staticmethod
    def _is_login_page(
        response: requests.Response,
        html: str,
    ) -> bool:
        path = urlparse(response.url).path.lower()
        if path.endswith(
            ("/userlogin.aspx", "/login.aspx")
        ):
            return True

        soup = BeautifulSoup(html, "html.parser")
        return bool(
            soup.select_one("#code-box")
            and soup.select_one(
                'input[name="UserName"]'
            )
        )

    @staticmethod
    def _extract_error_message(
        html: str,
    ) -> str | None:
        patterns = (
            r"""layer\.alert\(\s*['"]([^'"]+)['"]""",
            r"""alert\(\s*['"]([^'"]+)['"]\s*\)""",
        )
        for pattern in patterns:
            match = re.search(
                pattern,
                html,
                re.IGNORECASE,
            )
            if match:
                return clean_text(match.group(1))

        soup = BeautifulSoup(html, "html.parser")
        for selector in (
            "[id*=error]",
            "[class*=error]",
            ".validation-summary-errors",
        ):
            node = soup.select_one(selector)
            if node:
                text = clean_text(
                    node.get_text(" ", strip=True)
                )
                if text:
                    return text

        return None


    @staticmethod
    def _random_ascii(length: int) -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(
            random.SystemRandom().choice(alphabet)
            for _ in range(length)
        )

    # 对齐 CAS 页面 encrypt.js 的 $aes_chars（不含易混淆字符）。
    _AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"

    @classmethod
    def _vpn_random_string(cls, length: int) -> str:
        alphabet = cls._AES_CHARS
        return "".join(
            random.SystemRandom().choice(alphabet)
            for _ in range(length)
        )

    @classmethod
    def _vpn_encrypt_password(
        cls,
        password: str,
        salt: str,
        *,
        test_iv: bytes | None = None,
        test_random_prefix: str | None = None,
    ) -> str:
        """
        对齐 CAS 页面 encrypt.js 的 encryptPassword：
        随机 64 + 密码，AES-CBC/PKCS7，
        key = pwdEncryptSalt，随机 16 字符 IV，
        输出 Base64(密文)，**不**拼接 IV。
        CryptoJS.AES.encrypt().toString() 在提供 WordArray
        key/iv 时仅返回 ciphertext 的 Base64，不包含 IV。
        """
        key = salt.strip().encode("utf-8")
        if len(key) not in {16, 24, 32}:
            raise LoginPageChanged(
                f"pwdEncryptSalt 长度异常：{len(key)}"
            )

        iv = test_iv if test_iv else cls._vpn_random_string(16).encode("utf-8")
        prefix = test_random_prefix if test_random_prefix is not None else cls._vpn_random_string(64)
        plaintext = (prefix + password).encode("utf-8")

        cipher = AES.new(
            key,
            AES.MODE_CBC,
            iv=iv,
        )
        encrypted = cipher.encrypt(
            pad(plaintext, AES.block_size)
        )
        # encrypt.js: CryptoJS.AES.encrypt().toString() 只输出
        # 密文的 Base64，**不**拼接 IV。
        return base64.b64encode(encrypted).decode("ascii")

    @staticmethod
    def _form_value(
        form: Tag,
        name_or_id: str,
    ) -> str:
        node = form.select_one(
            f'[name="{name_or_id}"],'
            f'#{name_or_id}'
        )
        return str(node.get("value", "")) if node else ""

    def _login_vpn_direct(
        self,
        username: str,
        password: str,
    ) -> bool:
        login_url = f"{VPN_BASE}/login"
        try:
            self.session.get(login_url, timeout=self.timeout)
            post_data = {
                "username": username,
                "password": password,
                "remember_cookie": "on",
            }
            self.session.post(
                login_url,
                data=post_data,
                allow_redirects=False,
                timeout=self.timeout,
            )
            return False # School disabled Direct VPN login; cookie is dummy.
        except Exception as e:
            print(f"  [VPN] 直接登录异常: {e}")
            return False

    def _login_vpn_cas(
        self,
        username: str,
        password: str,
    ) -> bool:
        entry = f"{VPN_BASE}/login?cas_login=true"
        first = self.session.get(
            entry,
            timeout=self.timeout,
            allow_redirects=False,
        )
        self._save_debug(
            "00_vpn_entry",
            first,
        )

        if first.status_code in {301, 302, 303, 307, 308}:
            location = first.headers.get("Location", "")
            if location == "/":
                return
            if not location:
                raise AuthenticationFailed(
                    "WebVPN 登录入口没有返回 Location"
                )
            cas_url = urljoin(first.url, location)
        elif first.status_code == 200:
            # 某些版本直接返回认证页面。
            cas_url = first.url
        else:
            raise AuthenticationFailed(
                f"WebVPN 登录入口 HTTP {first.status_code}"
            )

        page = self.session.get(
            cas_url,
            timeout=self.timeout,
            allow_redirects=True,
        )
        self._save_debug(
            "00_vpn_cas_page",
            page,
        )
        html = self._response_text(page)
        soup = BeautifulSoup(html, "html.parser")
        form = soup.select_one("#pwdFromId")
        if form is None:
            if self.session.cookies.get(
                "wengine_vpn_ticketwebvpn_sylu_edu_cn"
            ):
                return
            raise LoginPageChanged(
                "WebVPN CAS 页面缺少 #pwdFromId"
            )

        salt = self._form_value(
            form,
            "pwdEncryptSalt",
        )
        execution = self._form_value(
            form,
            "execution",
        )
        if not salt or not execution:
            raise LoginPageChanged(
                "WebVPN CAS 页面缺少 "
                "pwdEncryptSalt 或 execution"
            )

        # 按参考实现检查滑块验证码。
        parsed = urlparse(page.url)
        login_index = parsed.path.rfind("/login")
        if login_index < 0:
            raise LoginPageChanged(
                f"无法从 CAS 地址推导 contextPath：{page.url}"
            )
        context_path = (
            f"{parsed.scheme}://{parsed.netloc}"
            f"{parsed.path[:login_index]}"
        )

        captcha_check = self.session.get(
            f"{context_path}/checkNeedCaptcha.htl",
            params={
                "username": username,
                "_": int(time.time() * 1000),
            },
            timeout=self.timeout,
        )
        need_captcha = False
        if captcha_check.ok:
            try:
                need_captcha = bool(
                    captcha_check.json().get("isNeed")
                )
            except (ValueError, AttributeError):
                pass

        if need_captcha:
            slider = self.session.get(
                f"{context_path}/common/"
                "openSliderCaptcha.htl",
                timeout=self.timeout,
            )
            try:
                slider_data = slider.json()
                if self.debug_dir:
                    for key, filename in (
                        ("bigImage", "vpn_slider_background.png"),
                        ("smallImage", "vpn_slider_piece.png"),
                    ):
                        value = slider_data.get(key, "")
                        if value:
                            (self.debug_dir / filename).write_bytes(
                                base64.b64decode(value)
                            )
            except Exception:
                pass
            raise AuthenticationFailed(
                "WebVPN 当前要求滑块验证码。"
                "图片已保存到 debug 目录；"
                "本测试版暂不自动提交滑块。"
            )

        action = str(form.get("action", "")).strip()
        if not action:
            raise LoginPageChanged(
                "WebVPN CAS 登录表单缺少 action"
            )
        action_url = urljoin(page.url, action)

        encrypted_password = self._vpn_encrypt_password(
            password,
            salt,
        )
        login_response = self.session.post(
            action_url,
            params={
                "service": (
                    "https://webvpn.sylu.edu.cn/"
                    "login?cas_login=true"
                )
            },
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
        self._save_debug(
            "00_vpn_login_response",
            login_response,
        )

        if login_response.status_code not in {
            301, 302, 303, 307, 308
        }:
            error_html = self._response_text(
                login_response
            )
            error_soup = BeautifulSoup(
                error_html,
                "html.parser",
            )
            node = error_soup.select_one(
                "#showErrorTip"
            )
            message = (
                clean_text(
                    node.get_text(" ", strip=True)
                )
                if node
                else "WebVPN 用户名或密码验证失败"
            )
            raise AuthenticationFailed(message)

        next_url = urljoin(
            login_response.url,
            login_response.headers.get(
                "Location",
                "",
            ),
        )
        if not next_url:
            raise AuthenticationFailed(
                "WebVPN 登录成功跳转地址为空"
            )

        # 手动跟随跳转，以便识别二次认证页面。
        for _ in range(12):
            current = self.session.get(
                next_url,
                timeout=self.timeout,
                allow_redirects=False,
            )
            self._save_debug(
                "00_vpn_redirect",
                current,
            )

            if current.status_code in {
                301, 302, 303, 307, 308
            }:
                location = current.headers.get(
                    "Location",
                    "",
                )
                if not location:
                    break
                candidate = urljoin(
                    current.url,
                    location,
                )
                if (
                    urlparse(candidate).path
                    == "/login"
                    and "second_login=true"
                    in candidate
                ):
                    code = input(
                        "WebVPN 要求六位二次验证码："
                    ).strip()
                    if not re.fullmatch(
                        r"\d{6}",
                        code,
                    ):
                        raise AuthenticationFailed(
                            "二次验证码必须是六位数字"
                        )
                    totp = self.session.post(
                        f"{VPN_BASE}/do-second-login",
                        data={
                            "username": "",
                            "code": code,
                        },
                        timeout=self.timeout,
                    )
                    try:
                        payload = totp.json()
                    except ValueError as exc:
                        raise AuthenticationFailed(
                            "WebVPN 二次认证返回格式异常"
                        ) from exc
                    if not payload.get("success"):
                        raise AuthenticationFailed(
                            str(
                                payload.get(
                                    "message",
                                    "二次认证失败",
                                )
                            )
                        )
                    final_url = payload.get("url")
                    if final_url:
                        self.session.get(
                            urljoin(
                                VPN_BASE,
                                str(final_url),
                            ),
                            timeout=self.timeout,
                        )
                    break

                next_url = candidate
                continue

            body = self._response_text(current)
            marker = "var errorMessage = '"
            if marker in body:
                message = body.split(
                    marker,
                    1,
                )[1].split("'", 1)[0]
                raise AuthenticationFailed(message)
            break

        return bool(self.session.cookies.get("wengine_vpn_ticketwebvpn_sylu_edu_cn"))

    def login_webvpn(
        self,
        username: str,
        password: str,
    ) -> None:
        if self.mode != "webvpn":
            return
            
        print("  [VPN] 尝试 Direct 方式登录...")
        if self._login_vpn_direct(username, password):
            return
            
        print("  [VPN] Direct 失败，尝试 CAS 方式登录...")
        try:
            if self._login_vpn_cas(username, password):
                return
        except Exception as e:
            print(f"  [VPN] CAS 登录异常: {e}")
            
        raise AuthenticationFailed("所有 WebVPN 登录策略均失败，请检查账号密码")

    def fetch_login_page(
        self,
    ) -> tuple[str, requests.Response, BeautifulSoup]:
        errors: list[str] = []

        for path in LOGIN_PATHS:
            response = self._get(
                path,
                allow_redirects=True,
            )
            self._save_debug(
                "01_login_page",
                response,
            )

            if response.status_code != 200:
                errors.append(
                    f"{path}: HTTP {response.status_code}"
                )
                continue

            html = self._response_text(response)
            soup = BeautifulSoup(
                html,
                "html.parser",
            )

            if (
                soup.select_one(
                    'input[name="UserName"]'
                )
                and soup.select_one("#code-box")
            ):
                self.login_path = path
                return html, response, soup

            # Ticket 失效时常被送回 WebVPN 登录页。
            if "/login" in urlparse(
                response.url
            ).path.lower():
                errors.append(
                    f"{path}: WebVPN Ticket 已失效"
                )
            else:
                errors.append(
                    f"{path}: 页面不是二课登录页"
                )

        raise AuthenticationFailed(
            "；".join(errors)
        )

    def login(
        self,
        username: str,
        password: str,
    ) -> None:
        html, page_response, soup = (
            self.fetch_login_page()
        )

        captcha = self._captcha_from_dom(soup)
        public_key = (
            self._input_value(soup, "pubKey")
            or FALLBACK_PUBLIC_KEY
        )

        if not public_key:
            raise LoginPageChanged(
                "登录页未找到 RSA 公钥 pubKey"
            )

        try:
            encrypted_password = self._rsa_encrypt(
                password,
                public_key,
            )
        except Exception as exc:
            raise LoginPageChanged(
                f"RSA 密码加密失败: {exc}"
            ) from exc

        form = self._all_form_inputs(soup)

        # 严格动态读取 queryBtn，避免硬编码空格数量导致静默失败
        query_button = self._input_value(soup, "queryBtn")

        form.update(
            {
                "UserName": username,
                "Password": password,
                "pwd": encrypted_password,
                "pubKey": public_key,
                "codeInput": captcha,
            }
        )
        if query_button:
            form["queryBtn"] = query_button

        # 有些页面的 input 仅有 id、没有 name。
        for hidden_name in (
            "__VIEWSTATE",
            "__VIEWSTATEGENERATOR",
            "__EVENTVALIDATION",
            "__VIEWSTATEENCRYPTED",
        ):
            value = self._input_value(
                soup,
                hidden_name,
            )
            if value or hidden_name in {
                "__VIEWSTATE",
                "__VIEWSTATEGENERATOR",
                "__EVENTVALIDATION",
            }:
                form[hidden_name] = value

        if not form.get("__VIEWSTATE"):
            raise LoginPageChanged(
                "登录页缺少 __VIEWSTATE"
            )

        assert self.login_path is not None
        login_url = self.url(self.login_path)

        response = self.session.post(
            login_url,
            data=self._gbk_form_body(form),
            headers={
                "Content-Type": (
                    "application/"
                    "x-www-form-urlencoded"
                ),
                "Referer": page_response.url,
                # 优先不发送 Origin 或严格使用对应的 WebVPN Origin。为了避免跨域被拒，此处直接移除。
            },
            timeout=self.timeout,
            allow_redirects=True,
        )
        self._save_debug(
            "02_login_response",
            response,
        )

        response_html = self._response_text(
            response
        )
        message = self._extract_error_message(
            response_html
        )

        # 不凭 URL 或 Set-Cookie 猜成功；
        # 必须再访问受保护页面并验证 CountA/SunCount。
        try:
            self.fetch_summary()
        except AuthenticationFailed as exc:
            detail = message or str(exc)
            raise AuthenticationFailed(
                f"二课登录失败：{detail}"
            ) from exc

    def _protected_soup(
        self,
        path: str,
        debug_name: str,
    ) -> BeautifulSoup:
        response = self._get(
            path,
            allow_redirects=True,
        )
        self._save_debug(debug_name, response)

        if response.status_code != 200:
            raise ErkeError(
                f"受保护页面 HTTP "
                f"{response.status_code}"
            )

        html = self._response_text(response)
        if self._is_login_page(response, html):
            raise AuthenticationFailed(
                "二课 Session 无效，仍停留在登录页"
            )

        return BeautifulSoup(
            html,
            "html.parser",
        )

    def fetch_summary(
        self,
    ) -> dict[str, float]:
        soup = self._protected_soup(
            SUMMARY_PATH,
            "03_summary",
        )

        summary: dict[str, float] = {}

        for key, name in CATEGORY_NAMES.items():
            node = soup.select_one(f"#Count{key}")
            if not node:
                raise AuthenticationFailed(
                    "成绩页未找到 CountA～CountE，"
                    "可能没有登录成功或页面已改版"
                )
            summary[name] = (
                safe_float(
                    node.get_text(" ", strip=True)
                )
                or 0.0
            )

        total_node = soup.select_one("#SunCount")
        if not total_node:
            raise LoginPageChanged(
                "成绩页缺少 #SunCount"
            )

        summary["总分"] = (
            safe_float(
                total_node.get_text(
                    " ",
                    strip=True,
                )
            )
            or 0.0
        )
        return summary

    @staticmethod
    def _find_activity_table(
        soup: BeautifulSoup,
    ) -> Tag:
        best_table: Tag | None = None
        best_score = -1

        for table in soup.find_all("table"):
            rows = table.find_all("tr")
            score = 0

            for row in rows:
                cells = row.find_all(["th", "td"])
                if len(cells) >= 8:
                    score += 1

            header = clean_text(
                table.get_text(" ", strip=True)
            )
            for keyword in (
                "活动名称",
                "申请单位",
                "活动时间",
                "参与人数",
                "获得分数",
            ):
                if keyword in header:
                    score += 5

            if score > best_score:
                best_table = table
                best_score = score

        if best_table is None or best_score <= 0:
            raise LoginPageChanged(
                "活动页面中未找到数据表格"
            )

        return best_table

    @staticmethod
    def _parse_activity_rows(
        soup: BeautifulSoup,
    ) -> list[Activity]:
        table = ErkeClient._find_activity_table(
            soup
        )
        activities: list[Activity] = []

        for row in table.find_all("tr"):
            columns = [
                clean_text(
                    cell.get_text(" ", strip=True)
                )
                for cell in row.find_all("td")
            ]

            if len(columns) < 8:
                continue

            # 跳过表头或分页控制行。
            joined = " ".join(columns)
            if (
                "活动名称" in joined
                or "获得分数" in joined
            ):
                continue

            category = columns[3]
            if category == "技能特长":
                category = "文体活动"

            # 与现有项目的二课表格列定义一致：
            # 0 名称、1 单位、2 时间、3 分类、
            # 4 身份、5 人数、7 分数。
            activity = Activity(
                name=columns[0],
                organizer=columns[1],
                date=columns[2],
                category=category,
                role=columns[4],
                participant_count=safe_int(
                    columns[5]
                ),
                score=safe_float(columns[7]),
                raw_columns=columns,
            )

            # 避免把布局行、空行当成活动。
            if activity.name and (
                activity.score is not None
                or activity.date
            ):
                activities.append(activity)

        return activities

    @staticmethod
    def _total_pages(
        soup: BeautifulSoup,
    ) -> int:
        pager = soup.select_one("#TPaged1")
        if not pager:
            return 1

        fonts = pager.find_all("font")
        for node in reversed(fonts):
            value = clean_text(
                node.get_text(" ", strip=True)
            )
            if value.isdigit():
                return max(1, int(value))

        text = clean_text(
            pager.get_text(" ", strip=True)
        )
        patterns = (
            r"共\s*(\d+)\s*页",
            r"/\s*(\d+)\s*页",
            r"总页数[：:]\s*(\d+)",
        )
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return max(1, int(match.group(1)))

        return 1

    def _activity_page_soup(
        self,
    ) -> BeautifulSoup:
        return self._protected_soup(
            ACTIVITY_PATH,
            "04_activities_page_1",
        )

    def _post_activity_page(
        self,
        soup: BeautifulSoup,
        page_number: int,
    ) -> BeautifulSoup:
        form = self._all_form_inputs(soup)

        # 搜索条件保持空值，模拟原项目的翻页请求。
        form.update(
            {
                "__VIEWSTATE": self._input_value(
                    soup,
                    "__VIEWSTATE",
                ),
                "__VIEWSTATEGENERATOR": (
                    self._input_value(
                        soup,
                        "__VIEWSTATEGENERATOR",
                    )
                ),
                "__EVENTVALIDATION": (
                    self._input_value(
                        soup,
                        "__EVENTVALIDATION",
                    )
                ),
                "__VIEWSTATEENCRYPTED": (
                    self._input_value(
                        soup,
                        "__VIEWSTATEENCRYPTED",
                    )
                ),
                "YearTime": "",
                "ActivityType": "",
                "OrgNo": "",
                "ActivityName": "",
                "TPaged1$GotoPage": str(
                    page_number
                ),
                "TPaged1$Jump": "跳 转",
            }
        )

        response = self.session.post(
            self.url(ACTIVITY_PATH),
            data=self._gbk_form_body(form),
            headers={
                "Content-Type": (
                    "application/"
                    "x-www-form-urlencoded"
                ),
                "Referer": self.url(
                    ACTIVITY_PATH
                ),
                "Origin": (
                    VPN_BASE
                    if self.mode == "webvpn"
                    else self.direct_base
                ),
            },
            timeout=self.timeout,
            allow_redirects=True,
        )
        self._save_debug(
            f"04_activities_page_{page_number}",
            response,
        )

        html = self._response_text(response)
        if self._is_login_page(response, html):
            raise AuthenticationFailed(
                f"抓取第 {page_number} 页时 "
                "Session 已失效"
            )

        return BeautifulSoup(
            html,
            "html.parser",
        )

    def fetch_activities(
        self,
        *,
        max_pages: int | None = None,
    ) -> tuple[list[Activity], int]:
        soup = self._activity_page_soup()
        total_pages = self._total_pages(soup)

        if max_pages is not None:
            total_pages = min(
                total_pages,
                max_pages,
            )

        all_activities: list[Activity] = []
        seen: set[
            tuple[str, str, str, str]
        ] = set()

        def append_page(
            current_soup: BeautifulSoup,
        ) -> None:
            for activity in self._parse_activity_rows(
                current_soup
            ):
                key = (
                    activity.name,
                    activity.date,
                    activity.organizer,
                    str(activity.score),
                )
                if key not in seen:
                    seen.add(key)
                    all_activities.append(activity)

        append_page(soup)

        for page_number in range(
            2,
            total_pages + 1,
        ):
            soup = self._post_activity_page(
                soup,
                page_number,
            )
            append_page(soup)

        return all_activities, total_pages

    def crawl(
        self,
        *,
        username: str,
        password: str,
        max_pages: int | None,
    ) -> CrawlResult:
        self.login(username, password)
        summary = self.fetch_summary()
        activities, pages = self.fetch_activities(
            max_pages=max_pages
        )

        return CrawlResult(
            student_id=username,
            summary=summary,
            activities=activities,
            pages_fetched=pages,
            fetched_at=datetime.now(
                timezone.utc
            ).isoformat(),
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "本地登录沈理二课并抓取"
            "分类分数与活动记录"
        )
    )
    parser.add_argument(
        "--mode",
        choices=("webvpn", "direct"),
        default="webvpn",
    )
    parser.add_argument(
        "--vpn-login",
        action="store_true",
        help=(
            "不使用浏览器 Ticket，"
            "在本地直接登录 WebVPN"
        ),
    )
    parser.add_argument(
        "--vpn-username",
        default=os.environ.get(
            "VPN_USERNAME",
            "",
        ),
        help=(
            "WebVPN 统一认证账号；"
            "也可设置 VPN_USERNAME"
        ),
    )
    parser.add_argument(
        "--vpn-password-env",
        default="VPN_PASSWORD",
        help=(
            "WebVPN 密码环境变量名；"
            "不存在时安全提示输入"
        ),
    )
    parser.add_argument(
        "--username",
        default=os.environ.get(
            "ERKE_USERNAME",
            "",
        ),
        help=(
            "二课学号；也可设置 "
            "ERKE_USERNAME"
        ),
    )
    parser.add_argument(
        "--password-env",
        default="ERKE_PASSWORD",
        help=(
            "从指定环境变量读取密码；"
            "不存在时安全提示输入"
        ),
    )
    parser.add_argument(
        "--direct-base",
        default="http://xg.sylu.edu.cn",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("erke_result.json"),
    )
    parser.add_argument(
        "--debug-dir",
        type=Path,
        default=None,
        help=(
            "可选：保存脱敏后的响应 HTML，"
            "不会保存 Set-Cookie"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=None,
        help=(
            "测试时限制活动页数；"
            "不填写则抓取全部"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    print("[TLS] 已启用 Windows 系统证书库（truststore）")
    print("[网络] 学校请求已禁用系统代理，使用直连")

    username = args.username.strip()
    if not username:
        username = input(
            "请输入二课学号："
        ).strip()

    if not username:
        print(
            "错误：学号不能为空",
            file=sys.stderr,
        )
        return 2

    password = os.environ.get(
        args.password_env,
        "",
    )
    if not password:
        password = getpass.getpass(
            "请输入二课密码（不会回显）："
        )

    if not password:
        print(
            "错误：密码不能为空",
            file=sys.stderr,
        )
        return 2

    vpn_ticket = None
    vpn_username = ""
    vpn_password = ""

    if args.mode == "webvpn":
        vpn_ticket = os.environ.get(
            "VPN_TICKET",
            "",
        ).strip()

        if args.vpn_login or not vpn_ticket:
            vpn_ticket = None
            vpn_username = (
                args.vpn_username.strip()
                or input(
                    "请输入 WebVPN 统一认证账号："
                ).strip()
            )
            if not vpn_username:
                print(
                    "错误：WebVPN 账号不能为空",
                    file=sys.stderr,
                )
                return 2

            vpn_password = os.environ.get(
                args.vpn_password_env,
                "",
            )
            if not vpn_password:
                vpn_password = getpass.getpass(
                    "请输入 WebVPN 密码（不会回显）："
                )
            if not vpn_password:
                print(
                    "错误：WebVPN 密码不能为空",
                    file=sys.stderr,
                )
                return 2

    from webvpn_client import WebVpnClient

    vpn_client = WebVpnClient(
        vpn_ticket=vpn_ticket,
        timeout=args.timeout,
        debug_dir=args.debug_dir,
    )

    client = ErkeClient(
        mode=args.mode,
        vpn_ticket=vpn_ticket,
        direct_base=args.direct_base,
        timeout=args.timeout,
        debug_dir=args.debug_dir,
        session=vpn_client.session,
        url_builder=vpn_client.url_for,
    )

    try:
        if args.mode == "webvpn" and vpn_ticket is None:
            print("[0/4] 正在本地登录 WebVPN……")
            vpn_client.login_cas(
                vpn_username,
                vpn_password,
            )
            print("[0/4] WebVPN 登录成功。")

        print("[1/4] 正在访问二课登录页……")
        print("[2/4] 正在读取 DOM 验证码并登录……")

        result = client.crawl(
            username=username,
            password=password,
            max_pages=args.max_pages,
        )

        print("[3/4] 登录验证成功，数据抓取完成。")

        data = asdict(result)
        args.output.write_text(
            json.dumps(
                data,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        print("[4/4] 结果已保存：", args.output)
        print()
        print("分类分数：")
        for name, score in result.summary.items():
            print(f"  {name}: {score:g}")

        print()
        print(
            f"活动记录：{len(result.activities)} 条，"
            f"抓取页数：{result.pages_fetched}"
        )

        if result.activities:
            print("前 5 条：")
            for item in result.activities[:5]:
                print(
                    f"  - {item.name} | "
                    f"{item.category} | "
                    f"{item.score}"
                )

        return 0

    except AuthenticationFailed as exc:
        print(
            f"登录失败：{exc}",
            file=sys.stderr,
        )
        return 3
    except LoginPageChanged as exc:
        print(
            f"页面结构异常：{exc}",
            file=sys.stderr,
        )
        return 4
    except requests.Timeout:
        print(
            "网络超时，请检查 WebVPN 和网络。",
            file=sys.stderr,
        )
        return 5
    except requests.RequestException as exc:
        print(
            f"网络请求失败：{exc}",
            file=sys.stderr,
        )
        return 5
    except ErkeError as exc:
        print(
            f"抓取失败：{exc}",
            file=sys.stderr,
        )
        return 6
    except Exception as exc:
        print(
            f"未处理异常：{type(exc).__name__}: "
            f"{exc}",
            file=sys.stderr,
        )
        return 10
    finally:
        # 尽量缩短明文密码变量的生命周期。
        password = ""
        vpn_password = ""


if __name__ == "__main__":
    raise SystemExit(main())
