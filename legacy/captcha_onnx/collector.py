from __future__ import annotations

import argparse
import csv
import hashlib
import io
import os
import random
import re
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from PIL import Image, UnidentifiedImageError


VPN_BASE = "https://webvpn.sylu.edu.cn"
TARGET_DOMAIN = "xg.sylu.edu.cn"
AES_KEY = b"wrdvpnisthebest!"
AES_IV = b"wrdvpnisthebest!"

LOGIN_PATHS = (
    "/SyluTW/Sys/UserLogin.aspx",
    "/SyluTW/Sys/SystemForm/Login.aspx",
)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)

CAPTCHA_IDS = (
    "ImageCode",
    "imgCode",
    "validCode",
    "codeImg",
    "captcha",
    "captchaImg",
)

CAPTCHA_KEYWORDS = (
    "checkcode",
    "validatecode",
    "verifycode",
    "captcha",
    "codeimg",
    "imagecode",
)


@dataclass(frozen=True)
class LoginTarget:
    internal_path: str
    request_url: str


class CaptchaCollector:
    def __init__(
        self,
        mode: str,
        output_dir: Path,
        vpn_ticket: Optional[str] = None,
        direct_base: str = "http://xg.sylu.edu.cn",
        timeout: float = 15.0,
        pseudo_label: bool = False,
    ) -> None:
        if mode not in {"direct", "webvpn"}:
            raise ValueError("mode 必须是 direct 或 webvpn")
        if mode == "webvpn" and not vpn_ticket:
            raise ValueError(
                "webvpn 模式必须通过 --vpn-ticket 或 VPN_TICKET 提供有效 Ticket"
            )

        self.mode = mode
        self.output_dir = output_dir
        self.raw_dir = output_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = output_dir / "manifest.csv"
        self.direct_base = direct_base.rstrip("/")
        self.timeout = timeout

        self.session = requests.Session()
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
        self._known_hashes = self._load_known_hashes()
        self._ocr = None

        if pseudo_label:
            try:
                import ddddocr  # type: ignore

                self._ocr = ddddocr.DdddOcr(show_ad=False)
            except ImportError as exc:
                raise RuntimeError(
                    "使用 --pseudo-label 前请安装 requirements-pseudo-label.txt"
                ) from exc

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

    def _vpn_url(self, internal_url_or_path: str) -> str:
        parsed = urlparse(internal_url_or_path)
        if parsed.scheme and parsed.netloc:
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
        else:
            path = internal_url_or_path

        if not path.startswith("/"):
            path = "/" + path

        return f"{VPN_BASE}/http/{self._encrypted_host}{path}"

    def _targets(self) -> list[LoginTarget]:
        targets: list[LoginTarget] = []
        for path in LOGIN_PATHS:
            if self.mode == "webvpn":
                url = self._vpn_url(path)
            else:
                url = self.direct_base + path
            targets.append(LoginTarget(path, url))
        return targets

    def _resolve_captcha_url(
        self,
        login_target: LoginTarget,
        src: str,
    ) -> str:
        src = src.strip()

        if src.startswith("//"):
            src = "https:" + src
        if self.mode == "webvpn" and src.startswith(("/http/", "/https/")):
            return VPN_BASE + src

        parsed = urlparse(src)
        if parsed.scheme and parsed.netloc:
            if parsed.netloc.lower() == TARGET_DOMAIN:
                if self.mode == "webvpn":
                    return self._vpn_url(src)
                return src
            return src

        if self.mode == "direct":
            return urljoin(login_target.request_url, src)

        # 在“真实内网站点”的上下文中解析 ../、相对路径和查询参数，
        # 然后再转换成 WebVPN 加密 URL。
        virtual_base = f"http://{TARGET_DOMAIN}{login_target.internal_path}"
        resolved_internal = urljoin(virtual_base, src)
        return self._vpn_url(resolved_internal)

    @staticmethod
    def find_captcha_src(html: str) -> str:
        soup = BeautifulSoup(html, "html.parser")

        for image_id in CAPTCHA_IDS:
            node = soup.find("img", id=image_id)
            if node and node.get("src"):
                return str(node["src"])

        for image in soup.find_all("img"):
            src = str(image.get("src") or "")
            lowered = src.lower()
            if any(keyword in lowered for keyword in CAPTCHA_KEYWORDS):
                return src

        # 部分页面由 JS 给图片赋值。
        patterns = (
            r"""(?:src|url)\s*[:=]\s*["']([^"']*(?:captcha|checkcode|verifycode|imagecode)[^"']*)["']""",
            r"""["']([^"']*(?:captcha|checkcode|verifycode|imagecode)[^"']*)["']""",
        )
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)

        raise RuntimeError("登录页中未找到验证码图片地址")

    def _load_known_hashes(self) -> set[str]:
        hashes: set[str] = set()
        if not self.manifest_path.exists():
            return hashes

        with self.manifest_path.open("r", encoding="utf-8-sig", newline="") as fp:
            for row in csv.DictReader(fp):
                value = (row.get("sha256") or "").strip()
                if value:
                    hashes.add(value)
        return hashes

    def _append_manifest(self, row: dict[str, str]) -> None:
        fields = (
            "image",
            "sha256",
            "suggestion",
            "collected_at",
            "mode",
            "login_path",
            "captcha_url_host",
        )
        exists = self.manifest_path.exists()
        with self.manifest_path.open(
            "a",
            encoding="utf-8-sig",
            newline="",
        ) as fp:
            writer = csv.DictWriter(fp, fieldnames=fields)
            if not exists:
                writer.writeheader()
            writer.writerow(row)

    @staticmethod
    def _normalize_image(content: bytes) -> bytes:
        try:
            with Image.open(io.BytesIO(content)) as image:
                image.load()
                # 统一保存为 RGB PNG，避免 GIF/BMP/WebP 在后续流程中产生差异。
                normalized = image.convert("RGB")
                buffer = io.BytesIO()
                normalized.save(buffer, format="PNG", optimize=True)
                return buffer.getvalue()
        except (UnidentifiedImageError, OSError) as exc:
            snippet = content[:80]
            raise RuntimeError(
                f"验证码响应不是可识别图片，前 80 字节为 {snippet!r}"
            ) from exc

    def _pseudo_label(self, png: bytes) -> str:
        if self._ocr is None:
            return ""
        value = str(self._ocr.classification(png))
        return re.sub(r"[^0-9A-Za-z]", "", value).strip()

    def fetch_one(self) -> Optional[Path]:
        errors: list[str] = []

        for target in self._targets():
            try:
                page = self.session.get(
                    target.request_url,
                    headers={"Referer": VPN_BASE if self.mode == "webvpn" else self.direct_base},
                    timeout=self.timeout,
                    allow_redirects=True,
                )
                if page.status_code != 200:
                    raise RuntimeError(f"登录页 HTTP {page.status_code}")

                content_type = page.headers.get("Content-Type", "").lower()
                if "text/html" not in content_type and "<html" not in page.text.lower():
                    raise RuntimeError(
                        f"登录页响应类型异常: {content_type or 'unknown'}"
                    )

                captcha_src = self.find_captcha_src(page.text)
                captcha_url = self._resolve_captcha_url(target, captcha_src)

                image_response = self.session.get(
                    captcha_url,
                    headers={
                        "Referer": target.request_url,
                        "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
                        "Cache-Control": "no-cache",
                        "Pragma": "no-cache",
                    },
                    timeout=self.timeout,
                    allow_redirects=True,
                )
                if image_response.status_code != 200:
                    raise RuntimeError(
                        f"验证码 HTTP {image_response.status_code}"
                    )

                png = self._normalize_image(image_response.content)
                digest = hashlib.sha256(png).hexdigest()
                if digest in self._known_hashes:
                    return None

                name = f"{datetime.now():%Y%m%d_%H%M%S}_{uuid.uuid4().hex[:10]}.png"
                relative = Path("raw") / name
                output = self.output_dir / relative
                output.write_bytes(png)

                suggestion = self._pseudo_label(png)
                self._known_hashes.add(digest)
                self._append_manifest(
                    {
                        "image": relative.as_posix(),
                        "sha256": digest,
                        "suggestion": suggestion,
                        "collected_at": datetime.now(timezone.utc).isoformat(),
                        "mode": self.mode,
                        "login_path": target.internal_path,
                        "captcha_url_host": urlparse(captcha_url).netloc,
                    }
                )
                return output

            except Exception as exc:  # 记录每个候选路径的错误后继续尝试
                errors.append(f"{target.internal_path}: {exc}")

        raise RuntimeError("；".join(errors))

    def collect(
        self,
        count: int,
        delay: float,
        jitter: float,
        max_consecutive_errors: int,
    ) -> None:
        saved = 0
        consecutive_errors = 0

        while saved < count:
            try:
                result = self.fetch_one()
                consecutive_errors = 0
                if result is None:
                    print("[SKIP] 与已有样本重复")
                else:
                    saved += 1
                    print(f"[{saved}/{count}] 已保存 {result}")
            except KeyboardInterrupt:
                print("\n用户中止采集")
                return
            except Exception as exc:
                consecutive_errors += 1
                print(
                    f"[ERROR {consecutive_errors}/{max_consecutive_errors}] {exc}",
                    file=sys.stderr,
                )
                if consecutive_errors >= max_consecutive_errors:
                    raise RuntimeError(
                        "连续失败次数过多，已停止。请检查 Ticket、网络和页面结构。"
                    ) from exc

            sleep_seconds = max(0.5, delay + random.uniform(-jitter, jitter))
            time.sleep(sleep_seconds)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="低频采集本人有权访问的二课登录验证码"
    )
    parser.add_argument(
        "--mode",
        choices=("direct", "webvpn"),
        required=True,
    )
    parser.add_argument("--output", type=Path, default=Path("data"))
    parser.add_argument("--count", type=int, default=500)
    parser.add_argument("--delay", type=float, default=3.0)
    parser.add_argument("--jitter", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--max-consecutive-errors", type=int, default=5)
    parser.add_argument(
        "--direct-base",
        default="http://xg.sylu.edu.cn",
    )
    parser.add_argument(
        "--vpn-ticket",
        default=os.environ.get("VPN_TICKET", ""),
        help="默认读取 VPN_TICKET 环境变量",
    )
    parser.add_argument(
        "--pseudo-label",
        action="store_true",
        help="使用 ddddocr 生成待人工审核的建议标签",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.count <= 0:
        raise ValueError("--count 必须大于 0")
    if args.delay < 1.0:
        raise ValueError("为避免触发学校风控，--delay 不应小于 1 秒")
    if args.jitter < 0:
        raise ValueError("--jitter 不能为负数")

    collector = CaptchaCollector(
        mode=args.mode,
        output_dir=args.output,
        vpn_ticket=args.vpn_ticket or None,
        direct_base=args.direct_base,
        timeout=args.timeout,
        pseudo_label=args.pseudo_label,
    )
    collector.collect(
        count=args.count,
        delay=args.delay,
        jitter=args.jitter,
        max_consecutive_errors=args.max_consecutive_errors,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
