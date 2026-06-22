import argparse
import json
import re
import sys
import os
import time
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Tuple, Optional

import requests
from bs4 import BeautifulSoup

from webvpn_client import WebVpnClient, WebVpnAuthenticationFailed


TARGET_DOMAIN = "jxw.sylu.edu.cn"


class JwxtError(RuntimeError):
    pass


class JwxtAuthenticationFailed(JwxtError):
    pass


class CourseNotOpenError(JwxtError):
    pass


class GradesNotOpenError(JwxtError):
    pass


class CookieLapseError(JwxtError):
    pass


class WebVpnAccessDeniedError(JwxtError):
    """WebVPN 已认证，但当前账号无权访问目标内网资源。"""


ACCESS_DENIED_MARKERS = (
    "没有权限访问该资源",
    "无权访问该资源",
    "您没有权限",
)


def _raise_for_html_interception(html: str) -> None:
    if any(marker in html for marker in ACCESS_DENIED_MARKERS):
        raise WebVpnAccessDeniedError(
            "WebVPN 登录成功，但当前账号无权访问教务系统"
        )

    if "统一身份认证" in html or "登录" in html:
        raise CookieLapseError(
            "会话已失效，接口返回登录页面"
        )


@dataclass
class CourseRawData:
    name: str
    teacher: str
    location: str
    time: str
    week_day: str
    week_str: str


@dataclass
class JwxtCrawlResult:
    vpn_login: bool
    jwxt_session: bool
    has_jsessionid: bool
    course_count: int
    grade_count: int


class JwxtClient:
    def __init__(
        self,
        session: requests.Session,
        url_builder,
        timeout: float = 15.0,
        debug_dir: Path | None = None,
    ):
        self.session = session
        self.url_builder = url_builder
        self.timeout = timeout
        self.debug_dir = debug_dir

    def url(self, path: str) -> str:
        return self.url_builder(TARGET_DOMAIN, path)

    def _save_debug(self, name: str, response: requests.Response):
        if not self.debug_dir:
            return

        safe_name = re.sub(r"[^0-9A-Za-z_.-]", "_", name)
        path = self.debug_dir / safe_name

        content_type = response.headers.get("Content-Type", "").lower()

        if "html" in content_type or not content_type:
            try:
                text = response.content.decode("utf-8")
            except UnicodeDecodeError:
                text = response.content.decode("gb18030", errors="replace")
            path.with_suffix(".html").write_text(text, encoding="utf-8", errors="replace")

        elif "json" in content_type:
            try:
                data = response.json()
                path.with_suffix(".json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass

    def establish_session(self) -> bool:
        """
        通过 WebVPN 代理访问教务入口，获取 JSESSIONID。
        """
        entry_url = self.url("/sso/jziotlogin")
        resp = self.session.get(entry_url, timeout=self.timeout, allow_redirects=True)
        self._save_debug("01_jwxt_entry", resp)

        content_type = resp.headers.get("Content-Type", "").lower()
        if "html" in content_type:
            _raise_for_html_interception(resp.text)

        has_jsessionid = False
        for cookie in self.session.cookies:
            if cookie.name == "JSESSIONID" and cookie.domain.endswith(TARGET_DOMAIN):
                has_jsessionid = True
                break
            # 有些负载均衡情况下可能 JSESSIONID 的 domain 是 webvpn 的代理 domain
            if cookie.name == "JSESSIONID":
                has_jsessionid = True

        return has_jsessionid

    def fetch_courses(self, year: str, semester: str, student_id: str) -> List[CourseRawData]:
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            "Referer": self.url(f"/kbcx/xskbcx_cxXsgrkb.html?gnmkdm=N2154&su={student_id}"),
        }

        all_courses: List[CourseRawData] = []
        seen = set()

        def _add_from_kblist(kb_list):
            for item in kb_list:
                course = CourseRawData(
                    name=item.get("kcmc", ""),
                    teacher=item.get("xm", ""),
                    location=item.get("cdmc", ""),
                    time=item.get("jc", ""),
                    week_day=str(item.get("xqj", "1")),
                    week_str=item.get("zcd", "")
                )
                key = (course.name, course.teacher, course.location, course.week_day, course.time, course.week_str)
                if key not in seen:
                    seen.add(key)
                    all_courses.append(course)

        # 尝试桌面端
        try:
            resp = self.session.post(
                self.url("/kbcx/xskbcx_cxXsgrkb.html"),
                params={"gnmkdm": "N2154", "su": student_id},
                data={"xnm": year, "xqm": semester, "kzlx": "ck", "xsdm": ""},
                headers=headers,
                timeout=self.timeout
            )
            self._save_debug("02_timetable_desktop_raw", resp)
            
            if resp.status_code in (901, 302):
                raise CookieLapseError("教务会话已过期 (DESK)")
                
            content_type = resp.headers.get("Content-Type", "").lower()
            if "html" in content_type:
                _raise_for_html_interception(resp.text)
                raise CookieLapseError("请求返回了 HTML，教务会话可能失效")

            if resp.status_code == 200 and resp.text.strip() not in ("null", ""):
                data = resp.json()
                kb_list = data.get("sjkList", [])
                if kb_list:
                    _add_from_kblist(kb_list)
        except (CookieLapseError, JwxtAuthenticationFailed, WebVpnAccessDeniedError):
            raise
        except Exception as e:
            print(f"  [WARN] 桌面端接口失败: {e}", file=sys.stderr)

        # 如果桌面端失败，尝试移动端
        if not all_courses:
            print("  [INFO] 尝试使用移动端接口获取课表...", file=sys.stderr)
            try:
                resp = self.session.post(
                    self.url("/kbcx/xskbcxMobile_cxXsKb.html"),
                    params={"gnmkdm": "N2154", "su": student_id},
                    data={"xnm": year, "zs": "1", "doType": "app", "xqm": semester, "kblx": "1"},
                    timeout=self.timeout
                )
                self._save_debug("02_timetable_mobile_raw", resp)
                
                if resp.status_code in (901, 302):
                    raise CookieLapseError("教务会话已过期 (MOBILE)")
                
                content_type = resp.headers.get("Content-Type", "").lower()
                if "html" in content_type:
                    _raise_for_html_interception(resp.text)
                    raise CookieLapseError("移动端请求返回了 HTML，教务会话可能失效")

                if resp.status_code == 200 and resp.text.strip() not in ("null", ""):
                    data = resp.json()
                    if "kbList" not in data:
                        raise CourseNotOpenError("移动端未返回 kbList 字段")
                    kb_list = data.get("kbList", [])
                    if kb_list:
                        _add_from_kblist(kb_list)
            except (CookieLapseError, JwxtAuthenticationFailed, CourseNotOpenError, WebVpnAccessDeniedError):
                raise
            except Exception as e:
                print(f"  [WARN] 移动端接口失败: {e}", file=sys.stderr)

        if not all_courses:
            raise CourseNotOpenError("当前学期课表暂未开放或解析失败")

        return all_courses

    def fetch_grades(self, year: str, semester: str, student_id: str) -> List[dict]:
        headers = {
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
        }
        
        all_items = []
        page = 1
        show_count = 5000

        while page <= 20:
            resp = self.session.post(
                self.url("/cjcx/cjcx_cxXsgrcj.html"),
                params={"doType": "query", "gnmkdm": "N305005", "su": student_id},
                data={
                    "xnm": year,
                    "xqm": semester,
                    "_search": "false",
                    "nd": str(int(time.time() * 1000)),
                    "queryModel.showCount": str(show_count),
                    "queryModel.currentPage": str(page),
                    "time": "2"
                },
                headers=headers,
                timeout=self.timeout
            )
            self._save_debug(f"03_grades_page_{page}_raw", resp)

            if resp.status_code != 200:
                raise CookieLapseError(f"获取成绩失败，HTTP {resp.status_code}")

            content_type = resp.headers.get("Content-Type", "").lower()
            if "html" in content_type:
                _raise_for_html_interception(resp.text)
                raise CookieLapseError("成绩接口返回 HTML，会话可能已失效")

            try:
                data = resp.json()
            except json.JSONDecodeError:
                raise GradesNotOpenError("成绩数据解析为 JSON 失败")

            items = data.get("items", [])
            if not isinstance(items, list):
                raise GradesNotOpenError("成绩接口返回的 items 不是列表格式，结构发生变化")
            
            if not items:
                break
                
            all_items.extend(items)

            try:
                total_result = int(data.get("totalResult") or 0)
            except (TypeError, ValueError):
                total_result = len(all_items)
                
            if len(all_items) >= total_result:
                break
                
            page += 1

        if not all_items:
            raise GradesNotOpenError("当前学期暂无成绩")

        return all_items


def main():
    parser = argparse.ArgumentParser(description="教务系统本地全流程验证脚本（经过 WebVPN）")
    parser.add_argument("--year", default="2025", help="学年，如 2025")
    parser.add_argument("--semester", default="12", help="学期，12=春，3=秋")
    parser.add_argument("--student-id", help="学号（优先使用环境 JWXT_USERNAME，若无则取此处或交互输入）")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    debug_dir = Path("debug")
    debug_dir.mkdir(exist_ok=True)

    vpn_username = os.getenv("VPN_USERNAME")
    vpn_password = os.getenv("VPN_PASSWORD")
    jwxt_username = os.getenv("JWXT_USERNAME") or args.student_id

    if not vpn_username:
        vpn_username = input("请输入 VPN 账号: ")
    if not vpn_password:
        import getpass
        vpn_password = getpass.getpass("请输入 VPN 密码: ")
    if not jwxt_username:
        jwxt_username = input("请输入教务学号: ")

    vpn_client = WebVpnClient(timeout=args.timeout, debug_dir=debug_dir)
    jwxt_client = JwxtClient(session=vpn_client.session, url_builder=vpn_client.url_for, timeout=args.timeout, debug_dir=debug_dir)

    result = JwxtCrawlResult(
        vpn_login=False,
        jwxt_session=False,
        has_jsessionid=False,
        course_count=0,
        grade_count=0
    )

    try:
        print("[1/5] 正在本地登录 WebVPN...")
        result.vpn_login = vpn_client.login_cas(vpn_username, vpn_password)
        if not result.vpn_login:
            print("WebVPN 登录失败。")
            return 1
        print("[1/5] WebVPN 登录成功。")

        print("[2/5] 正在通过 WebVPN 建立教务会话...")
        result.has_jsessionid = jwxt_client.establish_session()
        
        if not result.has_jsessionid:
            print("[2/5] 未获取到 JSESSIONID，将继续尝试通过后续接口验证会话")
        else:
            print("[2/5] 教务基础会话建立完成，已获得 JSESSIONID")

        print(f"[3/5] 正在抓取课表 ({args.year}-{args.semester})...")
        try:
            courses = jwxt_client.fetch_courses(args.year, args.semester, jwxt_username)
            result.course_count = len(courses)
            result.jwxt_session = True  # 课表请求成功，确认为有效会话
            print(f"[3/5] 成功获取 {len(courses)} 门课。")
            if courses:
                print("前 5 条课表记录：")
                for c in courses[:5]:
                    print(f"  - {c.name} | {c.teacher} | {c.location} | 周{c.week_day} | {c.time} | {c.week_str}")
        except CourseNotOpenError as e:
            print(f"[3/5] 课表未开放: {e}")

        print(f"[4/5] 正在抓取成绩 ({args.year}-{args.semester})...")
        try:
            grades = jwxt_client.fetch_grades(args.year, args.semester, jwxt_username)
            result.grade_count = len(grades)
            result.jwxt_session = True  # 成绩请求成功，确认为有效会话
            print(f"[4/5] 成功获取 {len(grades)} 条成绩。")
            if grades:
                print("前 5 条成绩记录：")
                for g in grades[:5]:
                    print(f"  - {g.get('kcmc', '未知课程')} | {g.get('cj', '')} | 学分: {g.get('xf', '')} | 绩点: {g.get('jd', '')}")
        except GradesNotOpenError as e:
            print(f"[4/5] 成绩未开放: {e}")

        print("[5/5] 验证完成，保存测试结果摘要...")
        
        summary_file = debug_dir / "test_summary.json"
        summary_file.write_text(json.dumps(asdict(result), ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"摘要已保存至 {summary_file}")
        
        return 0

    except WebVpnAuthenticationFailed as e:
        print(f"WebVPN 认证失败: {e}", file=sys.stderr)
        return 2
    except CookieLapseError as e:
        print(f"教务会话失效: {e}", file=sys.stderr)
        return 3
    except WebVpnAccessDeniedError as e:
        print(f"教务入口访问被拒绝: {e}", file=sys.stderr)
        return 4
    except Exception as e:
        print(f"未知错误: {e}", file=sys.stderr)
        return 10
    finally:
        vpn_password = ""


if __name__ == "__main__":
    sys.exit(main())
