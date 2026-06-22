"""Check login response for error messages"""
import re
from pathlib import Path

html = Path("debug/login_response.html").read_text(encoding="utf-8")

print("=== Looking for layer/tips/alert/msg ===")
for pat in [
    r"layer\.\w+\([^)]+\)",
    r'layer\.msg\([^)]+\)',
    r'layer\.tips\([^)]+\)',
    r'layer\.alert\([^)]+\)',
]:
    ms = re.findall(pat, html, re.IGNORECASE)
    for m in ms:
        print(m[:300])
        print()

print("\n=== Looking for error/验证码/密码 ===")
for kw in ["验证码错误", "密码错误", "验证码", "账号或密码", "error", "Error"]:
    if kw in html:
        idx = html.index(kw)
        print(f"  '{kw}': {html[max(0,idx-80):idx+150]}")
        print()

print("\n=== Diff with original ===")
orig = Path("debug/01_login_page.html").read_text(encoding="utf-8")
print(f"Original: {len(orig)} bytes, Response: {len(html)} bytes")
if orig == html:
    print("IDENTICAL - form submission was ignored!")
else:
    # Find differences in form values
    import difflib
    diff = list(difflib.unified_diff(orig.splitlines(keepends=True), html.splitlines(keepends=True)))
    for line in diff:
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
            if any(kw in line for kw in ["value=", "VIEWSTATE", "code-box", "encrypt", "alert", "tips", "msg"]):
                print(line.rstrip())
