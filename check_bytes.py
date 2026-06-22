import re
b = open("debug/01_login_page.html", "rb").read()
m = re.search(rb'queryBtn.*?value="(.*?)"', b)
print("Bytes:", [hex(x) for x in m.group(1)])
print("Len:", len(m.group(1)))
print("Decoded gbk:", m.group(1).decode("gbk"))
print("Number of spaces:", m.group(1).count(32))
