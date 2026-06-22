# 正方教务系统 WebVPN 本地验证与采集协议

本文档记录了通过 WebVPN 代理，在本地抓取沈阳理工大学正方教务系统（`jxw.sylu.edu.cn`）全量课表与成绩的协议规范。

> **终极目标：Flutter/Dart 为首选目标**
> 
> 本协议的最终目标是将校园数据采集能力直接集成进 SYLUlive 的 Flutter 客户端（使用 Dart 实现），并让数据存储在用户本地设备，不再经过第三方或开发者服务器。Android原生 (Kotlin) 仅作为 Dart 网络或加密库无法稳定支持部分能力时的底层下沉备选方案。

## 术语与规则
1. **WebVPN 代理**：通过 `webvpn_client` 获取的全局 Session。通过 AES-CFB128 加密 `jxw.sylu.edu.cn` 后，构造 `/http/` 代理 URL。
2. **凭证隔离**：必须使用公共 `requests.Session` 并开启 `trust_env = False`，清空 `proxies`，不泄露 `JSESSIONID` 与 `wengine_vpn_ticketwebvpn_sylu_edu_cn`。测试脚本只在 `debug/` 下保存脱敏信息。

## 登录与鉴权 (SSO)
从全新的本地会话出发，登录流程如下：

1. **登录 WebVPN CAS**：
   - 参考 `LOGIN_PROTOCOL.md` 提供的机制，首先向 `https://webvpn.sylu.edu.cn/login?cas_login=true` 获取 `pwdEncryptSalt` 和 `execution`。
   - 对密码执行 `Base64(AES-CBC)` 加密。
   - 提交表单后，自动追踪重定向。最终会在 Cookie 中获得有效的 WebVPN Ticket。
2. **获得教务系统会话 (`JSESSIONID`)**：
   - 生成 `jxw.sylu.edu.cn` 的 WebVPN 加密地址。
   - 访问入口（如 `/sso/jziotlogin` 或主页面）。
   - 期间可能经历统一身份认证的 SSO 重定向。但因为同一个 CookieJar 中已带有验证过的 WebVPN Ticket，教务系统会自动校验通过并在 Cookie 中下发包含负载均衡信息及真实的 `JSESSIONID`。
   - **验证成功依据**：
     - 请求没有被阻塞在登录 HTML。
     - Cookie 中包含 `JSESSIONID`。
     - （最终通过接口实际获取到数据来验证）。

## 课表接口

获取课表时，桌面端为首选项，遇到失败或不完整时回退至移动端接口。

### 桌面端 JSON（推荐首选项）
- **接口地址**：`POST /kbcx/xskbcx_cxXsgrkb.html?gnmkdm=N2154&su={学号}`
- **Headers**：
  - `X-Requested-With: XMLHttpRequest`
  - `Content-Type: application/x-www-form-urlencoded;charset=utf-8`
- **Body 参数**：
  - `xnm`: 学年（如 `2025`）
  - `xqm`: 学期（`12` = 春季，`3` = 秋季）
  - `kzlx`: `ck`
  - `xsdm`: （空）
- **解析方式**：
  - 返回的是 JSON 字符串。提取 `sjkList`（实际课表）。
  - 提取字段包含：`kcmc`（课程名）、`xm`（教师）、`cdmc`（地点）、`jc`（节次）、`xqj`（星期几）、`zcd`（周次段）。

### 移动端 JSON（备用回退选项）
如果桌面端接口发生错误或者没有数据，可以尝试调用该接口：
- **接口地址**：`POST /kbcx/xskbcxMobile_cxXsKb.html?gnmkdm=N2154&su={学号}`
- **Body 参数**：
  - `xnm`: 学年
  - `xqm`: 学期
  - `zs`: `1`
  - `doType`: `app`
  - `kblx`: `1`
- **解析方式**：
  - 提取 `kbList` 字段中的同样结构数据。

## 成绩接口

成绩查询采取设置极大 `showCount` 尝试一次拉取的策略，但仍然需要处理可能的分页。

- **接口地址**：`POST /cjcx/cjcx_cxXsgrcj.html?doType=query&gnmkdm=N305005&su={学号}`
- **Headers**：
  - `Content-Type: application/x-www-form-urlencoded;charset=utf-8`
- **Body 参数**：
  - `xnm`: 学年
  - `xqm`: 学期
  - `_search`: `false`
  - `nd`: 时间戳（毫秒）
  - `queryModel.showCount`: `5000`（避免频繁翻页）
  - `queryModel.currentPage`: 当前页码（从 1 开始）
  - `time`: `2`
- **解析方式**：
  - JSON 结构。目标列表在 `items` 中。
  - 单条成绩关键字段：`kcmc`（课程名）、`cj`（成绩）、`jd`（绩点）、`xf`（学分）。
  - **分页检查**：比较当前已收集数据量和 `totalResult` 的大小。如果仍有数据，则累加 `currentPage` 继续拉取。

## 开发与调试准则
- **避免假装成功**：绝不可仅以 HTTP 200 或者存在 `JSESSIONID` 视为操作完成。必须通过验证 JSON 内容是否合法、是否含有 `sjkList` 或 `items` 来确立。
- **环境安全**：保存的原始日志（`*_raw.json` 和 HTML 等）供协议分析，但**这些日志在 `debug/` 目录下属于敏感数据，并未脱敏**，可能包含真实的成绩、课表和身份参数。测试后应及时删除，绝不应该上传到公共代码库或通过截图泄露。已在 `.gitignore` 配置。
