# SYLUlive 二课登录协议分析与移植指南

本文档总结了从本地直接发起二课（第二课堂）登录的完整协议流程，可作为后续向 Android (Kotlin) 或其他平台移植的技术规范。

## 术语定义与设计原则

在后续的开发与文档中，统一采用以下术语与描述：

- **完成 WebVPN CAS 认证**：指代成功获取 WebVPN Ticket 的过程。
- **兼容 ASP.NET WebForms 提交流程**：指代正确提取并提交 `__VIEWSTATE`、`__EVENTVALIDATION` 等隐藏字段的过程。
- **当前服务端未观察到验证码校验**：针对目前服务端对验证码参数的宽容处理情况的准确描述。
- **请求头与浏览器行为对齐**：指代为匹配真实浏览器发出的请求而进行的一系列协议对齐操作（如 GB18030 编码、特定 Header 模拟等）。

## 关键技术细节纠正与注意事项

在实现 Kotlin 或其他语言版本的移植时，必须严格遵守以下结论，避免踩坑：

1. **CAS AES 加密逻辑**：
   - 算法流程：随机 64 字符前缀 + 密码 → AES-CBC + PKCS7 → 随机 16 字符 IV → 执行加密。
   - 最终输出：`Base64(AES-CBC 密文)`。**不要**将 IV 拼接到密文前面，直接对纯密文进行 Base64 编码，这与当前 Python 基准实现的输出结果保持严格一致。
   - 测试模式：为保证跨语言输出结果一致，加密函数必须支持传入固定的 IV 与固定的 64 字符前缀，以便编写单元测试直接对比字符串结果。

2. **Direct 登录接口的可用性**：
   - 当前测试环境中，Direct 登录结果无法用于访问二课（未获得有效会话），因此默认采用 CAS 登录方式。
   - Direct 登录接口仅保留作为兼容探测使用。

3. **验证码处理逻辑**：
   - 现状：当前页面中的 `#code-box` 主要由客户端脚本生成，并且当前服务端接受任意兼容值，未观察到有效的服务端验证码校验。
   - 稳妥的逻辑：
     - 如果 `#code-box` 有合法四位内容 → 优先使用页面内容。
     - 如果 `#code-box` 为空 → 使用当前已验证的兼容值（如 `KHG6`）。
     - 若登录响应中出现明确的验证码错误提示 → 重新获取登录页或转人工输入，**不要**无限重试。

4. **表单参数与请求头对齐**：
   - 成功登录是整体请求与真实页面协议匹配的结果（包括 VPN 登录策略、`queryBtn` 提取、`Origin` 头、验证码值、Session 获取方式及登录路径）。

## 会话复用流程

正式 App 不应该每次刷新都重新认证，应当优先尝试复用本地持久化的会话状态。推荐流程如下：

```text
刷新数据
  ↓
读取本地 WebVPN Ticket 与二课 Cookie
  ↓
访问受保护成绩页
  ├─ 存在 CountA、SunCount
  │    → Session 有效，直接拉取数据
  │
  └─ 被重定向至登录页 或 访问失败
       → 从安全存储读取凭证
       → 重新完成 CAS 和二课登录
       → 更新本地 Cookie
```

**安全注意**：Cookie、VPN Ticket 和密码都应保存在 Android Keystore 支持的安全存储中（例如 EncryptedSharedPreferences 或 flutter_secure_storage），不进入普通 SharedPreferences、日志或中转服务器。

## 认证协议分层模型

整个登录过程在逻辑上可划分为五个层次：

- **第一层**：WebVPN CAS 身份认证
- **第二层**：WebVPN 内网地址代理
- **第三层**：二课 ASP.NET 会话认证
- **第四层**：受保护资源验证
- **第五层**：成绩及活动数据解析

## 最终确定的完整登录流程

在代码实现时，请严格按照以下步骤顺序执行：

1. 本地访问 WebVPN CAS 登录页。
2. 解析页面中的 `pwdEncryptSalt` 和 `execution`。
3. 按照网页前端的算法加密统一认证密码（AES-CBC 逻辑）。
4. 提交登录表单，并妥善处理重定向跳转、滑块验证以及可能的 TOTP 二次认证。
5. 保持在同一个 Cookie Session 中，最终获得 VPN Ticket。
6. 使用 AES-CFB128 算法加密目标地址 `xg.sylu.edu.cn`，生成 WebVPN 代理 URL。
7. 请求代理后的二课登录页面 `UserLogin.aspx`。
8. 动态读取并解析页面中的关键字段（见下方映射表）。
9. 使用 RSA PKCS#1 v1.5 加密二课系统密码。
10. 使用 `GB18030` 对表单数据进行 URL 编码，并提交登录请求。
11. 验证登录态，请求 `StuFinishStudentScore.aspx`。
12. 页面解析，检测 `CountA`～`CountE` 和 `SunCount` 等分数项。
13. 请求活动数据页 `StuActionSearch.aspx`。
14. 解析活动数据表单。每次翻页后必须重新解析并提交当前页面返回的 `__VIEWSTATE`、`__VIEWSTATEGENERATOR`、`__EVENTVALIDATION` 以及分页控件字段，**不得复用第一页的旧状态参数**。

### 二课登录表单字段映射表

| 字段 | 来源 | 处理 |
| :--- | :--- | :--- |
| `UserName` | 用户输入 | 原值 |
| `Password` | 用户输入 | 按已跑通请求保留原明文 |
| `pwd` | 用户密码 | RSA PKCS#1 v1.5 后 Base64 |
| `pubKey` | 当前登录页 | 原样提取并提交 |
| `codeInput` | `#code-box` 或兼容值 | 四位字符串 |
| `queryBtn` | 当前页面按钮 | 保留全部空格原样提交 |
| `__VIEWSTATE` | 当前页面 | 原样提取并提交 |
| `__VIEWSTATEGENERATOR` | 当前页面 | 原样提取并提交 |
| `__EVENTVALIDATION` | 当前页面 | 原样提取并提交 |

---

## 推荐的 Kotlin 移植方案

### 模块结构建议

建议按照以下职责划分包结构：

```text
education/
├── network/
│   ├── VpnCasClient.kt
│   ├── WebVpnUrlCodec.kt
│   ├── ErkeAuthClient.kt
│   └── ErkeDataClient.kt
├── parser/
│   ├── VpnLoginParser.kt
│   ├── ErkeLoginParser.kt
│   ├── ErkeSummaryParser.kt
│   └── ErkeActivityParser.kt
├── crypto/
│   ├── CasPasswordCipher.kt
│   ├── WebVpnDomainCipher.kt
│   └── ErkeRsaCipher.kt
├── storage/
│   ├── EducationCredentialStore.kt
│   ├── EducationCookieStore.kt
│   └── EducationCacheStore.kt
├── model/
│   ├── ErkeSummary.kt
│   ├── ErkeActivity.kt
│   └── EducationResult.kt
├── EducationRepository.kt
└── LocalEducationPlugin.kt
```

### 推荐移植顺序

建议优先移植纯函数部分，便于直接与 Python 脚本对齐单元测试：

1. WebVPN 域名 AES-CFB128 加密
2. CAS AES-CBC 密码加密
3. 二课 RSA 加密
4. GB18030 表单编码
5. HTML 登录页解析
6. CAS 网络登录逻辑
7. 二课网络登录逻辑
8. 总分和活动解析
9. Cookie 安全保存
10. Flutter MethodChannel 或 Pigeon 接口对接

### 跨语言测试基准

在进行 Kotlin 开发前，建议基于已跑通的 Python 环境，生成一组不含真实敏感凭证的测试样本，用于保障两端输出的绝对一致：

```text
fixtures/
├── vpn_cas_login.html
├── erke_login.html
├── erke_summary.html
├── erke_activities_page_1.html
└── erke_activities_page_2.html
```

Python 和 Kotlin 的单元测试应当得到完全相同的：
- WebVPN 加密域名
- CAS 加密输出测试向量（使用固定 IV 与前缀）
- 验证码和 queryBtn 等表单字段
- 五类分数及总分
- 活动数量和字段列表
- 总页数
