# SYLUlive 校外本地校园数据协议验证工具

此项目现已转型为 **SYLUlive** 校园数据的本地协议分析与验证库，用于通过 WebVPN 采集二课、教务等关键数据，为 Flutter/Dart 客户端的最终集成做协议验证与技术储备。

> **背景故事与项目转型**  
> 此项目原名为 `sylulive_captcha_onnx_toolkit`，最初用于解决本地二课系统的验证码识别（通过本地 ONNX 模型）。由于最新版的 WebVPN 和教务系统通过直连/代理模式已被验证可以稳定抓取，我们将**验证码相关的旧代码**归档至 `legacy/captcha_onnx/`，而主线工作已转向统一使用 Python 验证协议（无需第三方服务器），以便之后直接向 Dart (Flutter) 迁移。

## 当前包含的能力验证

*   **WebVPN 统一会话共享** (`webvpn_client.py`)
*   **教务系统本地全流程** (`jwxt_full_local_test.py` 与 `JWXT_PROTOCOL.md`)
*   **二课系统本地全流程** (`erke_full_local_login_test.py` 与 `LOGIN_PROTOCOL.md`)

## 快速使用

### 环境要求
- Python 3.10+
- 推荐使用 `venv`
- 安装依赖：`pip install -r requirements.txt` (若需要旧版功能，请进入 `legacy` 安装额外依赖)

### 教务与二课测试

教务与二课系统的本地抓取验证：

```powershell
# 教务测试
$env:VPN_USERNAME="账号"; $env:VPN_PASSWORD="密码"; $env:JWXT_PASSWORD="密码"
python jwxt_full_local_test.py --student-id "学号" --year "2025" --semester "12"

# 二课测试
$env:VPN_USERNAME="账号"; $env:VPN_PASSWORD="密码"; $env:ERKE_USERNAME="学号"; $env:ERKE_PASSWORD="密码"
python erke_full_local_login_test.py --mode webvpn
```

## 目录

```text
collector.py                 验证码采集
label_ui.py                  人工审核标签
captcha_model.py             PyTorch 模型
train.py                     训练、验证、导出 ONNX
infer_onnx.py                在电脑上测试 ONNX
requirements.txt             基础训练依赖
requirements-pseudo-label.txt 可选 ddddocr 依赖
.env.example                 WebVPN Ticket 示例
android/
  CaptchaOnnxRecognizer.kt   Android ONNX 推理
  LocalEducationPlugin.kt    Flutter MethodChannel
  flutter_usage.dart         Flutter 调用示例
  build.gradle.kts.snippet   Gradle 依赖
```

## 1. 建立 Python 环境

Windows PowerShell：

```powershell
cd sylulive_captcha_onnx_toolkit
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -r requirements.txt
```

需要 ddddocr 生成初始伪标签时：

```powershell
pip install -r requirements-pseudo-label.txt
```

建议使用 Python 3.10 或 3.11。PyTorch 请根据你的 CUDA 环境选择官方安装命令；`requirements.txt` 中的普通安装默认也可以使用 CPU。

## 2. 采集验证码

### 模式 A：校园网直接访问

```powershell
python collector.py `
  --mode direct `
  --count 1000 `
  --delay 3 `
  --jitter 1 `
  --pseudo-label
```

默认直接地址为：

```text
http://xg.sylu.edu.cn
```

可通过 `--direct-base` 修改。

### 模式 B：通过 WebVPN Ticket

先把你本人浏览器登录 WebVPN 后获得的 Ticket 放进环境变量。不要把 Ticket 发给别人，也不要提交到 Git。

```powershell
$env:VPN_TICKET="你的 wengine_vpn_ticketwebvpn_sylu_edu_cn"
python collector.py `
  --mode webvpn `
  --count 1000 `
  --delay 3 `
  --jitter 1 `
  --pseudo-label
```

采集结果位于：

```text
data/raw/
data/manifest.csv
```

采集器会尝试两个当前项目中出现过的登录路径：

```text
/SyluTW/Sys/UserLogin.aspx
/SyluTW/Sys/SystemForm/Login.aspx
```

并根据 HTML 中的图片元素自动寻找验证码。

### 采集数量建议

这是经验值，不是硬性要求：

- 先采 500～1000 张验证流程；
- 正式训练建议审核 2000～5000 张；
- 如果验证码变化很小，较少数据也可能达到可用效果；
- 验证码字体、背景或字符集改版后，需要重新采集并微调。

不要把 `--delay` 设得很小。默认每次请求间隔约 2～4 秒，并在连续失败后停止。

## 3. 审核标签

伪标签不能直接当作真值。启动审核界面：

```powershell
python label_ui.py --dataset data --length 4
```

操作：

- `Enter`：保存当前标签并进入下一张；
- `→`：跳过当前图片；
- `←`：返回上一张；
- 文本框会预填 ddddocr 的建议结果；
- 只有点击保存的记录才会标记为 `reviewed=1`。

结果保存在：

```text
data/labels.csv
```

训练脚本只读取人工审核通过的记录。

## 4. 训练并导出 ONNX

```powershell
python train.py `
  --dataset data `
  --epochs 50 `
  --batch-size 64 `
  --output output
```

输出：

```text
output/best.pt
output/captcha.onnx
output/labels.txt
output/model_meta.json
```

模型默认输入：

```text
NCHW = [1, 1, 48, 160]
```

输出：

```text
[batch, captcha_length, class_count]
```

例如四位验证码、36 个字符类别时，输出约为：

```text
[1, 4, 36]
```

训练脚本会从审核后的标签自动推断：

- 验证码长度；
- 实际字符集；
- `labels.txt` 内容。

## 5. 在电脑上测试 ONNX

```powershell
python infer_onnx.py `
  --model output/captcha.onnx `
  --labels output/labels.txt `
  --meta output/model_meta.json `
  --image data/raw/某张图片.png
```

## 6. 接入 Android

复制：

```text
output/captcha.onnx
output/labels.txt
output/model_meta.json
```

到：

```text
client/android/app/src/main/assets/
```

在 Android App 模块加入：

```kotlin
implementation("com.microsoft.onnxruntime:onnxruntime-android:1.26.0")
```

然后放入：

```text
android/CaptchaOnnxRecognizer.kt
android/LocalEducationPlugin.kt
```

把包名改为你的 SYLUlive Android 包名，并在 `MainActivity` 中创建插件：

```kotlin
private lateinit var localEducationPlugin: LocalEducationPlugin

override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
    super.configureFlutterEngine(flutterEngine)
    localEducationPlugin = LocalEducationPlugin(
        applicationContext,
        flutterEngine.dartExecutor.binaryMessenger,
    )
}

override fun onDestroy() {
    localEducationPlugin.close()
    super.onDestroy()
}
```

Flutter 调用示例见：

```text
android/flutter_usage.dart
```

## 7. 真正登录时的建议流程

有关二课系统完整的认证协议分层、加密方式及详细表单提交流程，请参阅：
[LOGIN_PROTOCOL.md](LOGIN_PROTOCOL.md)

简化的 Android 建议流程如下：

```text
先复用本地 Cookie
  ↓ 失效
读取 Android Keystore 中的账号密码
  ↓
下载验证码
  ↓
本地 ONNX 识别
  ↓
提交登录
  ↓ 验证码错误
重新下载并识别，最多 2～3 次
  ↓ 仍失败
显示验证码给用户手动输入
```

不要每次刷新都重新登录。优先复用 WebVPN Ticket 和二课 Session Cookie。

## 8. 常见问题

### 一直提示登录页不可访问

- WebVPN Ticket 已失效；
- 当前网络无法直接访问校园内网；
- 学校更换了 WebVPN 或二课域名；
- 登录路径发生变化。

### 找不到验证码图片

把登录页脱敏后保存下来，检查验证码元素的 `id` 和 `src`，然后扩展 `collector.py` 中的 `find_captcha_src()`。

### 模型准确率很高，但真实登录失败

可能原因：

- 标签中混入了错误伪标签；
- 验证集与训练集存在重复验证码；
- 学校验证码已经改版；
- 预处理与 Android 不一致；
- 字母大小写处理错误。

以“完整四位全部正确”的 `exact_accuracy` 为主要指标，不要只看单字符准确率。

### 为什么不用 CTC

当前二课验证码看起来是固定长度、横向排列字符。多位置分类模型更小、更易导出，也更适合 Android。若以后验证码变成长短不一，再改成 CRNN + CTC。
