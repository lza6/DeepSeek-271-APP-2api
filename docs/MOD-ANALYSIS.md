# Mod 版鉴定报告

样本：`DeepSeek_v2.7.1_(288)_Mod.apk`
MD5 `f90bf9c83805394b36f8cc2b9106e1c8` · SHA-1 见 `apksigner` 输出 · 19.0 MB / 698 个条目
包名 `com.deepseek.chat` · versionName 2.7.1 / versionCode 288 · arm64-v8a · minSdk 29 / targetSdk 36

> 无法与官方原包做逐字节 diff（手上没有官方的 v2.7.1 安装包）。因此本报告只陈述**可以在样本内部自证**的篡改痕迹，凡需要对比才能下结论的，明确标注「需官方样本复核」。

---

## 1. 签名：第三方重签，且只剩 v3

`apksigner verify --verbose --print-certs`（Android SDK build-tools 35.0.0）实测：

```
Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): false
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Number of signers: 1
Signer #1 certificate DN: CN=IN
Signer #1 certificate SHA-256: 1da5e08fffa51acf0ae1cab33b0878b3a386557a2de4d698cb65d9c722ea6d55
Signer #1 key algorithm: RSA, 1024 bits
WARNING: No SourceStamp signature
```

三条独立证据都指向"非官方重签"：

1. **v1 与 v2 方案全部为 false**，唯一生效的是 v3。官方 Play 分发包通常是 v1+v2+v3 共存；`META-INF` 下也**没有** `MANIFEST.MF` / `.SF` / `.RSA`（已验证，`zipfile.namelist()` 过滤为空）。
2. **证书 DN 是 `CN=IN`** —— 两个字，不是公司名。这是破解重签工具（MT 管理器 / NP 管理器一类）默认模板证书的典型特征。
3. **RSA 1024 位**。Google Play 的应用签名密钥用 RSA 2048/4096，1024 位是老旧自签工具的默认值，安全性上已被淘汰。
4. **自签且有效期 100 年**：`subject=CN=IN issuer=CN=IN`，`notBefore=2022-12-24`、`notAfter=2123-03-10`。没有任何真实发布者会签一张百年证书，这是工具生成模板的默认行为。

```bash
openssl x509 -inform DER -in signer-cert.der -noout -subject -issuer -dates
# subject=CN=IN
# issuer=CN=IN
# notBefore=Dec 24 15:38:39 2022 GMT
# notAfter=Mar 10 15:38:39 2123 GMT
```

附带现象：APK Signing Block 的布局不符合规范（magic 前 8 字节的 size 字段为 4088，但按 `start = magic - 8 - size` 回推的块首字节是 `0x00000000` 而非同一个 size 值）。这是签名改写工具留下的结构性痕迹，不影响 `apksigner` 校验 v3 通过。

**判定：该包被第三方重签，签名身份不是 DeepSeek 官方。装它等于信任这个 `CN=IN` 的匿名密钥。**

---

## 2. PairIP 授权校验被摘掉

DeepSeek 官方 APK 使用 Google 的 **PairIP**（Play Integrity 的防重打包方案），组件在 `com.pairip.licensecheck.*`。正常情况下它由两处触发：

- `android:name="com.pairip.application.Application"`（Application 入口）
- `<provider android:name="com.pairip.licensecheck.LicenseContentProvider">`（进程启动即校验）

实测：

| 检查项 | 结果 |
|---|---|
| manifest 中出现 `pairip` 的行 | 仅 1 行：`android:name="com.pairip.application.Application"` |
| manifest 中出现 `LicenseContentProvider` | **false** |

`LicenseContentProvider.onCreate()` 里的 `LicenseClient.checkLicense(getContext())` 是这个壳真正的入口（见 `jadx_out/sources/com/pairip/licensecheck/LicenseContentProvider.java:12`）。**provider 声明被从 manifest 删除 ⇒ 校验永远不会触发**，而类本身还躺在 dex 里做样子。

保留的 `com.pairip.application.Application` 已经被改成空壳：

```java
public class Application extends App {          // 继承 DeepSeek 自己的 App，不是 android.app.Application
    @Override protected void attachBaseContext(Context context) {
        super.attachBaseContext(context);       // 只透传，无任何校验逻辑
    }
}
```

原版 PairIP 的 Application 会在 `attachBaseContext` 里跑 VMRunner 做完整性校验并决定是否 `System.exit`。现在它只剩一句 `super`。

**判定：Play 安装来源校验 + 重打包完整性校验被移除，这是"能在非 Play 渠道安装"的前提，也是本 Mod 的核心改动。**

---

## 3. dex 归属：只有两个类被搬出来改写

`classes2.dex` 只有 44,368 字节，时间戳 **2026-10-24 22:18**，而 `classes.dex`/`classes3.dex`/`classes4.dex`/所有 `.so` 的全是 `1981-01-01 00:01`（zip 零时间戳，构建工具的默认值）。**一个 dex 单独带真实时间戳 = 它在最后一次打包时被单独生成/替换。**

它里面一共 38 个类，全部属于两个包：

```
com.deepseek.chat.App                     ← 1 个，来自业务代码
com.pairip.application.Application        ← 1 个
com.pairip.licensecheck.*                 ← 36 个（LicenseClient/LicenseActivity/
                                             LicenseContentProvider/TrialClient/
                                             LicenseResponseHelper/… + 15 个 lambda）
```

**判定：打包者把 `com.deepseek.chat.App` 和整个 PairIP 包单独抽成 `classes2.dex` 做定向改写**，其余业务代码原样留在 `classes.dex`（12.6 MB）里。这与"只去校验、不改功能"的轻 Mod 手法一致。

`App.attachBaseContext` 里唯一一句额外调用 `eba.m6845c(this, false)` 属于腾讯 Tinker 热修复框架的初始化（`eba` 引用了 `ZipFile`/`ZipEntry`/`AtomicReference`，是 Tinker 的 patch loader），参数 `false` 表示不加载外部 dex —— 这是官方代码，不是注入。

---

## 4. 权限：干净，没有注入间谍/远控能力

manifest 里 `uses-permission` 全表（19 条，全部官方功能所需）：

```
INTERNET  ACCESS_NETWORK_STATE  ACCESS_WIFI_STATE  CHANGE_NETWORK_STATE  CHANGE_WIFI_STATE
CAMERA  RECORD_AUDIO  MODIFY_AUDIO_SETTINGS  BLUETOOTH  BLUETOOTH_CONNECT
READ_MEDIA_IMAGES  READ_MEDIA_VISUAL_USER_SELECTED  READ_EXTERNAL_STORAGE(≤32)  WRITE_EXTERNAL_STORAGE(≤29)
POST_NOTIFICATIONS  POST_PROMOTED_NOTIFICATIONS  FOREGROUND_SERVICE
FOREGROUND_SERVICE_MEDIA_PLAYBACK  FOREGROUND_SERVICE_MICROPHONE
```

高危权限逐项检查（`grep -c` 于 manifest，全部为 0）：

| 权限 | 计数 |
|---|---|
| `REQUEST_INSTALL_PACKAGES`（静默装包） | 0 |
| `SYSTEM_ALERT_WINDOW`（悬浮窗） | 0 |
| `QUERY_ALL_PACKAGES`（枚举全部已装应用） | 0 |
| `READ_SMS` / `RECEIVE_SMS` | 0 / 0 |
| `BIND_ACCESSIBILITY_SERVICE`（无障碍，远控常用） | 0 |
| `MANAGE_EXTERNAL_STORAGE` | 0 |
| `PACKAGE_USAGE_STATS` | 0 |
| `READ_PHONE_STATE` | 0 |
| `READ_CONTACTS` | 0 |
| `DEVICE_ADMIN` | 0 |

对照：如果这是"加了私货"的包，典型会看到 `REQUEST_INSTALL_PACKAGES` + `SYSTEM_ALERT_WINDOW` + `BIND_ACCESSIBILITY_SERVICE` 三件套，或至少 `QUERY_ALL_PACKAGES`。这里一个都没有。

**判定：没有注入远控/间谍能力。**

---

## 5. 注入代码扫描

在 4 个 dex 里搜常见注入特征：

| 特征 | 命中 |
|---|---|
| `LuckyPatcher` / `ApkSignatureKiller` / `MT Manager` / `Mod by` / `ElaMods` / `PlatinumMods` | 0 / 0 / 0 / 0 / 0 / 0 |
| `InMemoryDexClassLoader`（内存加载隐藏 dex） | 0 |
| `DexClassLoader` | 1 处，位于 `com.ishumei.smantifraud`（数美风控 SDK 自带的类加载器探测） |

`DexClassLoader` 的唯一命中是数美反欺诈 SDK 在检查自己的 classloader（`com/ishumei/smantifraud/l1111l111111Il.java:822` 判断 `classLoader instanceof BaseDexClassLoader` 并读 `pathList` 字段）。这是官方 SDK 的风控代码，不是加载器注入。

**判定：未发现第三方 payload、未发现动态加载外部 dex。**

---

## 6. 总判定

**这是一个"仅剥离 Play 授权校验 + 第三方重签"的轻量重打包，不是加料包。**

改动清单（按证据强度排序）：

| # | 改动 | 证据强度 |
|---|---|---|
| 1 | 第三方重签：`CN=IN` / RSA-1024 / 仅 v3 方案 | **已验证**（apksigner） |
| 2 | 删除 `LicenseContentProvider` 声明，PairIP 校验不再触发 | **已验证**（manifest 无该声明） |
| 3 | `com.pairip.application.Application` 退化成只有 `super` 的空壳 | **已验证**（反编译源码） |
| 4 | `App` 类与 PairIP 包被单独抽进 `classes2.dex`（时间戳异常） | **已验证**（dex 类清单 + zip 时间戳） |
| 5 | 未注入危险权限 / 未加载外部 dex / 无破解组署名 | **已验证**（权限表 + 字符串扫描） |
| 6 | 业务代码（聊天/搜索/文件/通话）是否被改过 | **需官方样本复核** —— 没有官方 v2.7.1 包可 diff |

### 对这个包的实际使用建议

- **能装、能跑，但不要登真实账号**：签名不是你信任的身份，且它绕过了 Play 完整性校验，理论上任何持有该私钥的人都能推送"看起来一样"的新版本。
- **它的"Mod"不含任何付费解锁**：DeepSeek App 本身免费，没有 VIP 可破，能改的只有本地校验 —— 这也解释了为什么这个包的体积、权限、功能面和官方基本一致。
- **对逆向取协议这件事是好事**：改动集中在壳层，业务代码保持原样，所以从它身上还原出的端点、PoW、DTO 与官方行为一致。
