# NewShell

一个轻量级、低内存占用的 SSH / 终端客户端，本项目是在开源项目 meatshell 的基础上进行的二次自定义修改版本

> ## 关于本项目 · 二次自定义修改说明
>
> **本项目是在开源项目 [meatshell](https://github.com/yituorou/meatshell) 基础上进行的二次自定义修改版本。**
>
> - 上游源仓库：<https://github.com/yituorou/meatshell>
> - 本仓库地址：<https://github.com/ovoene/NewShell>
>
> 我们对原项目进行了裁剪与增强：删除了部分用不到的功能以进一步精简体积、
> 聚焦核心使用场景，同时新增了若干贴合自身使用习惯的能力。具体改动见下方
> [自定义修改内容](#自定义修改内容)。感谢原作者的开源工作。

## 截图

<p align="center">
  <img src="https://raw.githubusercontent.com/ovoene/NewShell/main/ui.png" alt="NewShell 界面" width="800"><br>
  <em>NewShell 主界面：会话管理 + 资源监控 + 多标签页终端 + SFTP 文件浏览</em>
</p>

## 自定义修改内容

相较上游 [meatshell](https://github.com/yituorou/meatshell)，本二次修改版本做了如下调整：

### 新增 / 增强

- **手动断开与连接**：会话支持手动断开、手动重新连接，连接状态由用户主动掌控，不再只能被动等待。
- **首页展示优化**：重新设计了欢迎页 / 首页的布局与信息呈现，进入更清爽、常用入口更直达。
- **自定义区域颜色**：支持自定义界面各区域（左·侧栏 / 右上·终端 / 右下·目录结构）的背景配色与透明度；每个区域还可单独设置**区域内字体颜色**，次要 / 弱化文字会由所选颜色自动派生浓淡层次。终端区的字体颜色只改变终端自身默认输入 / 输出（含独立命令输入框与其提示文字）的颜色，脚本通过 ANSI 转义序列指定的颜色不受影响。字体颜色跟随该区域的「启用」开关，关闭后恢复主题默认。
- **添加日期显示**：界面中新增日期信息展示。
- **关于页检查更新**：打开「设置 → 关于」时会自动向 GitHub Releases 查询最新版本并与当前版本比对：网络不可用则静默提示「当前网络无法检查更新」；已是最新则显示「已是最新版本」；有新版则显示最新版本号与「前往下载」按钮，点击后用系统浏览器打开 Releases 页面自行下载（不做应用内自动替换）。
- **其他细节调整**：针对交互与显示做了若干细节层面的打磨。

### 移除 / 精简

- **端口转发 / 隧道（tunnel）**：移除了本地 -L / 远程 -R / 动态 -D（SOCKS5）等端口转发能力。
- **网卡信息**：移除了资源监控中的网卡（网络接口）信息展示。
- **历史输入**：移除了命令历史 / 历史输入相关功能。
- **PowerShell 等相关功能**：移除了 PowerShell 等相关支持。

## 打包与发布（GitHub Actions）

本项目通过 GitHub Actions 自动打包。**你无需在本地安装任何编译环境**，只要把代码推到
GitHub 并打上一个 `v` 开头的版本 tag，云端就会自动构建以下两个平台的产物，并创建一个
Release 把它们挂上去：

| 平台                | 产物（zip 包）                          | 解压后内容      | 说明                                     |
| ------------------- | --------------------------------------- | --------------- | ---------------------------------------- |
| Windows x86_64      | `NewShell--windows-x86_64.exe`          | 不需要解压       | 建议放入独立的文件夹运行                   |
| macOS Apple Silicon | `NewShell--macos-arm64.zip`             | `NewShell.app`  | 原生 arm64，适用于 M1 / M2 / M3 芯片 Mac  |


工作流定义见 [`.github/workflows/release.yml`](.github/workflows/release.yml)。

### 触发条件

- **推送 `v*` 形式的 tag**（如 `v8.8.8`）→ 自动构建 **并创建 GitHub Release**，产物（zip 包）作为附件上传。
- 在 Actions 页面手动点 **Run workflow**（workflow_dispatch）→ 只构建、把产物（zip 包）作为 artifact
  上传到那次运行的页面底部，**不创建 Release**（适合试构建）。

---

### 首次打包步骤（完整流程）

> 前置条件：本机已安装 [Git](https://git-scm.com/) 和 [GitHub CLI (`gh`)](https://cli.github.com/)。

**1. 登录 GitHub（首次，一次即可）**

```bash
gh auth login
```

按提示选择 **GitHub.com → HTTPS → Login with a web browser**，复制终端给出的一次性代码，
在浏览器里粘贴登录。成功后会显示 `Logged in as <你的用户名>`。

**2. 配置 Git 身份（首次，一次即可）**

```bash
git config --global user.email "你的邮箱@example.com"
git config --global user.name  "ovoene"
```

**3. 初始化仓库并提交代码**

在项目根目录执行：

```bash
git init
git add -A
git commit -m "NewShell 初始提交"
git branch -M main
```

**4. 关联远程仓库**

若 GitHub 上还没有仓库，用 `gh` 一条命令创建并自动关联：

```bash
gh repo create ovoene/NewShell --public --source=. --remote=origin
```

若仓库已存在，则手动关联：

```bash
git remote add origin https://github.com/ovoene/NewShell.git
# 若提示 origin 已存在，改用：
# git remote set-url origin https://github.com/ovoene/NewShell.git
```

**5. 推送代码到 main 分支**

```bash
git push -u origin main
```

> - 若报 `rejected ... fetch first`（远程有你本地没有的内容，通常是建仓库时自动生成的
>   README），确认远程内容不需要保留后，用本地内容强制覆盖：
>   ```bash
>   git push -u origin main --force
>   ```
> - 若报 `Connection was reset` 等网络错误，多为访问 GitHub 不稳定，可重试几次，或为
>   Git 配置代理（把 `7890` 换成你代理软件实际的本地端口）：
>   ```bash
>   git config --global http.proxy  http://127.0.0.1:7890
>   git config --global https.proxy http://127.0.0.1:7890
>   ```
>   推送完成后如需取消代理：
>   ```bash
>   git config --global --unset http.proxy
>   git config --global --unset https.proxy
>   ```

**6. 打版本 tag 触发打包**

tag 号必须与 `Cargo.toml` 里的 `version` 一致（当前为 `8.8.8`）：

```bash
git tag v8.8.8
git push origin v8.8.8
```

推送 tag 的瞬间，GitHub Actions 就会开始构建。

**7. 查看进度与下载产物**

- 构建进度：<https://github.com/ovoene/NewShell/actions>（`windows` 与 `macos` 两个任务并行，约 5–15 分钟）
- 两个任务都打绿勾后，到 Releases 页面下载产物：<https://github.com/ovoene/NewShell/releases>

---

### 升级版本后的打包步骤

发布新版本时，**核心要求：tag 号、`Cargo.toml` 版本、`Cargo.lock` 里 `newshell` 的版本
三者必须完全一致**，否则工作流会在发布前做版本校验并直接失败。

有两种方式，**强烈推荐方式一（脚本）**，因为它会自动同步版本号、跑校验，避免手滑漏改导致
构建失败。

#### 方式一：使用发布脚本（推荐）

脚本位于 [`scripts/release.ps1`](scripts/release.ps1)，在 **Windows PowerShell** 里运行。
它会自动完成：检查工作区无未提交改动 → 同步改写 `Cargo.toml` 和 `Cargo.lock` 的版本号 →
运行 `cargo check --locked` → 校验 `newshell --version` 输出与 tag 一致 → 提交版本变更 →
创建带注释的 tag →（加 `-Push` 时）推送分支和 tag。

**一步到位（构建 + 推送）：**

```powershell
.\scripts\release.ps1 v8.8.9 -Push
```

这一条命令跑完，就等同于「改版本号 + 提交 + 打 tag + 推送」全部完成，GitHub Actions 随即开始构建。

**只在本地准备提交和 tag、稍后再手动推送：**

```powershell
.\scripts\release.ps1 v8.8.9
git push origin HEAD
git push origin v8.8.9
```

**先空跑预览会执行哪些操作、不做任何改动（排错用）：**

```powershell
.\scripts\release.ps1 v8.8.9 -DryRun
```

> 脚本参数说明：
> - 第一个参数是 tag，**必须**是 `vX.Y.Z` 或 `vX.Y.Z-后缀` 格式（如 `v8.8.9`、`v9.0.0-rc1`），否则脚本会拒绝。
> - `-Push`：创建提交和 tag 后，自动推送当前分支与 tag。
> - `-DryRun`：只打印将要执行的命令，不真正修改文件、不提交、不推送。
> - 运行前**工作区必须干净**（没有未提交或已暂存的改动），否则脚本会报错退出——先 `git commit` 或 `git stash` 处理掉。
> - 若目标 tag 已存在，脚本也会报错，需先删除旧 tag 或换一个新版本号。

#### 方式二：手动升级（不使用脚本）

如果你不用 PowerShell，也可以手动操作，但**务必记得同步三处版本号**：

```bash
# 1. 编辑 Cargo.toml，把 version = "8.8.8" 改成 version = "8.8.9"
# 2. 编辑 Cargo.lock，找到 name = "newshell" 那一段，把其下的 version 同步改成 8.8.9
#    （或运行 cargo update -p newshell 让 Cargo 自动同步 Cargo.lock）
git add Cargo.toml Cargo.lock
git commit -m "Release v8.8.9"
git tag v8.8.9
git push origin HEAD
git push origin v8.8.9
```

---

### 打包注意事项

- **版本号三处一致**：这是最常见的踩坑点。tag `v8.8.9` 就要求 `Cargo.toml`、`Cargo.lock`、
  以及构建出的 `newshell --version` 都是 `8.8.9`。用脚本可自动规避此问题。
- **tag 不可重复**：同一个 tag 名不能推两次。要重新发布同一版本，需先删除旧 tag
  （本地 `git tag -d v8.8.9`，远程 `git push origin :refs/tags/v8.8.9`）再重新打。
- **产物为 zip 包**：Windows 和 macOS 的产物都统一打成纯 ASCII 名称的 zip（内外均为
  `NewShell`），避免 Release 附件名被清洗成 `default.xxx`，也避免 zip 内非 ASCII 文件名
  在 Windows GUI 程序下静默启动失败。下载后需先解压，再按下方
  [各系统首次使用说明](#各系统首次使用说明) 操作。
- **macOS 产物为 ad-hoc 签名**（无苹果开发者证书）：用户首次打开会被 Gatekeeper 拦截，
  提示「已损坏 / 无法验证开发者」。这是正常现象，解除方法见下方 macOS 使用说明。
- **构建失败排查**：到 Actions 页面点开报红的任务，展开失败的步骤查看日志。最常见的失败原因
  就是上面第一条的「版本号不一致」。

---

## 各系统首次使用说明

### Windows（x86_64）

产物：`NewShell--windows-x86_64.exe`，下载后即可运行！ 

1. 在Release 下载 NewShell--windows-x86_64.exe。
   建议把它放到一个固定目录（如 `D:\Tools\NewShell\`）。
2. **首次运行放行 SmartScreen**：双击 `NewShell--windows-x86_64.exe`，若弹出蓝色的 **“Windows 已保护你的电脑”**
   提示，点 **“更多信息” → “仍要运行”** 即可启动。这是因为程序未做数字签名，属正常现象。
3. **浏览器下载拦截**（如遇到）：Edge / Chrome 有时会把未签名的 `.exe` 标记为
   “不常下载，可能有危险”。点下载项旁的 **“…” → 保留 / 仍然保留** 即可保住文件，不要选删除。
4. 之后每次使用直接双击 `NewShell--windows-x86_64.exe` 即可，**无需安装**。若想要开始菜单 / 桌面快捷方式，
   自行右键该 exe → **发送到 → 桌面快捷方式**。

> - 程序是自包含单文件，不写注册表、不需要管理员权限，删除时直接删掉这个 exe 即可。
> - 若杀毒软件误报（未签名的国产/小众工具常见），需在杀软里把该文件加入信任 / 白名单。

### macOS（Apple Silicon，M1 / M2 / M3 等）

产物：`NewShell--macos-arm64.zip`，解压后得到应用包 `NewShell.app`。

> ⚠️ 仅支持 Apple Silicon（arm64）芯片的 Mac。Intel 芯片的 Mac 无法运行该产物。

1. **解压**：双击 zip，Finder 会自动解压出 `NewShell.app`。
2. **移动到应用程序**：把 `NewShell.app` 拖进 **“应用程序”（Applications）** 文件夹（可选，
   但推荐，方便管理和后续命令）。
3. **首次打开会被 Gatekeeper 拦截**：因为是 ad-hoc 签名（无苹果开发者证书），直接双击可能
   提示 **“已损坏，无法打开”** 或 **“无法验证开发者”**。用以下**任一**方法放行：

   **方法 A：右键打开（最简单，无需终端）**

   在 Finder 里 **右键（或按住 Control 单击）`NewShell.app` → 打开**，在弹窗里再点一次
   **“打开”**。之后就会被系统记住，后续可直接双击。

   **方法 B：终端清除隔离属性（遇到“已损坏”时最可靠）**

   打开 **“终端”**，执行（路径按 app 实际所在位置调整）：

   ```bash
   # 如果已放进「应用程序」文件夹：
   xattr -dr com.apple.quarantine /Applications/NewShell.app
   # 如果还在「下载」文件夹里：
   # xattr -dr com.apple.quarantine ~/Downloads/NewShell.app
   ```

   然后正常双击打开，或执行 `open /Applications/NewShell.app`。

   **方法 C：从系统设置放行**

   若仍被拦截，打开 **系统设置 → 隐私与安全性**，向下滚动找到关于被拦截 App 的提示，
   点 **“仍要打开”**。

4. 放行一次后，之后就和普通 App 一样，双击 Launchpad / 应用程序里的图标即可启动。

> - 遇到 “已损坏” 提示不必惊慌，它并不代表文件真的损坏，而是 Gatekeeper 对未签名 App 的
>   统一拦截话术，用上面方法 B 清除隔离属性后即可正常运行。

## 从源码运行

```bash
cargo run --release
```

首次启动会在配置目录建立空的会话库。点击右上角 **“＋ 新建会话”** 添加第一台服务器。

## 开发提示

- Slint 控件有非常严格的布局 DSL，改 `.slint` 后 `cargo check` 是最快的
  反馈方式。
- 应用事件循环是单线程（Slint 要求），所有跨线程 UI 更新通过
  `slint::invoke_from_event_loop` 回调。
- SSH / SFTP 共享 `known_hosts` 校验逻辑：首次连接会确认并记住主机密钥，
  后续密钥变化会再次提示。

## 致谢

本项目基于开源项目 [meatshell](https://github.com/yituorou/meatshell) 二次修改而来，
感谢原作者 [@yituorou](https://github.com/yituorou) 的开源贡献。

## License

本项目沿用上游许可协议（MIT OR Apache-2.0）。作为 [NewShell](https://github.com/ovoene/NewShell)
的二次修改版本，相关版权归原作者与本项目贡献者所有。

