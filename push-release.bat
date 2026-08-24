@echo off
rem ============================================================================
rem  NewShell 一键发布脚本
rem ----------------------------------------------------------------------------
rem  做的事（按顺序）：
rem    1. 读你输入的【版本号】和【build 日期】
rem    2. 把版本号同步写进 Cargo.toml + Cargo.lock，把 build 日期写进 src/app.rs
rem       的 BUILD_LABEL —— 就是「关于」对话框和左下角页脚显示的那个日期
rem       —— 必须同步！.github/workflows/release.yml 里产物文件名取的是
rem          Cargo.toml 的 version，不是 tag。忘了改就会打出
rem          NewShell-8.8.12-windows-x86_64.exe 这种版本号不对的包。
rem    3. git add -A + commit
rem    4. 打带注释的 tag（注释里写上 build 日期）
rem    5. push 分支 + push tag  ——  tag 一推上去 GitHub Actions 就开始云端
rem       打包 Windows exe 和 macOS zip
rem
rem  用法：
rem    直接双击                         → 全部交互式输入
rem    push-release.bat 8.8.13          → 版本号给了，其余问
rem    push-release.bat 8.8.13 2026-08-24
rem    push-release.bat 8.8.13 2026-08-24 "新增：诊断日志开关"
rem
rem  版本号写 8.8.13 或 v8.8.13 都行，脚本自己处理。
rem
rem  注意（重要）：
rem    * 本文件是 GBK / ANSI 编码，不是 UTF-8。用记事本改完请选「ANSI」保存，
rem      VS Code 右下角要选 GB2312/GBK。存成 UTF-8 的话，cmd.exe 在 chcp 65001
rem      下读批处理有个老 bug：会在缓冲区边界把多字节汉字切断，于是下面这些中文
rem      注释和提示会被当成命令执行，满屏「不是内部或外部命令」。这不是玄学，
rem      是实测出来的，别改编码。
rem    * 行尾必须是 CRLF。同理，LF 结尾的 .bat 也会被 cmd 切错行。
rem    * 提交说明里不要打英文双引号和百分号，cmd 的引号配对和变量展开会被搞乱。
rem    * 远端是 HTTPS，push 时如果 Windows 凭据管理器里没存 GitHub 凭据，
rem      会弹窗要账号密码 / token，属正常。
rem ============================================================================

chcp 936 >nul 2>&1
setlocal EnableExtensions DisableDelayedExpansion
title NewShell 一键发布

rem 切到脚本所在目录（放在仓库根目录），这样双击运行也不看当前工作目录是哪
cd /d "%~dp0"

set "PS=powershell -NoProfile -ExecutionPolicy Bypass -Command"
set "ARG_VER=%~1"
set "ARG_DATE=%~2"
set "ARG_MSG=%~3"

echo.
echo ================================================================
echo   NewShell 发布  --  提交 + 打 tag + 推送 GitHub
echo ================================================================
echo.

rem ---------------------------------------------------------------- 环境检查
where git >nul 2>&1
if errorlevel 1 (
    echo [错误] 找不到 git，请先装 Git for Windows 并确认它在 PATH 里。
    goto :die
)

git rev-parse --is-inside-work-tree >nul 2>&1
if errorlevel 1 (
    echo [错误] 这个目录不是 git 仓库：%CD%
    echo        请把本脚本放在仓库根目录（和 Cargo.toml 同一层）。
    goto :die
)

rem 无论脚本是被双击、还是被绝对路径/快捷方式/计划任务拉起来，都先站到仓库根目录。
rem 后面所有 git 命令和文件改写都以这里为基准。
for /f "usebackq delims=" %%i in (`git rev-parse --show-toplevel`) do set "GITROOT=%%i"
if not defined GITROOT (
    echo [错误] 拿不到仓库根目录。
    goto :die
)
cd /d "%GITROOT%"

if not exist "Cargo.toml" (
    echo [错误] 仓库根目录里没有 Cargo.toml：%CD%
    goto :die
)

rem 把要改的目录固定下来，显式传给 PowerShell。
rem 不用 PowerShell 的 Get-Location —— 它继承的是调用方的工作目录，万一 cd 没生效
rem 就会静默地去改另一个仓库的 Cargo.toml。写死成这里验证过 Cargo.toml 的那个目录。
set "NS_REPO=%CD%"

for /f "usebackq delims=" %%i in (`git rev-parse --abbrev-ref HEAD`) do set "BRANCH=%%i"
for /f "usebackq delims=" %%i in (`git config --get remote.origin.url`) do set "REMOTE=%%i"
rem 传给 PowerShell 用环境变量，省掉一层引号转义的坑
set "NS_REMOTE=%REMOTE%"

if not defined REMOTE (
    echo [错误] 没有配置 origin 远端。先执行：
    echo        git remote add origin https://github.com/ovoene/NewShell.git
    goto :die
)

rem ---------------------------------------------------------------- 版本号
if defined ARG_VER goto :have_ver
:ask_ver
for /f "usebackq delims=" %%i in (`%PS% "((Get-Content -LiteralPath (Join-Path $env:NS_REPO 'Cargo.toml')) -match '^version')[0] -replace '[^0-9.]',''"`) do set "CUR_VER=%%i"
echo Cargo.toml 里当前版本号：%CUR_VER%
set /p "ARG_VER=请输入新版本号（例 8.8.13，直接回车沿用 %CUR_VER%）: "
if not defined ARG_VER set "ARG_VER=%CUR_VER%"

:have_ver
rem 去掉可能带的前缀 v / V，统一成 8.8.13 的形式
set "VERSION=%ARG_VER%"
if /i "%VERSION:~0,1%"=="v" set "VERSION=%VERSION:~1%"
set "NS_VERSION=%VERSION%"

for /f "usebackq delims=" %%i in (`%PS% "if ($env:NS_VERSION -match '^[0-9]+\.[0-9]+\.[0-9]+[-.0-9A-Za-z]*$') { 'OK' } else { 'BAD' }"`) do set "CHK=%%i"
if not "%CHK%"=="OK" (
    echo [错误] 版本号格式不对：%ARG_VER%
    echo        应形如 8.8.13 或 v8.8.13 或 8.8.13-beta.1
    goto :die
)
set "TAG=v%VERSION%"

rem ---------------------------------------------------------------- build 日期
for /f "usebackq delims=" %%i in (`%PS% "Get-Date -Format yyyy-MM-dd"`) do set "TODAY=%%i"
if defined ARG_DATE goto :have_date
set /p "ARG_DATE=请输入 build 日期（YYYY-MM-DD，直接回车用今天 %TODAY%）: "
if not defined ARG_DATE set "ARG_DATE=%TODAY%"

:have_date
set "NS_DATE=%ARG_DATE%"
for /f "usebackq delims=" %%i in (`%PS% "if ($env:NS_DATE -match '^[0-9]{4}-[0-9]{2}-[0-9]{2}$') { 'OK' } else { 'BAD' }"`) do set "CHK=%%i"
if not "%CHK%"=="OK" (
    echo [错误] 日期格式不对：%ARG_DATE%    应形如 2026-08-24
    goto :die
)
set "BUILD_DATE=%ARG_DATE%"
rem BUILD_LABEL 原本就是点号写法（Build 2026.08.11），沿用它，别改成横杠。
set "DOT_DATE=%BUILD_DATE:-=.%"

rem ---------------------------------------------------------------- 提交说明
if defined ARG_MSG goto :have_msg
echo.
echo 提交说明留空则用: Release %TAG% (build %BUILD_DATE%)
set /p "ARG_MSG=请输入提交说明: "
if not defined ARG_MSG set "ARG_MSG=Release %TAG% (build %BUILD_DATE%)"

:have_msg
set "COMMIT_MSG=%ARG_MSG%"
rem 同一份说明，留一个给 PowerShell 用的环境变量（见下面 [3/5] 的编码说明）。
set "NS_MSG=%ARG_MSG%"

rem ---------------------------------------------------------------- 确认清单
for /f "usebackq delims=" %%i in (`%PS% "((Get-Content -LiteralPath (Join-Path $env:NS_REPO 'Cargo.toml')) -match '^version')[0] -replace '[^0-9.]',''"`) do set "CUR_VER=%%i"
for /f "usebackq delims=" %%i in (`%PS% "$q=[char]34; $m=[regex]::Match([System.IO.File]::ReadAllText((Join-Path $env:NS_REPO 'src/app.rs')), ('BUILD_LABEL[^' + $q + ']*' + $q + '([^' + $q + ']*)' + $q)); if ($m.Success) { $m.Groups[1].Value } else { '(找不到)' }"`) do set "CUR_LABEL=%%i"
set /a CHANGED=0
for /f "usebackq delims=" %%i in (`git status --porcelain`) do set /a CHANGED+=1

echo.
echo ----------------------------------------------------------------
echo   仓库      : %CD%
echo   远端      : %REMOTE%
echo   分支      : %BRANCH%
echo   待提交    : %CHANGED% 个文件改动（改完版本号和日期还会多 3 个）
echo   版本号    : %CUR_VER%  --^>  %VERSION%   (会同步写入 Cargo.toml + Cargo.lock)
echo   Tag       : %TAG%
echo   build 日期: %CUR_LABEL%  --^>  Build %DOT_DATE%
echo               (写进 src/app.rs 的 BUILD_LABEL：关于对话框 + 左下角页脚 + 解锁窗口标题)
echo   提交说明  : %COMMIT_MSG%
echo ----------------------------------------------------------------
echo.
echo   1 = 完整发布（改版本号 + 提交 + 打 tag + 推送，会触发云端打包）
echo   2 = 只在本地做（改版本号 + 提交 + 打 tag，不推送）
echo   3 = 取消
echo.
set /p "MODE=请选择 [1/2/3]: "
rem 顺手抹掉空格：手滑打成 "2 " 的话，下面的 == 比较会不相等，然后莫名其妙走到取消。
if defined MODE set "MODE=%MODE: =%"
if "%MODE%"=="1" goto :go
if "%MODE%"=="2" goto :go
echo 已取消，什么都没有改动。
goto :done

rem ---------------------------------------------------------------- tag 冲突
:go
git rev-parse -q --verify "refs/tags/%TAG%" >nul 2>&1
if errorlevel 1 goto :tag_free
echo.
echo [提醒] 本地已经存在 tag %TAG%。
set /p "RETAG=删除本地和远端的旧 tag，然后重新打? [y/N] "
if defined RETAG set "RETAG=%RETAG: =%"
if /i not "%RETAG%"=="y" (
    echo 已取消。换一个版本号再来，或者手动处理这个 tag。
    goto :done
)
git tag -d "%TAG%"
if errorlevel 1 goto :fail
if "%MODE%"=="1" (
    echo 删除远端旧 tag %TAG% ...
    git push origin ":refs/tags/%TAG%"
    rem 远端本来就没有这个 tag 时这里会报错，不算致命，继续
)

:tag_free

rem ---------------------------------------------------------------- 1) 写版本号
echo.
echo [1/5] 写入版本号和 build 日期 (Cargo.toml / Cargo.lock / src/app.rs) ...
set "NS_VERSION=%VERSION%"
%PS% "$ErrorActionPreference='Stop'; $q=[char]34; $v=$env:NS_VERSION; $enc=New-Object System.Text.UTF8Encoding $false; $p=Join-Path $env:NS_REPO 'Cargo.toml'; $t=[System.IO.File]::ReadAllText($p); $re=New-Object System.Text.RegularExpressions.Regex ('(?m)^version\s*=\s*' + $q + '[^' + $q + ']*' + $q); $n=$re.Replace($t, ('version = ' + $q + $v + $q), 1); if ($n -notmatch ('(?m)^version\s*=\s*' + $q + [regex]::Escape($v) + $q)) { throw 'Cargo.toml 的 [package] version 没能改成 ' + $v }; if ($n -ne $t) { [System.IO.File]::WriteAllText($p, $n, $enc); Write-Host ('      Cargo.toml -> ' + $v) } else { Write-Host ('      Cargo.toml 已经是 ' + $v + '，跳过') }; $p2=Join-Path $env:NS_REPO 'Cargo.lock'; if (Test-Path -LiteralPath $p2) { $t2=[System.IO.File]::ReadAllText($p2); $re2=New-Object System.Text.RegularExpressions.Regex ('(?m)^(name\s*=\s*' + $q + 'newshell' + $q + '\r?\nversion\s*=\s*)' + $q + '[^' + $q + ']*' + $q); $n2=$re2.Replace($t2, ('${1}' + $q + $v + $q), 1); if ($n2 -eq $t2 -and $t2 -notmatch ('(?m)^name\s*=\s*' + $q + 'newshell' + $q + '\r?\nversion\s*=\s*' + $q + [regex]::Escape($v) + $q)) { throw 'Cargo.lock 里 newshell 的 version 没能改成 ' + $v }; if ($n2 -ne $t2) { [System.IO.File]::WriteAllText($p2, $n2, $enc); Write-Host ('      Cargo.lock -> ' + $v) } else { Write-Host ('      Cargo.lock 已经是 ' + $v + '，跳过') } }"
if errorlevel 1 (
    echo [错误] 版本号写入失败，仓库没有被提交，可以放心重来。
    goto :die
)

rem build 日期写进 src/app.rs 的 BUILD_LABEL。那一个常量同时喂三个地方：
rem   * 左下角侧边栏页脚   ui/sidebar.slint       "NewShell 新の世界 " + app-version
rem   * 关于对话框标题右边 ui/app.slint           app-version
rem   * 解锁窗口的标题栏   ui/unlock_window.slint build-label
rem 所以改这一行，三处一起变，不用碰 .slint。
%PS% "$ErrorActionPreference='Stop'; $q=[char]34; $lab='Build ' + $env:NS_DATE.Replace('-','.'); $enc=New-Object System.Text.UTF8Encoding $false; $p=Join-Path $env:NS_REPO 'src/app.rs'; $t=[System.IO.File]::ReadAllText($p); $re=New-Object System.Text.RegularExpressions.Regex ('(?m)^(pub\(crate\) const BUILD_LABEL[^' + $q + ']*' + $q + ')[^' + $q + ']*' + $q); if (-not $re.IsMatch($t)) { throw 'src/app.rs 里找不到 BUILD_LABEL 那一行，别的都没动，直接重来' }; $n=$re.Replace($t, ('${1}' + $lab + $q), 1); if ($n -eq $t) { Write-Host ('      src/app.rs BUILD_LABEL 已经是 ' + $lab + '，跳过') } else { [System.IO.File]::WriteAllText($p, $n, $enc); Write-Host ('      src/app.rs BUILD_LABEL -> ' + $lab + '   (关于 / 左下角)') }"
if errorlevel 1 (
    echo [错误] build 日期写入 src/app.rs 失败。版本号可能已经改了但还没提交，
    echo        git status / git diff 看一眼，或者 git checkout -- Cargo.toml Cargo.lock 撤销。
    goto :die
)

rem ---------------------------------------------------------------- 2) 提交
echo.
echo [2/5] git add -A ...
git add -A
if errorlevel 1 goto :fail

echo [3/5] git commit ...
git diff --cached --quiet
if not errorlevel 1 (
    echo       暂存区是空的，没有需要提交的改动，跳过 commit。
    goto :do_tag
)
rem 提交说明先用 UTF-8 写成临时文件，再 git commit -F 读进来。
rem 为什么不直接 git commit -m "%COMMIT_MSG%"：git.exe 是按 ANSI（这里就是 GBK）读命令行
rem 参数的，中文说明会以 GBK 字节存进提交对象，GitHub 网页上看就是一片乱码。cmd 里的环境
rem 变量本身是 Unicode，交给 PowerShell 转成 UTF-8 落盘，中文才是对的。实测出来的。
set "MSGFILE=%TEMP%\newshell-commit-msg.txt"
set "NS_MSGFILE=%MSGFILE%"
%PS% "$ErrorActionPreference='Stop'; $enc=New-Object System.Text.UTF8Encoding $false; [System.IO.File]::WriteAllText($env:NS_MSGFILE, ($env:NS_MSG + [char]10), $enc)"
if errorlevel 1 (
    echo [错误] 写不出临时提交说明文件：%MSGFILE%
    goto :die
)
git commit --cleanup=whitespace -F "%MSGFILE%"
if errorlevel 1 (
    del "%MSGFILE%" >nul 2>&1
    goto :fail
)
del "%MSGFILE%" >nul 2>&1

rem ---------------------------------------------------------------- 3) 打 tag
:do_tag
echo.
echo [4/5] 打 tag %TAG% ...
git tag -a "%TAG%" -m "Release %TAG%" -m "Build date: %BUILD_DATE%"
if errorlevel 1 goto :fail

rem ---------------------------------------------------------------- 4) 推送
if "%MODE%"=="2" goto :local_only

echo.
echo [5/5] 推送分支和 tag ...
git push origin HEAD
if errorlevel 1 goto :push_failed
git push origin "%TAG%"
if errorlevel 1 goto :push_failed

for /f "usebackq delims=" %%i in (`%PS% "($env:NS_REMOTE -replace '\.git$','')"`) do set "WEB=%%i"

echo.
echo ================================================================
echo   完成：%TAG%  (build %BUILD_DATE%) 已推送
echo ================================================================
echo   云端打包进度  : %WEB%/actions
echo   打完的安装包  : %WEB%/releases/tag/%TAG%
echo.
echo   Windows 和 macOS 两个 job 并行跑，通常十几分钟。
echo   产物名会是 NewShell-%VERSION%-windows-x86_64.exe
echo             NewShell-%VERSION%-macos-arm64.zip
goto :done

rem ---------------------------------------------------------------- 收尾分支
:local_only
echo.
echo ================================================================
echo   本地已就绪，尚未推送
echo ================================================================
echo   想推送的话执行这两条：
echo       git push origin HEAD
echo       git push origin %TAG%
echo   不想要了就撤销：
echo       git tag -d %TAG%
echo       git reset --soft HEAD~1
goto :done

:push_failed
echo.
echo [错误] 推送失败。提交和 tag 都已经在本地了，修好网络/凭据后补推即可：
echo        git push origin HEAD
echo        git push origin %TAG%
echo.
echo 常见原因：
echo   - 远端有别人的新提交，需要先 git pull --rebase
echo   - 远端已存在同名 tag，先 git push origin :refs/tags/%TAG%
echo   - 凭据过期，Windows 凭据管理器里删掉 github.com 那条再重试
goto :die

:fail
echo.
echo [错误] 上一条 git 命令失败了（错误码 %errorlevel%），已停在这里。
echo        用 git status 看一眼当前状态。
goto :die

:die
echo.
pause
endlocal
exit /b 1

:done
echo.
pause
endlocal
exit /b 0
