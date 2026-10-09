# Wireshark 极简构建（ENABLE_MINIMAL_BUILD）

面向工业协议的 Windows 精简构建：保留 GUI / `tshark` / `dumpcap`，协议集中在 MMS、GOOSE、SV、IEC 60870（101/103/104）、Modbus 及必要基础协议，目标 NSIS 安装包 **≤ 30 MB**。

相关设计见仓库根目录 [`计划.md`](../../计划.md)。

## 前置条件

| 组件 | 本机默认路径（可改） |
| --- | --- |
| VS 2022（BuildTools / Community 等）+ C++ 桌面工作负载 | `VsDevCmd.bat` 自动探测 |
| Qt 6.10.x msvc2022_64 | `C:\Development\Qt\6.10.3\msvc2022_64` |
| Wireshark 第三方库目录 | `C:\Development\wireshark-third-party` |
| NSIS（`makensis.exe`） | `C:\Development\NSIS-Tool\tools\makensis.exe` |
| Git（生成 `vcs_version.h`） | `C:\Program Files\Git\cmd` |
| CMake ≥ 3.x、Python 3 | 已在 PATH |

默认构建目录：`C:\Development\wsbuild-industrial`（与全量 `wsbuild64` 隔离）。

## 一键构建并打包

在 **cmd.exe** 中（不要依赖未初始化的 VS 环境，脚本会自行调用 `VsDevCmd`）：

```bat
cd /d F:\software\temp\wireshark-industrial
tools\minimal-build\build-industrial.bat
```

产物：

```text
C:\Development\wsbuild-industrial\packaging\nsis\宾尧-0.10.3-x64.exe
```

静默安装示例：

```bat
"C:\Development\wsbuild-industrial\packaging\nsis\宾尧-0.10.3-x64.exe" /S /desktopicon=yes
```

## 分步脚本

| 脚本 | 作用 |
| --- | --- |
| `env.bat` | 公共路径与默认值（被其它脚本调用） |
| `configure.bat` | CMake 配置，`ENABLE_MINIMAL_BUILD=ON` |
| `build.bat` | 编译 `wireshark` / `tshark` / `dumpcap`，并复制数据文件（含精简 `colorfilters`） |
| `package-nsis.bat` | `wireshark_nsis_prep` + `wireshark_nsis`，检查体积 ≤ 30 MB |
| `create-green-package.bat` | 从 staging 生成绿色免安装包（配置隔离，不写 Program Files） |
| `build-all.bat` | 依次执行 configure → build → package |
| `smoke-check.bat` | 快速验收：`-v`、协议列表、colorfilters、安装包体积 |

示例：

```bat
tools\minimal-build\configure.bat
tools\minimal-build\build.bat
tools\minimal-build\package-nsis.bat
tools\minimal-build\smoke-check.bat
```

仅增量重编并重新打安装包（已配置过）：

```bat
tools\minimal-build\build.bat
tools\minimal-build\package-nsis.bat
```

## 覆盖默认路径

在调用脚本**之前**设置环境变量即可：

```bat
set WIRESHARK_BUILD_DIR=D:\build\wsbuild-min
set WIRESHARK_BASE_DIR=D:\deps\wireshark-third-party
set CMAKE_PREFIX_PATH=D:\Qt\6.10.3\msvc2022_64
set MAKENSIS_EXECUTABLE=D:\NSIS\makensis.exe
set WIRESHARK_BUILD_CONFIG=RelWithDebInfo
set VSDEVCMD=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat
tools\minimal-build\build-all.bat
```

| 变量 | 含义 | 默认 |
| --- | --- | --- |
| `WIRESHARK_SRC_DIR` | 源码根目录 | 脚本所在仓库根 |
| `WIRESHARK_BUILD_DIR` | 构建目录 | `C:\Development\wsbuild-industrial` |
| `WIRESHARK_BASE_DIR` | 第三方库 | `C:\Development\wireshark-third-party` |
| `CMAKE_PREFIX_PATH` | Qt 前缀 | `C:\Development\Qt\6.10.3\msvc2022_64` |
| `MAKENSIS_EXECUTABLE` | makensis | `C:\Development\NSIS-Tool\tools\makensis.exe` |
| `WIRESHARK_BUILD_CONFIG` | MSVC 配置 | `RelWithDebInfo` |
| `VSDEVCMD` | VsDevCmd.bat | 自动探测 VS2022 |

## CMake 开关摘要

`configure.bat` 固定打开：

- `-DENABLE_MINIMAL_BUILD=ON`
- 关闭 Lua / SMI / 插件 / 多数编解码与压缩扩展
- 关闭绝大多数 CLI/extcap 工具；保留 `wireshark`、`tshark`、`dumpcap`
- `-DENABLE_LTO=ON`

极简构建行为要点：

- 协议保留清单：`epan/dissectors/minimal-dissectors.txt`
- GUI：去掉电话 / 无线 / 工具 / **统计** 菜单及相关入口
- 安装数据：使用 `resources/share/wireshark/colorfilters.minimal`（避免 HSRP 等缺失协议的着色告警）；默认附带 `pres_context_list`（Context Id `3` → MMS OID `1.0.9506.2.3`，无个人配置时生效）
- NSIS：`MinimalManifest` 裁剪 Qt 冗余 DLL；翻译仅 zh_CN（安装到 `translations/` 与 `languages/`）

## 手工等价命令

若不用脚本，在已加载 VS 环境的前提下：

```bat
mkdir C:\Development\wsbuild-min
cd /d C:\Development\wsbuild-min
cmake -G "Visual Studio 17 2022" -A x64 -DENABLE_MINIMAL_BUILD=ON ... <源码根>
cmake --build . --config RelWithDebInfo --target wireshark --parallel
cmake --build . --config RelWithDebInfo --target tshark --parallel
cmake --build . --config RelWithDebInfo --target dumpcap --parallel
cmake --build . --config RelWithDebInfo --target copy_data_files --parallel
cmake --build . --config RelWithDebInfo --target wireshark_nsis_prep --parallel
cmake --build . --config RelWithDebInfo --target wireshark_nsis --parallel
```

完整 `-D` 列表以 `configure.bat` 为准。

## 验收建议

1. 安装包体积 ≤ 30 MB：`smoke-check.bat` 或查看 `package-nsis.bat` 输出。
2. `tshark -G protocols`：协议数大幅下降，含 mms/goose/sv/iec60870_104/mbtcp；无 http/dns/tls/wlan/lua；stderr 无 `OOPS` / `doesn't exist`。
3. GUI：无「统计 / 电话 / 无线 / 工具」菜单；启动无 colorfilters（HSRP/Routing）告警。
4. 样本 pcap：MMS / GOOSE / SV / 104 / 103 / Modbus 可正常解剖。

## 常见问题

**`vcs_version.h` / Git KeyError**  
确保 Git 在 PATH（`env.bat` 已尝试加入 `Program Files\Git`）。

**安装包仍含完整 colorfilters**  
确认 `ENABLE_MINIMAL_BUILD=ON` 且执行了 `copy_data_files`；staging 中 `run\<Config>\colorfilters` 应与 `colorfilters.minimal` 一致且不含 `hsrp`。

**NSIS 找不到 makensis**  
设置 `MAKENSIS_EXECUTABLE` 后重新 `configure.bat`。

**与全量构建混淆**  
务必使用独立目录 `wsbuild-min`，不要复用 `wsbuild64`。

## 绿色免安装包（推荐给终端用户）

从已编译的 `run\RelWithDebInfo` 复制运行文件，并写入带 `WIRESHARK_APPDATA` 隔离的启动脚本，**不安装、不改注册表、不占用已安装 Wireshark 的配置目录**：

```bat
cd /d F:\software\temp\wireshark-industrial
tools\minimal-build\create-green-package.bat
```

默认产物（包名使用 ASCII，避免中文路径乱码）：

```text
C:\Development\Binyao-0.10.3-green\          ← 解压即用目录
C:\Development\Binyao-0.10.3-green.zip
```

双击目录内 `Run.bat` 即可运行。可用 `WIRESHARK_GREEN_DIR` 覆盖输出路径；加 `-NoZip` 可只生成目录。

注意：实时抓包仍需目标机已安装 Npcap；分析现有 pcap 不需要。

## 一键汇总整包（空白机可编译打包 + GitHub 提交）

将安装包、运行目录、**带可搬迁 `.git` 的源码**、Qt/第三方库/NSIS、便携 Git/Python/CMake、VS 引导安装器、构建脚本汇总到单一目录（约 5 GB+；FullGit 会再加大）。

在开发机上生成：

```bat
cd /d F:\software\temp\wireshark-industrial
tools\minimal-build\create-bundle.bat
```

可选参数（传给 `make-bundle.ps1`）：

| 参数 | 含义 |
| --- | --- |
| （默认） | 嵌入**完整** Git 历史，便于迁机后 `commit` / `push` |
| `-ShallowGit` | 浅克隆（depth≈100），体积更小 |
| `-SkipInstaller` | 尚未打出 NSIS 时跳过 `01-installer` |

或：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\minimal-build\make-bundle.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tools\minimal-build\make-bundle.ps1 -ShallowGit
```

默认输出：`C:\Development\Wireshark-Industrial-Bundle-0.10.3\`

| 目录 | 内容 |
| --- | --- |
| `01-installer\` | NSIS 安装包 + Npcap/USBPcap |
| `02-runtime\` | 免安装运行目录 |
| `03-source\wireshark\` | 源码 + 便携 `.git`（含 `github` / `origin` remote） |
| `04-compile-env\` | Qt、third-party、NSIS、Git、Python、CMake、`vs_BuildTools.exe` |
| `05-scripts\` | `use-bundle-env` / `build-all-from-bundle` / `DEV` / `setup-github` |
| `06-build\` | 目标机编译输出（首次构建时创建） |

### 迁到空白机：编译出安装包

1. 整目录拷贝到目标机（建议 ASCII 路径，如 `D:\Binyao-SDK`）
2. 双击根目录 `SETUP.bat`（需管理员 + 网络，首次装 VS Build Tools 约 10–30 分钟）
3. 或手动：`04-compile-env\install-vs-buildtools.bat` → `BUILD.bat` / `05-scripts\build-all-from-bundle.bat`
4. 安装包：`06-build\wsbuild-industrial\packaging\nsis\*.exe`

### 迁到空白机：开发并 push 到 GitHub

1. 双击 `DEV.bat`（进入 `03-source\wireshark`，PATH 含便携 Git）
2. 双击 `setup-github.bat`：配置 `user.name` / `user.email`，并在**本机**完成登录（`gh auth login` / HTTPS PAT / SSH）。**凭据不会打进整包。**
3. 修改后：`git add` → `git commit` → `git push -u github HEAD`
4. remote `github` 指向工业仓库；`origin` 多为上游 `wireshark/wireshark`，勿误推

### 体积与限制

- 主要占用：Qt ~2.4 GB + third-party ~0.6 GB + 工具与源码/.git
- VS **不能**整棵目录搬迁，仅提供官方引导安装器；目标机需联网安装
- Npcap 安装多为交互式；分析现有 pcap 可不装 Npcap
- 不打包 GitHub token / SSH 私钥

可用环境变量：`WIRESHARK_BUNDLE_DIR`、`WIRESHARK_SRC_DIR`、`WIRESHARK_BUILD_DIR`、`BUNDLE_GIT_SRC`、`BUNDLE_PYTHON_SRC`、`BUNDLE_CMAKE_SRC`。
