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

默认构建目录：`C:\Development\wsbuild-min`（与全量 `wsbuild64` 隔离）。

## 一键构建并打包

在 **cmd.exe** 中（不要依赖未初始化的 VS 环境，脚本会自行调用 `VsDevCmd`）：

```bat
cd /d F:\software\temp\wireshark
tools\minimal-build\build-all.bat
```

产物：

```text
C:\Development\wsbuild-min\packaging\nsis\Wireshark-4.7.4-x64.exe
```

静默安装示例：

```bat
"C:\Development\wsbuild-min\packaging\nsis\Wireshark-4.7.4-x64.exe" /S /desktopicon=yes
```

## 分步脚本

| 脚本 | 作用 |
| --- | --- |
| `env.bat` | 公共路径与默认值（被其它脚本调用） |
| `configure.bat` | CMake 配置，`ENABLE_MINIMAL_BUILD=ON` |
| `build.bat` | 编译 `wireshark` / `tshark` / `dumpcap`，并复制数据文件（含精简 `colorfilters`） |
| `package-nsis.bat` | `wireshark_nsis_prep` + `wireshark_nsis`，检查体积 ≤ 30 MB |
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
| `WIRESHARK_BUILD_DIR` | 构建目录 | `C:\Development\wsbuild-min` |
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
- NSIS：`MinimalManifest` 裁剪 Qt 冗余 DLL；翻译仅 zh_CN + en

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
