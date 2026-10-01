; Chinese (Simplified) UI strings for ENABLE_MINIMAL_BUILD NSIS installer.
; Included from wireshark.nsi when ENABLE_MINIMAL_BUILD is defined.

!define WS_ZH_BRANDING "Wireshark${U+00ae} 安装程序"

!define WS_ZH_WELCOME_TEXT "本向导将引导您安装 ${PROGRAM_NAME}。$\r$\n$\r$\n开始安装前，请确认 ${PROGRAM_NAME} 未在运行。$\r$\n$\r$\n单击“下一步”继续。"
!define WS_ZH_LICENSE_TOP "Wireshark 基于 GNU 通用公共许可证（GPL）发布。"
!define WS_ZH_LICENSE_BOTTOM "本页不是最终用户许可协议（EULA），仅供参考。"
!define WS_ZH_LICENSE_BUTTON "已知晓"
!define WS_ZH_FINISH_README "打开发行说明"
!define WS_ZH_UNCONFIRM_TOP "即将卸载以下 ${PROGRAM_NAME} 安装。单击“下一步”继续。"

!define WS_ZH_COMPONENT_TEXT "下列组件可供安装。"
!define WS_ZH_DIR_TEXT "请选择 ${PROGRAM_NAME} 的安装目录。"

!define WS_ZH_CERT_HEADER "您是否在专业环境中使用 Wireshark？"
!define WS_ZH_CERT_SUBHEADER "了解 Wireshark 认证分析师（WCA）"

!define WS_ZH_NPCAP_HEADER "数据包捕获"
!define WS_ZH_NPCAP_SUBHEADER "捕获实时网络数据需要安装 Npcap。"

!define WS_ZH_USBPCAP_HEADER "USB 捕获"
!define WS_ZH_USBPCAP_SUBHEADER "捕获 USB 流量需要 USBPcap。是否安装 USBPcap（实验性）？"

!define WS_ZH_SEC_WIRESHARK "主界面网络协议分析程序。"
!define WS_ZH_SEC_TSHARK "基于文本的网络协议分析程序。"

!define WS_ZH_UN_SEC_UNINSTALL "卸载全部 ${PROGRAM_NAME} 组件。"
!define WS_ZH_UN_SEC_PLUGINS "卸载全部全局插件（包括旧版本）。"
!define WS_ZH_UN_SEC_PROFILES "卸载全部全局配置配置文件。"
!define WS_ZH_UN_SEC_GLOBAL "卸载全局设置，例如：$INSTDIR\cfilters"
!define WS_ZH_UN_SEC_PERSONAL "删除个人配置目录：$APPDATA\${PROGRAM_NAME}。"
!define WS_ZH_UN_SEC_NPCAP "调用 Npcap 卸载程序。"
!define WS_ZH_UN_SEC_USBPCAP "调用 USBPcap 卸载程序。"

; InstallOptions page filenames
!define WS_CERT_PAGE_INI "CertificationPage-zh.ini"
!define WS_NPCAP_PAGE_INI "NpcapPage-zh.ini"
!define WS_USBPCAP_PAGE_INI "USBPcapPage-zh.ini"

; Dynamic Npcap page strings (myShowCallback)
!define WS_ZH_NPCAP_INSTALL "安装 Npcap ${NPCAP_PACKAGE_VERSION}"
!define WS_ZH_NPCAP_NONE "均未安装"
!define WS_ZH_NPCAP_NONE_HINT "（请先通过“添加/删除程序”卸载任何未被检测到的旧版 Npcap 或 WinPcap）"
!define WS_ZH_NPCAP_CURRENT "当前已安装的 Npcap 版本"
!define WS_ZH_NPCAP_MANUAL_UNINSTALL "如需安装 Npcap，请先手动卸载 $NPCAP_NAME。"
!define WS_ZH_NPCAP_WINPCAP_HINT "将先卸载当前已安装的 $WINPCAP_NAME。"
!define WS_ZH_NPCAP_OLD_HINT_VER "将先卸载当前已安装的 Npcap $NPCAP_DISPLAY_VERSION。"
!define WS_ZH_NPCAP_OLD_HINT_NAME "将先卸载当前已安装的 $NPCAP_NAME。"

; Dynamic USBPcap page strings
!define WS_ZH_USBPCAP_INSTALL "安装 USBPcap ${USBPCAP_PACKAGE_VERSION}"
!define WS_ZH_USBPCAP_NONE "当前未安装 USBPcap"
!define WS_ZH_USBPCAP_NONE_HINT "（请先通过“添加/删除程序”卸载任何未被检测到的旧版 USBPcap）"
!define WS_ZH_USBPCAP_MANUAL_UNINSTALL "如需安装 USBPcap ${USBPCAP_PACKAGE_VERSION}，请先手动卸载 $USBPCAP_NAME。"

!define WS_ZH_UN_SEC_NAME_UNINSTALL "un.卸载"
!define WS_ZH_UN_SEC_NAME_PLUGINS "un.卸载全局插件"
!define WS_ZH_UN_SEC_NAME_PROFILES "un.卸载全局配置文件"
!define WS_ZH_UN_SEC_NAME_GLOBAL "un.卸载全局设置"
!define WS_ZH_UN_SEC_NAME_PERSONAL "un.删除个人设置"
!define WS_ZH_UN_SEC_NAME_NPCAP "un.卸载 Npcap"
!define WS_ZH_UN_SEC_NAME_USBPCAP "un.卸载 USBPcap"

!define WS_ZH_MSG_ALREADY_INSTALLED "$OLD_DISPLAYNAME 已安装。$\n$\n是否先卸载？"
!define WS_ZH_MSG_WIX_ALREADY "$WIX_DISPLAYNAME $WIX_DISPLAYVERSION (msi) 已安装。$\n$\n是否先卸载？"
!define WS_ZH_MSG_REMOVE_FAILED "无法删除 $INSTDIR。"
!define WS_ZH_MSG_EXE_IN_USE "$EXECUTABLE.exe 无法删除，可能正在使用中。"
