# 私有 APCI 头部抽取

每个厂商连续 `buf[i++]` 赋值序列，长度即推断出的头部字节数。

## ABB103  (38 字节, 来自 Rtu.cpp)
```
00: 0x68
01: 0x0D
02: 0x0D
03: 0x68
04: (BYTE)(0x53 | m_FCB<<5)   // 功能类型，即控制域
05: m_btAddr   // 地址
06: 0x15
07: 0x81
08: 0x2A
09: m_btAddr
10: 0xFE   // 功能类型
11: 0xF1   // 信息序号
12: 0x00
13: 0x01
14: (BYTE)type   // 组号
15: 0x01   // 条目号
16: 0x01   // KOD
17: CheckSum(&m_pSend->buf[4],13)
18: 0x16
19: 0x68
20: 0x0D
21: 0x0D
22: 0x68
23: (BYTE)(0x53 | m_FCB<<5)   // 功能类型，即控制域
24: m_btAddr   // 地址
25: 0x15
26: 0x81
27: 0x2A
28: m_btAddr
29: 0xFE   // 功能类型
30: 0xF1   // 信息序号
31: 0x00
32: 0x01
33: (BYTE)type   // 组号
34: 0x00   // 条目号
35: 0x01   // KOD
36: CheckSum(&m_pSend->buf[4],13)
37: 0x16
```
## ABB_COM_101  (6 字节, 来自 Com103.cpp)
```
00: 0x10   // 起始符
01: 0x49   // 控制码
02: m_btAddr1   // 地址码
03: m_btAddr   // 地址码
04: CheckSum(&m_pSend->buf[1],2)   // 校验码
05: 0x16   // 结束符
```
## ALSTOM_103_COM  (29 字节, 来自 Packet.cpp)
```
00: 0x90   // 0xEB90
01: 0xEB
02: (BYTE) ((LOWORD(DWPacketLong)) % 256)   // 数据长度
03: (BYTE) ((LOWORD(DWPacketLong)) / 256)
04: (BYTE) ((HIWORD(DWPacketLong)) % 256)
05: (BYTE) ((HIWORD(DWPacketLong)) / 256)
06: 0x90   // 0xEB90
07: 0xEB
08: 0x00   // 源厂站号
09: 0x00
10: 0x00   // 源地址
11: 0x00
12: 0x00   // 目标厂站号
13: 0x00
14: m_btSourceAddr   // 目标地址
15: 0x00   // 目标地址
16: 0x00
17: (BYTE) iPacketType   // 报文类型0--103报文  3--心跳报文
18: 0x00
19: 0x00   // 数据编号
20: 0x00
21: 0xFF   // 保留字节
22: 0xFF
23: 0xFF
24: 0xFF
25: 0xFF
26: 0xFF
27: 0xFF
28: 0xFF
```
## ASCII  (15 字节, 来自 Rtu.cpp)
```
00: 'C'
01: 'E'
02: 'V'
03: ' '   // 故障号(1...40)
04: ' '
05: 'L'   // 采样类型：每周波16个采样点
06: 0x0D
07: 0x0D   // 采样类型：每周波4个采样点等
08: 'E'
09: 'V'
10: 'E'
11: ' '   // 故障号(1...40)
12: ' '
13: 'C'   // 采样类型：每周波16个采样点
14: 0x0D
```
## BP103  (38 字节, 来自 Rtu.cpp)
```
00: 0x68
01: 0x0D
02: 0x0D
03: 0x68
04: (BYTE)(0x53 | (m_FCB<<5))   // 功能类型，即控制域
05: m_btAddr   // 地址
06: 0x18   // asdu类型,用ASDU24
07: 0x81
08: 0x1F
09: m_btAddr
10: 0xFF   // 功能类型
11: 0x00   // 信息序号
12: (BYTE)CmdType   // 命令类型
13: (BYTE)type   // 扰动值的类型
14: (BYTE)(SoeNo%256)   // 故障序号
15: (BYTE)(SoeNo/256)   // 故障序号
16: (BYTE)ChaNo   // 实际通道序号
17: CheckSum(&m_pSend->buf[4],13)
18: 0x16
19: 0x68
20: 0x0D
21: 0x0D
22: 0x68
23: (BYTE)(0x53 | (m_FCB<<5))   // 功能类型，即控制域
24: m_btAddr   // 地址
25: 0x19   // asdu类型,用ASDU25
26: 0x81
27: 0x1F
28: m_btAddr
29: 0xFF   // 功能类型
30: 0x00   // 信息序号
31: (BYTE)CmdType   // 命令类型
32: (BYTE)type   // 扰动值的类型
33: (BYTE)(SoeNo%256)   // 故障序号
34: (BYTE)(SoeNo/256)   // 故障序号
35: (BYTE)ChaNo   // 实际通道序号
36: CheckSum(&m_pSend->buf[4],13)
37: 0x16
```
## DGT801  (12 字节, 来自 Rtu.cpp)
```
00: 0xFF
01: 0x3E
02: 0x07
03: IntToBCD(time.wYear%100)
04: IntToBCD(time.wYear/100)
05: IntToBCD(time.wMonth)
06: IntToBCD(time.wDay)
07: IntToBCD(time.wHour)
08: IntToBCD(time.wMinute)
09: IntToBCD(time.wSecond)
10: btLCrc
11: btHCrc
```
## FH_3000_TCP  (28 字节, 来自 Packet.cpp)
```
00: 0x68
01: 0x16
02: 0x00
03: 0x68
04: (BYTE)(0x53 | (m_FCB<<5))   // 功能类型，即控制域
05: m_iSourceAddr   // 地址
06: 0x0F   // asdu类型
07: 0x81   // 可变结构限定词
08: 0x00   // 传输原因
09: m_iSourceAddr   // 单元公共地址
10: 0xFF   // 功能类型
11: 0x00   // INF见装置的相应信息表信息序号
12: (start_time.wMilliseconds+start_time.wSecond*1000)%256
13: (start_time.wMilliseconds+start_time.wSecond*1000)/256
14: start_time.wMinute
15: start_time.wHour
16: start_time.wDay
17: start_time.wMonth
18: start_time.wYear-1900
19: (end_time.wMilliseconds+end_time.wSecond*1000)%256
20: (end_time.wMilliseconds+end_time.wSecond*1000)/256
21: end_time.wMinute
22: end_time.wHour
23: end_time.wDay
24: end_time.wMonth
25: end_time.wYear-1900
26: CheckSum(&m_pSendBuff->buf[4], 22)
27: 0x16
```
## FH_LR12_COM  (12 字节, 来自 DFR.cpp)
```
00: StartTime.wYear - 1980
01: StartTime.wMonth
02: StartTime.wDay
03: StartTime.wHour
04: StartTime.wMinute
05: StartTime.wSecond   // 查询文件的结束时间
06: EndTime.wYear - 1980
07: EndTime.wMonth
08: EndTime.wDay
09: EndTime.wHour
10: EndTime.wMinute
11: EndTime.wSecond
```
## FH_LR2000_COM  (12 字节, 来自 DFR.cpp)
```
00: StartTime.wYear - 1980
01: StartTime.wMonth
02: StartTime.wDay
03: StartTime.wHour
04: StartTime.wMinute
05: StartTime.wSecond   // 查询文件的结束时间
06: EndTime.wYear - 1980
07: EndTime.wMonth
08: EndTime.wDay
09: EndTime.wHour
10: EndTime.wMinute
11: EndTime.wSecond
```
## FH_LR2000_NET  (12 字节, 来自 DFR.cpp)
```
00: StartTime.wYear - 1980
01: StartTime.wMonth
02: StartTime.wDay
03: StartTime.wHour
04: StartTime.wMinute
05: StartTime.wSecond   // 查询文件的结束时间
06: EndTime.wYear - 1980
07: EndTime.wMonth
08: EndTime.wDay
09: EndTime.wHour
10: EndTime.wMinute
11: EndTime.wSecond
```
## GEC  (13 字节, 来自 Rtu.cpp)
```
00: 0x68
01: 0x00
02: 0x00
03: 0x68
04: GetFunCode()
05: m_btAddr
06: 0x00
07: 0x07
08: 0x40   // preload
09: cell.row
10: cell.col
11: Datetype   // 数据类型
12: strValue.size()
```
## GE_MLINK_MODEM_MODBUS_COM  (9 字节, 来自 CMLinkPacket.cpp)
```
00: 01
01: bt_Type_of_service
02: bt_addr
03: 03
04: 01
05: 0x4f   // · 00h: Protection.
06: bt_Addr_second_station
07: bt_application_data_length
08: bt_xor_packet
```
## GE_Modbus  (6 字节, 来自 CPacket.cpp)
```
00: HIBYTE(map_mem_addr)
01: LOBYTE(map_mem_addr)
02: HIBYTE((WORD)number_setting)
03: LOBYTE((WORD)number_setting)
04: (BYTE) iNumber
05: pbt_databody[j]
```
## HuaRuiT_FWK_COM  (12 字节, 来自 Packet.cpp)
```
00: 0xaa   // 起始符
01: 0X08   // 长度;＝0代表这一帧接收完毕
02: (BYTE)m_iSourceAddr   // 地址
03: 0x3c   // 命令/数据类型
04: dec_to_CBD(Time.wSecond)
05: dec_to_CBD(Time.wMinute)
06: dec_to_CBD(Time.wHour)
07: dec_to_CBD(Time.wDay)
08: dec_to_CBD(Time.wMonth)
09: dec_to_CBD(Time.wYear%100)
10: LOBYTE(checksum)   // 校验和（LB）
11: HIBYTE(checksum)   // 校验和（HB）
```
## KELI_103_TCP  (34 字节, 来自 Net103.cpp)
```
00: 0x68
01: 0x1C
02: 0x00
03: 0x68
04: (BYTE)(0x53 | (m_FCB<<5))   // 功能类型，即控制域
05: m_iAddr   // 地址
06: 0x0F   // asdu类型
07: 0x81   // 可变结构限定词
08: 0x00   // 传输原因
09: m_pCmdRtu->m_iAddr   // 单元公共地址
10: 0xFF   // 功能类型
11: 0x00   // INF见装置的相应信息表信息序号
12: 0x01
13: pStartTime->wMilliseconds%256
14: pStartTime->wMilliseconds/256
15: pStartTime->wSecond
16: pStartTime->wMinute
17: pStartTime->wHour
18: pStartTime->wDay
19: pStartTime->wMonth
20: pStartTime->wYear%256
21: pStartTime->wYear/256
22: 0x01
23: pEndTime->wMilliseconds%256
24: pEndTime->wMilliseconds/256
25: pEndTime->wSecond
26: pEndTime->wMinute
27: pEndTime->wHour
28: pEndTime->wDay
29: pEndTime->wMonth
30: pEndTime->wYear%256
31: pEndTime->wYear/256
32: CheckSum(&m_Sendbuf.buf[4], 28)
33: 0x16
```
## NFDFR  (28 字节, 来自 DFR.cpp)
```
00: 0x68
01: m_iAddr
02: 0x81
03: 0xff
04: 0x00
05: 0x00
06: 0x1b
07: 0x00
08: 0x00
09: 0x00
10: StartTime.wYear%256
11: StartTime.wYear/256
12: StartTime.wMonth
13: StartTime.wDay
14: StartTime.wHour
15: StartTime.wMinute
16: EndTime.wYear%256
17: EndTime.wYear/256
18: EndTime.wMonth
19: EndTime.wDay
20: EndTime.wHour
21: EndTime.wMinute
22: '?'
23: '?'
24: 'F'
25: '?'
26: 0x00
27: 0x00
```
## NFDFR200  (28 字节, 来自 DFR.cpp)
```
00: 0x68
01: m_iAddr
02: 0x81
03: 0xff
04: 0x00
05: 0x00
06: 0x1b
07: 0x00
08: 0x00
09: 0x00
10: StartTime.wYear%256
11: StartTime.wYear/256
12: StartTime.wMonth
13: StartTime.wDay
14: StartTime.wHour
15: StartTime.wMinute
16: EndTime.wYear%256
17: EndTime.wYear/256
18: EndTime.wMonth
19: EndTime.wDay
20: EndTime.wHour
21: EndTime.wMinute
22: '?'
23: '?'
24: 'F'
25: '?'
26: 0x00
27: 0x00
```
## NF_RFW200_NET  (27 字节, 来自 DFR.cpp)
```
00: 0x68
01: m_iAddr
02: TYPE_SEARCHFILE   // 功能类型
03: 0xff   // 应答码
04: CaculPassWord()%256   // 装置的口令
05: CaculPassWord()/256
06: 0x00   // 报文的总大小(包括报文头)
07: 0x00
08: 0x00   // 数据区数据的校验和,为必要域
09: 0x00
10: StartTime.wYear%256   // 结构体 数据区(数据长度最大限制1500)
11: StartTime.wYear/256
12: StartTime.wMonth
13: StartTime.wDay
14: StartTime.wHour
15: StartTime.wMinute
16: EndTime.wYear%256
17: EndTime.wYear/256
18: EndTime.wMonth
19: EndTime.wDay
20: EndTime.wHour
21: EndTime.wMinute
22: '?'
23: '?'
24: 'F'
25: '?'
26: 0x00   // m_pSend->buf[i++] = 0x00;
```
## NR103  (38 字节, 来自 Rtu.cpp)
```
00: 0x68
01: 0x0D
02: 0x0D
03: 0x68
04: (BYTE)(0x53 | (FCB<<5))   // 功能类型，即控制域
05: m_btAddr   // 地址
06: 0x18   // asdu类型,用ASDU24
07: 0x81
08: 0x1F
09: m_btAddr
10: m_btFuncCode
11: 0x00   // 信息序号
12: (BYTE)CmdType   // 命令类型
13: (BYTE)type   // 扰动值的类型
14: (BYTE)(SoeNo%256)   // 故障序号
15: (BYTE)(SoeNo/256)   // 故障序号
16: (BYTE)ChaNo   // 实际通道序号
17: CheckSum(&m_pSend->buf[4],13)
18: 0x16
19: 0x68
20: 0x0D
21: 0x0D
22: 0x68
23: (BYTE)(0x53 | (FCB<<5))   // 功能类型，即控制域
24: m_btAddr   // 地址
25: 0x19   // asdu类型,用ASDU25
26: 0x81
27: 0x1F
28: m_btAddr
29: m_btFuncCode
30: 0x00   // 信息序号
31: (BYTE)CmdType   // 命令类型
32: (BYTE)type   // 扰动值的类型
33: (BYTE)(SoeNo%256)   // 故障序号
34: (BYTE)(SoeNo/256)   // 故障序号
35: (BYTE)ChaNo   // 实际通道序号
36: CheckSum(&m_pSend->buf[4],13)
37: 0x16
```
## NR103_RCS9691  (38 字节, 来自 Rtu.cpp)
```
00: 0x68
01: 0x0D
02: 0x0D
03: 0x68
04: (BYTE)(0x53 | (FCB<<5))   // 功能类型，即控制域
05: m_btAddr   // 地址
06: 0x18   // asdu类型,用ASDU24
07: 0x81
08: 0x1F
09: m_btAddr
10: 0xFF   // 功能类型
11: 0x00   // 信息序号
12: (BYTE)CmdType   // 命令类型
13: (BYTE)type   // 扰动值的类型
14: (BYTE)(SoeNo%256)   // 故障序号
15: (BYTE)(SoeNo/256)   // 故障序号
16: (BYTE)ChaNo   // 实际通道序号
17: CheckSum(&m_pSend->buf[4],13)
18: 0x16
19: 0x68
20: 0x0D
21: 0x0D
22: 0x68
23: (BYTE)(0x53 | (FCB<<5))   // 功能类型，即控制域
24: m_btAddr   // 地址
25: 0x19   // asdu类型,用ASDU25
26: 0x81
27: 0x1F
28: m_btAddr
29: 0xFF   // 功能类型
30: 0x00   // 信息序号
31: (BYTE)CmdType   // 命令类型
32: (BYTE)type   // 扰动值的类型
33: (BYTE)(SoeNo%256)   // 故障序号
34: (BYTE)(SoeNo/256)   // 故障序号
35: (BYTE)ChaNo   // 实际通道序号
36: CheckSum(&m_pSend->buf[4],13)
37: 0x16
```
## NR_103_NET  (31 字节, 来自 Rtu.cpp)
```
00: 0x0A
01: 0x81
02: 0x28
03: m_iAddr
04: 0xFE
05: 0xF9   // 信息序号
06: 0xFA
07: 0x00
08: 0x01   // 数据数目
09: (unsigned char) m_pBaohu->pGroup->DZ_GROUP
10: 0x01   // ID
11: 0x01   // KOD
12: 0x03   // TYPE
13: 0x01   // WIDTH
14: 0x01   // 数目
15: (BYTE)m_iCurSwitchDZGroup   // 通用分类数据
16: (unsigned char)m_ChangeSoftBroad.size()
17: (unsigned char)(pSoft->ID/1000)   // 得到条目号
18: (unsigned char)(pSoft->ID%1000)
19: 0x01   // 描述类别, KOD
20: (unsigned char)pSoft->Type
21: (unsigned char)pSoft->Width
22: 0x01   // 数目
23: (unsigned char)atoi(pSoft->strValue.GetBuffer(MAX_PATH))
24: (unsigned char)m_ChangeDZ.size()
25: (unsigned char)(pDZ->ID/1000)   // 得到条目号
26: (unsigned char)(pDZ->ID%1000)
27: 0x01   // 描述类别, KOD
28: (unsigned char)pDZ->Type
29: (unsigned char)pDZ->Width   // ASCII
30: (unsigned char)pDZ->strValue.GetLength()   // 数目
```
## NR_LFP_COM  (192 字节, 来自 Com.cpp)
```
00: 0xEB   // 同步字符
01: 0x90
02: 0xEB
03: 0x90
04: 0x02   // 起始符
05: btAddr
06: 0x06
07: 0x01
08: 0x01
09: 0x04
10: l
11: h
12: 0x03
13: 0xEB   // 同步字符
14: 0x90
15: 0xEB
16: 0x90
17: 0x02   // 起始符
18: btAddr
19: 0x15
20: 0x01
21: 0x01
22: 0x04
23: l
24: h
25: 0x03
26: 0xEB   // 同步字符
27: 0x90
28: 0xEB
29: 0x90
30: 0x02   // 起始符
31: btAddr
32: 0x40
33: 0x01
34: 0x01
35: 0x04
36: l
37: h
38: 0x03
39: 0xEB   // 同步字符
40: 0x90
41: 0xEB
42: 0x90
43: 0x02   // 起始符
44: btAddr
45: 0x41
46: 0x01
47: 0x01
48: 0x04
49: l
50: h
51: 0x03
52: 0xEB   // 同步字符
53: 0x90
54: 0xEB
55: 0x90
56: 0x02   // 起始符
57: btAddr
58: 0x43
59: 0x01
60: 0x01
61: 0x04
62: l
63: h
64: 0x03
65: 0xEB   // 同步字符
66: 0x90
67: 0xEB
68: 0x90
69: 0x02   // 起始符
70: btAddr
71: 0x44
72: 0x01
73: 0x01
74: 0x04
75: l
76: h
77: 0x03
78: 0xEB   // 同步字符
79: 0x90
80: 0xEB
81: 0x90
82: 0x02   // 起始符
83: btAddr
84: 0x45
85: 0x01
86: 0x01
87: 0x05
88: 0x00
89: l
90: h
91: 0x03
92: 0xEB   // 同步字符
93: 0x90
94: 0xEB
95: 0x90
96: 0x02   // 起始符
97: btAddr
98: 0x46
99: 0x01
100: 0x01
101: 0x04
102: l
103: h
104: 0x03
105: 0xEB   // 同步字符
106: 0x90
107: 0xEB
108: 0x90
109: 0x02   // 起始符
110: 0xFF   // btAddr;
111: 0x47
112: 0x01
113: 0x01
114: 12
115: (unsigned char)(st.wYear%100)
116: (unsigned char)st.wMonth
117: (unsigned char)st.wDay
118: (unsigned char)st.wHour
119: (unsigned char)st.wMinute
120: (unsigned char)st.wSecond
121: (unsigned char)(st.wMilliseconds%256)
122: (unsigned char)(st.wMilliseconds/256)
123: l
124: h
125: 0x03
126: 0xEB   // 同步字符
127: 0x90
128: 0xEB
129: 0x90
130: 0x02   // 起始符
131: btAddr
132: 0x49
133: 0x01
134: 0x01
135: 0x04
136: l
137: h
138: 0x03
139: 0xEB   // 同步字符
140: 0x90
141: 0xEB
142: 0x90
143: 0x02   // 起始符
144: btAddr
145: 0x4A
146: 0x01
147: 0x01
148: 0x05
149: m_newGroup
150: l
151: h
152: 0x03
153: 0xEB   // 同步字符
154: 0x90
155: 0xEB
156: 0x90
157: 0x02   // 起始符
158: btAddr
159: 0x4B
160: 0x01
161: 0x01
162: 0x04
163: l
164: h
165: 0x03
166: 0xEB   // 同步字符
167: 0x90
168: 0xEB
169: 0x90
170: 0x02   // 起始符
171: btAddr
172: 0x4C
173: 0x01
174: 0x01
175: 0x04
176: l
177: h
178: 0x03
179: 0xEB   // 同步字符
180: 0x90
181: 0xEB
182: 0x90
183: 0x02   // 起始符
184: btAddr
185: 0x40
186: 0x01
187: 0x01
188: 0x04
189: l
190: h
191: 0x03
```
## NZ103  (38 字节, 来自 Rtu.cpp)
```
00: 0x68
01: 0x0D
02: 0x0D
03: 0x68
04: (BYTE)(0x50 | m_FCB<<5)   // 功能类型，即控制域
05: (BYTE)(m_btAddr)   // 地址
06: 0x15   // asdu类型,用ASDU21来启动通用服务召唤
07: 0x81
08: 0x2A
09: (BYTE)(m_btAddr)
10: 0xFE   // 功能类型
11: 0xF1   // 信息序号
12: 0x00
13: 0x01
14: (BYTE)Type   // 组号
15: 0x02   // 条目号：01当前定值区；02运行定值区
16: 0x01   // 类别描述：01实际值
17: CheckSum(&m_pSend->buf[4],13)
18: 0x16
19: 0x68
20: 0x0D
21: 0x0D
22: 0x68
23: (BYTE)(0x53 | m_FCB<<5)   // 功能类型，即控制域
24: m_btAddr   // 地址
25: 0x15
26: 0x81
27: 0x2A
28: m_btAddr
29: 0xFE   // 功能类型
30: 0xF1   // 信息序号
31: 0x00
32: 0x01
33: (BYTE)type   // 组号
34: 0x00   // 条目号
35: 0x01   // KOD
36: CheckSum(&m_pSend->buf[4],13)
37: 0x16
```
## NZ103II  (48 字节, 来自 Rtu.cpp)
```
00: 0x68
01: 0x11
02: 0x11
03: 0x68
04: (BYTE)(0x53 | (m_FCB[No]<<5))   // 功能类型，即控制域
05: (BYTE)(m_btAddr+m_btCpuNo[No])   // 地址
06: 0x0A
07: 0x81
08: 0x28
09: (BYTE)(m_btAddr+m_btCpuNo[No])
10: 0xFE   // 功能类型
11: 0xF9   // 信息序号
12: 0x00
13: 0x01
14: bt_Group   // 组号表示投切压板组0x08
15: bt_Inf   // 条目号
16: 0x01   // KOD
17: 0x09   // 数据类型 双点信息
18: 0x01   // 数据大小
19: 0x01   // 数据数目
20: 0x02   // 表示合
21: 0x01   // 表示开
22: CheckSum(&m_pSend->buf[4],17)
23: 0x16
24: 0x68
25: 0x11
26: 0x11
27: 0x68
28: (BYTE)(0x53 | (m_FCB[No]<<5))   // 功能类型，即控制域
29: (BYTE)(m_btAddr+m_btCpuNo[No])   // 地址
30: 0x0A
31: 0x81
32: 0x28
33: (BYTE)(m_btAddr+m_btCpuNo[No])
34: 0xFE   // 功能类型
35: 0xFA   // 信息序号
36: 0x00
37: 0x01
38: bt_Group   // 组号表示投切压板组0x08
39: bt_Inf   // 条目号
40: 0x01   // KOD
41: 0x09   // 数据类型双点信息
42: 0x01   // 数据大小
43: 0x01   // 数据数目
44: 0x02   // 表示合
45: 0x01   // 表示开
46: CheckSum(&m_pSend->buf[4],17)
47: 0x16
```
## NZ_NET103  (29 字节, 来自 CNet103_Packet.cpp)
```
00: 0x90   // 0xEB90
01: 0xEB
02: (BYTE) ((LOWORD(DWPacketLong)) % 256)   // 数据长度
03: (BYTE) ((LOWORD(DWPacketLong)) / 256)
04: (BYTE) ((HIWORD(DWPacketLong)) % 256)
05: (BYTE) ((HIWORD(DWPacketLong)) / 256)
06: 0x90   // 0xEB90
07: 0xEB
08: 0x00   // 源厂站号
09: 0x00
10: 0x00   // 源地址
11: 0x00
12: 0x00   // 目标厂站号
13: 0x00
14: m_btSourceAddr   // 目标地址
15: 0x00   // 目标地址
16: 0x00
17: (BYTE) iPacketType   // 报文类型0--103报文  3--心跳报文
18: 0x00
19: 0x00   // 数据编号
20: 0x00
21: 0xFF   // 保留字节
22: 0xFF
23: 0xFF
24: 0xFF
25: 0xFF
26: 0xFF
27: 0xFF
28: 0xFF
```
## NetCSC2000  (22 字节, 来自 Rtu.cpp)
```
00: (BYTE)(7+btMaxLen)   // 报文长度
01: (BYTE)m_btAddr   // Rtu地址
02: (BYTE)(m_btDssAddr | (m_btTempCpuNo<<5))   // 主站地址
03: (SET_SETTINGS | 0x80)   // 报文类型
04: (BYTE)((btFrameIndex+1) % 256)   // 帧序号低
05: (BYTE)((btFrameIndex+1) / 256)   // 帧序号高
06: m_btTempGroupNo   // 定值区号
07: btSettingType   // 定值类型
08: (BYTE)(6+btMaxLen)   // 报文长度
09: (BYTE)m_btAddr   // Rtu地址
10: (BYTE)(m_btDssAddr | (m_btTempCpuNo<<5))   // 主站地址
11: (SET_SETTINGS | 0x80)   // 报文类型
12: (BYTE)((btFrameIndex+1) % 256)   // 帧序号低
13: (BYTE)(((btFrameIndex+1) / 256) | 0x80)   // 帧序号高
14: m_btTempGroupNo   // 定值区号
15: (BYTE)(6+btMaxLen)   // 报文长度
16: (BYTE)m_btAddr   // Rtu地址
17: (BYTE)(m_btDssAddr | (m_btTempCpuNo<<5))   // 主站地址
18: (SET_SETTINGS | 0x80)   // 报文类型
19: (BYTE)((btFrameIndex+1) % 256)   // 帧序号低
20: (BYTE)((btFrameIndex+1) / 256)   // 帧序号高
21: m_btTempGroupNo   // 定值区号
```
## NetCSC2000L  (7 字节, 来自 Csc2000L.cpp)
```
00: 0x03   // 长度
01: 0xFF   // m_WriteBuf->buf[i++]=0x0E;//主站地址
02: 0x20   // //填充帧长
03: 0x03   // 长度
04: 0xFF   // 广播地址
05: 0x0E   // 主站地址
06: GroupNo   // 0x61召唤第一组录波；0x62召唤第二组
```
## SDDFR  (23 字节, 来自 DFR.cpp)
```
00: 237
01: 0x81
02: 32
03: 0x00
04: 0xFF
05: 0x00
06: 0x00
07: 0x00
08: 0x00
09: wValue%256
10: wValue/256
11: StartTime.wMinute
12: StartTime.wHour
13: StartTime.wDay
14: StartTime.wMonth
15: StartTime.wYear%100
16: wValue%256
17: wValue/256
18: EndTime.wMinute
19: EndTime.wHour
20: EndTime.wDay
21: EndTime.wMonth
22: EndTime.wYear%100
```
## SD_WGDLV_NET  (28 字节, 来自 DFR.cpp)
```
00: 0x68
01: 0x00
02: 0x00
03: 0x68
04: (BYTE)(0x53 | (FCB<<5))   // 功能类型，即控制域
05: m_iAddr   // 地址
06: 0x0F   // asdu类型
07: 0x81   // 可变结构限定词
08: 0x00   // 传输原因
09: m_iAddr   // 单元公共地址
10: 0xFF   // 功能类型
11: 0x00   // INF见装置的相应信息表信息序号
12: wMilliseconds%256
13: wMilliseconds/256
14: StartTime.wMinute
15: StartTime.wHour
16: StartTime.wDay
17: StartTime.wMonth
18: StartTime.wYear%100
19: wMilliseconds%256
20: wMilliseconds/256
21: EndTime.wMinute
22: EndTime.wHour
23: EndTime.wDay
24: EndTime.wMonth
25: EndTime.wYear%100
26: m_CRC.CheckSum(&m_pSend->buf[4],wlen)
27: 0x16
```
## SF103  (119 字节, 来自 Rtu.cpp)
```
00: 0x10
01: (BYTE)(0x5A | (m_FCB<<5))
02: m_btAddr
03: CheckSum(&m_pSend->buf[1],2)
04: 0x16
05: 0x10
06: (BYTE)(0x5B | m_FCB<<5)
07: m_btAddr
08: CheckSum(&m_pSend->buf[1],2)
09: 0x16
10: 0x68
11: 0x09
12: 0x09
13: 0x68
14: (BYTE)(0x53 | m_FCB<<5)
15: m_btAddr
16: 0x07   // 类型标识：0x07
17: 0x81
18: 0x09   // 传送原因：0x09总召唤的启动
19: m_btAddr
20: 0xFF   // 功能类型：0xFF全局功能类型
21: 0x00   // 信息序号
22: 0x00   // m_pSend->buf[i++]=CheckSum(&m_pSend->buf[4],9);
23: 0x16
24: 0x68   // 开始
25: 0x0F
26: 0x0F
27: 0x68   // 开始
28: (BYTE)(0x53 | m_FCB<<5)   // 控制域
29: m_btAddr   // 链路地址
30: 0x06   // asdu6类型
31: 0x81
32: 0x08
33: m_btAddr   // 应用层地址
34: 0xFF   // 功能类型
35: 0x00   // 信息序号
36: (BYTE)(Time.wMilliseconds%256)
37: (BYTE)(Time.wMilliseconds/256)
38: (BYTE)Time.wMinute
39: (BYTE)((Time.wDayOfWeek<<5) | Time.wHour)
40: (BYTE)Time.wDay
41: (BYTE)Time.wMonth
42: (BYTE)(Time.wYear%100)
43: CheckSum(&m_pSend->buf[4],15)
44: 0x16   // 结束
45: 0x68
46: 0x0A
47: 0x0A
48: 0x68
49: (BYTE)(0x53 | (m_FCB<<5))   // 控制域
50: m_btAddr   // 地址
51: 0x14   // asdu类型
52: 0x81
53: 0x14   // 传送原因:一般命令
54: m_btAddr
55: 0xAC   // FUN
56: 0x06   // inf
57: 0x02   // 双点信息:1跳;2合;0、3未用
58: 0x00
59: CheckSum(&m_pSend->buf[4],10)
60: 0x16
61: 0x68   // 开始
62: 0x0D
63: 0x0D
64: 0x68   // 开始
65: (BYTE)(0x53 | (m_FCB<<5))   // 控制域
66: m_btAddr   // 链路地址
67: 0x15
68: 0x81
69: 0x2A
70: m_btAddr   // 应用层地址
71: 0xFE   // 功能类型
72: 0xF1   // 信息序号
73: 0x00
74: 0x01
75: (BYTE)GroupNo
76: (BYTE)ItemNo
77: 0x01
78: CheckSum(&m_pSend->buf[4],13)
79: 0x16   // 结束
80: 0x68   // 开始
81: 0x11
82: 0x11
83: 0x68   // 开始
84: (BYTE)(0x53 | (m_FCB<<5))   // 功能类型，即控制域
85: m_btAddr   // 0xFF;//链路地址
86: 0x0A   // asdu10类型
87: 0x81
88: 0x28
89: m_btAddr   // 0xFF;应用层地址
90: 0xFE   // 功能类型
91: 0xF9   // 信息序号
92: 0x00
93: 0x01
94: 0x0B   // 组号
95: 0x00   // 条目号
96: 0x01   // 描述类别
97: 0x03   // 数据类型
98: 0x01   // 数据宽度
99: 0x01   // 数据数目
100: GroupNo   // 数据值
101: CheckSum(&m_pSend->buf[4],17)
102: 0x16   // 结束
103: 0x68   // 开始
104: 0x0A
105: 0x0A
106: 0x68   // 开始
107: (BYTE)(0x53 | (m_FCB<<5))   // 功能类型，即控制域
108: m_btAddr   // 链路地址
109: 0x0A   // asdu10类型
110: 0x81
111: 0x28
112: m_btAddr   // 0xFF;应用层地址
113: 0xFE   // 功能类型
114: 0xFA   // 信息序号
115: 0x00
116: 0x00
117: CheckSum(&m_pSend->buf[4],10)
118: 0x16   // 结束
```
## SF103_CSC103A  (117 字节, 来自 Rtu.cpp)
```
00: 0x10   // m_pSend->buf[i++]=(BYTE)(0x5A | (m_FCB<<5));
01: m_btAddr   // m_pSend->buf[i++]=CheckSum(&m_pSend->buf[1],2);
02: 0x16   // m_pSend->dwLen=i;
03: 0x10
04: (BYTE)(0x5B | m_FCB<<5)
05: m_btAddr
06: CheckSum(&m_pSend->buf[1],2)
07: 0x16
08: 0x68
09: 0x09
10: 0x09
11: 0x68
12: (BYTE)(0x53 | m_FCB<<5)
13: m_btAddr
14: 0x07   // 类型标识：0x07
15: 0x81
16: 0x09   // 传送原因：0x09总召唤的启动
17: m_btAddr
18: 0xFF   // 功能类型：0xFF全局功能类型
19: 0x00   // 信息序号
20: 0x00   // m_pSend->buf[i++]=CheckSum(&m_pSend->buf[4],9);
21: 0x16
22: 0x68   // 开始
23: 0x0F
24: 0x0F
25: 0x68   // 开始
26: (BYTE)(0x53 | m_FCB<<5)   // 控制域
27: 0xFF   // 链路地址
28: 0x06   // asdu6类型
29: 0x81
30: 0x08
31: 0xFF   // 应用层地址
32: 0xFF   // 功能类型
33: 0x00   // 信息序号
34: (BYTE)((Time.wMilliseconds+1000*Time.wSecond)%256)
35: (BYTE)((Time.wMilliseconds+1000*Time.wSecond)/256)
36: (BYTE)Time.wMinute
37: (BYTE)((Time.wDayOfWeek<<5) | Time.wHour)
38: (BYTE)Time.wDay
39: (BYTE)Time.wMonth
40: (BYTE)(Time.wYear%100)
41: CheckSum(&m_pSend->buf[4],15)
42: 0x16   // 结束
43: 0x68
44: 0x0A
45: 0x0A
46: 0x68
47: (BYTE)(0x53 | (m_FCB<<5))   // 控制域
48: m_btAddr   // 地址
49: 0x14   // asdu类型
50: 0x81
51: 0x14   // 传送原因:一般命令
52: m_btAddr
53: 0xAC   // FUN
54: 0x06   // inf
55: 0x02   // 双点信息:1跳;2合;0、3未用
56: 0x00
57: CheckSum(&m_pSend->buf[4],10)
58: 0x16
59: 0x68   // 开始
60: 0x0D
61: 0x0D
62: 0x68   // 开始
63: (BYTE)(0x53 | (m_FCB<<5))   // 控制域
64: m_btAddr   // 链路地址
65: 0x15
66: 0x81
67: 0x2A
68: m_btAddr   // 应用层地址
69: 0xFE   // 功能类型
70: 0xF1   // 信息序号
71: 0x00
72: 0x01
73: (BYTE)GroupNo
74: (BYTE)ItemNo
75: 0x01
76: CheckSum(&m_pSend->buf[4],13)
77: 0x16   // 结束
78: 0x68   // 开始
79: 0x11
80: 0x11
81: 0x68   // 开始
82: (BYTE)(0x53 | (m_FCB<<5))   // 功能类型，即控制域
83: m_btAddr   // 0xFF;//链路地址
84: 0x0A   // asdu10类型
85: 0x81
86: 0x28
87: m_btAddr   // 0xFF;应用层地址
88: 0xFE   // 功能类型
89: 0xF9   // 信息序号
90: 0x00
91: 0x01
92: 0x0A   // 组号
93: 0x01   // 条目号
94: 0x01   // 描述类别
95: 0x03   // 数据类型
96: 0x01   // 数据宽度
97: 0x01   // 数据数目
98: GroupNo   // 数据值
99: CheckSum(&m_pSend->buf[4],17)
100: 0x16   // 结束
101: 0x68   // 开始
102: 0x0A
103: 0x0A
104: 0x68   // 开始
105: (BYTE)(0x53 | (m_FCB<<5))   // 功能类型，即控制域
106: m_btAddr   // 链路地址
107: 0x0A   // asdu10类型
108: 0x81
109: 0x28
110: m_btAddr   // 0xFF;应用层地址
111: 0xFE   // 功能类型
112: 0xFA   // 信息序号
113: 0x00
114: 0x00
115: CheckSum(&m_pSend->buf[4],10)
116: 0x16   // 结束
```
## SF_CSFM103_TCP  (28 字节, 来自 Packet.cpp)
```
00: 0x68
01: 0x1A   // APDU长度14
02: (BYTE)((m_dwSendFrameCounter%128)<<1)   // 发送序列号低
03: (BYTE)(m_dwSendFrameCounter/128)   // 发送序列号高
04: (BYTE)((m_dwRecvFrameCounter%128)<<1)   // 接收序列号低
05: (BYTE)(m_dwRecvFrameCounter/128)   // 接收序列号高
06: 0x0F   // asdu类型
07: 0x81   // 可变结构限定词
08: 0x00   // 传输原因
09: 0x00   // 单元公共地址低字节
10: m_iSourceAddr   // 单元公共地址高字节
11: 0xFF   // 功能类型
12: 0x00   // INF见装置的相应信息表信息序号
13: 0x00   // 返回信息标识符(RII)
14: (start_time.wMilliseconds+start_time.wSecond*1000)%256
15: (start_time.wMilliseconds+start_time.wSecond*1000)/256
16: start_time.wMinute
17: start_time.wHour
18: start_time.wDay
19: start_time.wMonth
20: start_time.wYear-2000
21: (end_time.wMilliseconds+end_time.wSecond*1000)%256
22: (end_time.wMilliseconds+end_time.wSecond*1000)/256
23: end_time.wMinute
24: end_time.wHour
25: end_time.wDay
26: end_time.wMonth
27: end_time.wYear-2000
```
## SF_UDP103  (117 字节, 来自 Rtu.cpp)
```
00: 0x10   // m_pSend->buf[i++]=(BYTE)(0x5A | (m_FCB<<5));
01: m_btAddr   // m_pSend->buf[i++]=CheckSum(&m_pSend->buf[1],2);
02: 0x16   // m_pSend->dwLen=i;
03: 0x10
04: (BYTE)(0x5B | m_FCB<<5)
05: m_btAddr
06: CheckSum(&m_pSend->buf[1],2)
07: 0x16
08: 0x68
09: 0x09
10: 0x09
11: 0x68
12: (BYTE)(0x53 | m_FCB<<5)
13: m_btAddr
14: 0x07   // 类型标识：0x07
15: 0x81
16: 0x09   // 传送原因：0x09总召唤的启动
17: m_btAddr
18: 0xFF   // 功能类型：0xFF全局功能类型
19: 0x00   // 信息序号
20: 0x00   // m_pSend->buf[i++]=CheckSum(&m_pSend->buf[4],9);
21: 0x16
22: 0x68   // 开始
23: 0x0F
24: 0x0F
25: 0x68   // 开始
26: (BYTE)(0x53 | m_FCB<<5)   // 控制域
27: 0xFF   // 链路地址
28: 0x06   // asdu6类型
29: 0x81
30: 0x08
31: 0xFF   // 应用层地址
32: 0xFF   // 功能类型
33: 0x00   // 信息序号
34: (BYTE)((Time.wMilliseconds+1000*Time.wSecond)%256)
35: (BYTE)((Time.wMilliseconds+1000*Time.wSecond)/256)
36: (BYTE)Time.wMinute
37: (BYTE)((Time.wDayOfWeek<<5) | Time.wHour)
38: (BYTE)Time.wDay
39: (BYTE)Time.wMonth
40: (BYTE)(Time.wYear%100)
41: CheckSum(&m_pSend->buf[4],15)
42: 0x16   // 结束
43: 0x68
44: 0x0A
45: 0x0A
46: 0x68
47: (BYTE)(0x53 | (m_FCB<<5))   // 控制域
48: m_btAddr   // 地址
49: 0x14   // asdu类型
50: 0x81
51: 0x14   // 传送原因:一般命令
52: m_btAddr
53: 0xAC   // FUN
54: 0x06   // inf
55: 0x02   // 双点信息:1跳;2合;0、3未用
56: 0x00
57: CheckSum(&m_pSend->buf[4],10)
58: 0x16
59: 0x68   // 开始
60: 0x0D
61: 0x0D
62: 0x68   // 开始
63: (BYTE)(0x53 | (m_FCB<<5))   // 控制域
64: m_btAddr   // 链路地址
65: 0x15
66: 0x81
67: 0x2A
68: m_btAddr   // 应用层地址
69: 0xFE   // 功能类型
70: 0xF1   // 信息序号
71: 0x00
72: 0x01
73: (BYTE)GroupNo
74: (BYTE)ItemNo
75: 0x01
76: CheckSum(&m_pSend->buf[4],13)
77: 0x16   // 结束
78: 0x68   // 开始
79: 0x11
80: 0x11
81: 0x68   // 开始
82: (BYTE)(0x53 | (m_FCB<<5))   // 功能类型，即控制域
83: m_btAddr   // 0xFF;//链路地址
84: 0x0A   // asdu10类型
85: 0x81
86: 0x28
87: m_btAddr   // 0xFF;应用层地址
88: 0xFE   // 功能类型
89: 0xF9   // 信息序号
90: 0x00
91: 0x01
92: 0x0A   // 组号
93: 0x01   // 条目号
94: 0x01   // 描述类别
95: 0x03   // 数据类型
96: 0x01   // 数据宽度
97: 0x01   // 数据数目
98: GroupNo   // 数据值
99: CheckSum(&m_pSend->buf[4],17)
100: 0x16   // 结束
101: 0x68   // 开始
102: 0x0A
103: 0x0A
104: 0x68   // 开始
105: (BYTE)(0x53 | (m_FCB<<5))   // 功能类型，即控制域
106: m_btAddr   // 链路地址
107: 0x0A   // asdu10类型
108: 0x81
109: 0x28
110: m_btAddr   // 0xFF;应用层地址
111: 0xFE   // 功能类型
112: 0xFA   // 信息序号
113: 0x00
114: 0x00
115: CheckSum(&m_pSend->buf[4],10)
116: 0x16   // 结束
```
## SH2000  (20 字节, 来自 Sh2000_packet.cpp)
```
00: 0x12
01: 0x3D   // 报文长度
02: 0x00
03: LOBYTE(data_length)
04: HIBYTE(data_length)
05: LOBYTE(connect_type)
06: HIBYTE(connect_type)
07: LOBYTE(ver)
08: HIBYTE(ver)
09: LOBYTE(protol_type)
10: HIBYTE(protol_type)
11: LOBYTE(LOWORD(m_StationID))   // 调试时注意
12: HIBYTE(LOWORD(m_StationID))
13: LOBYTE(HIWORD(m_StationID))
14: HIBYTE(HIWORD(m_StationID))
15: LOBYTE(LOWORD(m_LBID))
16: HIBYTE(LOWORD(m_LBID))
17: LOBYTE(HIWORD(m_LBID))
18: HIBYTE(HIWORD(m_LBID))
19: (BYTE)(*name)
```
## SIEMENS_103_COM  (38 字节, 来自 Rtu.cpp)
```
00: 0x68
01: 0x0D
02: 0x0D
03: 0x68
04: (BYTE)(0x53 | (m_FCB<<5))   // 功能类型，即控制域
05: m_btAddr   // 地址
06: 0x18   // asdu类型,用ASDU24
07: 0x81
08: 0x1F
09: m_btAddr
10: 0xC3   // ==195;				//功能类型
11: 0x00   // 信息序号
12: (BYTE)CmdType   // 命令类型
13: (BYTE)type   // 扰动值的类型
14: (BYTE)(SoeNo%256)   // 故障序号
15: (BYTE)(SoeNo/256)   // 故障序号
16: (BYTE)ChaNo   // 实际通道序号
17: CheckSum(&m_pSend->buf[4],13)
18: 0x16
19: 0x68
20: 0x0D
21: 0x0D
22: 0x68
23: (BYTE)(0x53 | (m_FCB<<5))   // 功能类型，即控制域
24: m_btAddr   // 地址
25: 0x19   // asdu类型,用ASDU25
26: 0x81
27: 0x1F
28: m_btAddr
29: 0xC3   // ==195;			//功能类型
30: 0x00   // 信息序号
31: (BYTE)CmdType   // 命令类型
32: (BYTE)type   // 扰动值的类型
33: (BYTE)(SoeNo%256)   // 故障序号
34: (BYTE)(SoeNo/256)   // 故障序号
35: (BYTE)ChaNo   // 实际通道序号
36: CheckSum(&m_pSend->buf[4],13)
37: 0x16
```
## SJ103  (45 字节, 来自 Rtu.cpp)
```
00: 0x10
01: (BYTE)(0x5A | (m_FCB<<5))
02: m_btAddr
03: CheckSum(&m_pSend->buf[1],2)
04: 0x16
05: 0x10
06: (BYTE)(0x5B | m_FCB<<5)
07: m_btAddr
08: CheckSum(&m_pSend->buf[1],2)
09: 0x16
10: 0x68   // 开始
11: 0x0F
12: 0x0F
13: 0x68   // 开始
14: (BYTE)(0x54 | m_FCB<<5)   // 控制域
15: m_btAddr   // 0xFF;//链路地址
16: 0x06   // asdu6类型
17: 0x81
18: 0x08
19: m_btAddr   // 0xFF;应用层地址
20: 0xFF   // 功能类型
21: 0x00   // 信息序号
22: (BYTE)(Time.wMilliseconds%256)
23: (BYTE)(Time.wMilliseconds/256)
24: (BYTE)Time.wMinute
25: (BYTE)((Time.wDayOfWeek<<5) | Time.wHour)
26: (BYTE)Time.wDay
27: (BYTE)Time.wMonth
28: (BYTE)(Time.wYear%100)
29: CheckSum(&m_pSend->buf[4],15)
30: 0x16   // 结束
31: 0x68
32: 0x09
33: 0x09
34: 0x68
35: (BYTE)(0x53 | m_FCB<<5)
36: m_btAddr
37: 0x07   // 类型标识：0x07
38: 0x81
39: 0x09   // 传送原因：0x09总召唤的启动
40: m_btAddr
41: 0xFF   // 功能类型：0xFF全局功能类型
42: 0x00   // 信息序号
43: 0x00   // m_pSend->buf[i++]=CheckSum(&m_pSend->buf[4],9);
44: 0x16
```
## SZNR_103_TCP  (37 字节, 来自 Net103.cpp)
```
00: 0x68
01: 0x00
02: 0x00
03: 0x68
04: (BYTE)(0x50 | (m_pCmdRtu->m_FCB<<5))
05: m_pCmdRtu->m_btAddr
06: 0x0A
07: 0x81
08: 0x28
09: m_pCmdRtu->m_btAddr
10: 0xFE
11: 0xF9   // 信息序号
12: 0xFA
13: 0x00   // 定值区号
14: 0x01   // 数据数目
15: (unsigned char)m_pCmdRtu->m_pGroup->DZ_GROUP   // 组号
16: 0x01   // 条目号
17: 0x01   // 描述类别
18: 0x03   // 数据类型
19: 0x01   // 数据宽度
20: 0x01   // 数目
21: m_btTempZoneNo   // 定值区号
22: (unsigned char)m_pCmdRtu->m_vecChangeSoftBroad.size()
23: (unsigned char)(m_pCmdRtu->m_pGroup->SOFT_BOARD)   // 组号
24: (unsigned char)(suSoftBoard.ID)   // 条目号
25: 0x01   // 描述类别
26: (unsigned char)suSoftBoard.Type   // 数据类型
27: (unsigned char)suSoftBoard.Width   // 数据宽度
28: 0x01   // 数目
29: (unsigned char)atoi(suSoftBoard.strValue.GetBuffer(MAX_PATH))
30: (unsigned char)m_pCmdRtu->m_vecChangeDZ.size()
31: (unsigned char)(suDZ.ID/256)   // 组号
32: (unsigned char)(suDZ.ID%256)   // 条目号
33: 0x01   // 描述类别
34: (unsigned char)suDZ.Type   // 数据类型
35: (unsigned char)suDZ.Width   // 数据宽度
36: 0x01   // 数目
```
## Toshiba_Com_RSM  (22 字节, 来自 ToshibaPacket.cpp)
```
00: LOBYTE(LOWORD((DWORD)all_packet_size))
01: HIBYTE(LOWORD((DWORD)all_packet_size))
02: LOBYTE(HIWORD((DWORD)all_packet_size))
03: HIBYTE(HIWORD((DWORD)all_packet_size))   // Relay address
04: LOBYTE(m_iSourceAddr)
05: HIBYTE(m_iSourceAddr)   // for (int j=0;j<16;j++)
06: 0X00
07: 0X04
08: LOBYTE((WORD)group_num)
09: HIBYTE((WORD)group_num)
10: LOBYTE((WORD)current_group)
11: HIBYTE((WORD)current_group)
12: LOBYTE((WORD)type_num)
13: HIBYTE((WORD)type_num)
14: LOBYTE((WORD)type_no)
15: HIBYTE((WORD)type_no)
16: LOBYTE((WORD)down_dz_array.size())
17: HIBYTE((WORD)down_dz_array.size())
18: LOBYTE((WORD)down_dz_array[j].offset)
19: HIBYTE((WORD)down_dz_array[j].offset)
20: LOBYTE((WORD)down_dz_array[j].i_value)
21: HIBYTE((WORD)down_dz_array[j].i_value)
```
## WFBL_FTP103  (29 字节, 来自 CNet103_Packet.cpp)
```
00: 0x90   // 0xEB90
01: 0xEB
02: (BYTE) ((LOWORD(DWPacketLong)) % 256)   // 数据长度
03: (BYTE) ((LOWORD(DWPacketLong)) / 256)
04: (BYTE) ((HIWORD(DWPacketLong)) % 256)
05: (BYTE) ((HIWORD(DWPacketLong)) / 256)
06: 0x90   // 0xEB90
07: 0xEB
08: 0x00   // 源厂站号
09: 0x00
10: 0x00   // 源地址
11: 0x00
12: 0x00   // 目标厂站号
13: 0x00
14: m_btSourceAddr   // 目标地址
15: 0x00   // 目标地址
16: 0x00
17: (BYTE) iPacketType   // 报文类型0--103报文  3--心跳报文
18: 0x00
19: 0x00   // 数据编号
20: 0x00
21: 0xFF   // 保留字节
22: 0xFF
23: 0xFF
24: 0xFF
25: 0xFF
26: 0xFF
27: 0xFF
28: 0xFF
```
## WGL3000  (15 字节, 来自 CNet103_Packet.cpp)
```
00: 0x0a   // ASDU类型
01: 0x81
02: bt_cot
03: m_btSourceAddr
04: 0xFE
05: bt_inf
06: bt_rii
07: bt_ngd
08: (BYTE) ((vec_w_gin[j] & 0xFF00) >> 8)   // group 组号
09: (BYTE) (vec_w_gin[j] & 0x00FF)   // entry 条目号
10: 0x01   // 实际值
11: vec_bt_datatype_gdd[j]   // 数据类型
12: (BYTE) ((vec_w_datasize_number_gdd[j] & 0xFF00) >> 8)   // 数据宽度
13: (BYTE) (vec_w_datasize_number_gdd[j] & 0x00FF)   // 数据数目（7-1）和后续状态位(8)
14: vec2_bt_gid[j][k]   // 得到通用分类数据
```
## XJ_103_COM  (43 字节, 来自 Rtu.cpp)
```
00: 0x10
01: (BYTE)(0x5A |FCB<<5)
02: m_btAddr
03: CheckSum(&m_pSend->buf[1],2)
04: 0x16
05: 0x68
06: 0x0D
07: 0x0D
08: 0x68
09: (BYTE)(0x53 | (FCB<<5))   // 功能类型，即控制域
10: m_btAddr   // 地址
11: 0x18   // asdu类型,用ASDU24
12: 0x81
13: 0x1F
14: m_btAddr
15: 0xFF   // 功能类型
16: 0x00   // 信息序号
17: (BYTE)CmdType   // 命令类型
18: (BYTE)type   // 扰动值的类型
19: (BYTE)(SoeNo%256)   // 故障序号
20: (BYTE)(SoeNo/256)   // ;		//故障序号
21: (BYTE)ChaNo   // 实际通道序号
22: CheckSum(&m_pSend->buf[4],13)
23: 0x16
24: 0x68
25: 0x0D
26: 0x0D
27: 0x68
28: (BYTE)(0x53 | (FCB<<5))   // 功能类型，即控制域
29: m_btAddr   // 地址
30: 0x19   // asdu类型,用ASDU25
31: 0x81
32: 0x1F
33: m_btAddr
34: 0xFF   // 功能类型
35: 0x00   // 信息序号
36: (BYTE)CmdType   // 命令类型
37: (BYTE)type   // 扰动值的类型
38: (BYTE)(SoeNo%256)   // 故障序号
39: (BYTE)(SoeNo/256)   // 故障序号
40: (BYTE)ChaNo   // 实际通道序号
41: CheckSum(&m_pSend->buf[4],13)
42: 0x16
```
## XJ_COM103  (43 字节, 来自 Rtu.cpp)
```
00: 0x10
01: (BYTE)(0x5A |FCB<<5)
02: m_btAddr
03: CheckSum(&m_pSend->buf[1],2)
04: 0x16
05: 0x68
06: 0x0D
07: 0x0D
08: 0x68
09: (BYTE)(0x53 | (FCB<<5))   // 功能类型，即控制域
10: m_btAddr   // 地址
11: 0x18   // asdu类型,用ASDU24
12: 0x81
13: 0x1F
14: bt_Cpu
15: 0xFF   // 功能类型
16: 0x00   // 信息序号
17: (BYTE)CmdType   // 命令类型
18: (BYTE)type   // 扰动值的类型
19: (BYTE)(SoeNo%256)   // 故障序号
20: (BYTE)(SoeNo/256)   // ;		//故障序号
21: (BYTE)ChaNo   // 实际通道序号
22: CheckSum(&m_pSend->buf[4],13)
23: 0x16
24: 0x68
25: 0x0D
26: 0x0D
27: 0x68
28: (BYTE)(0x53 | (FCB<<5))   // 功能类型，即控制域
29: m_btAddr   // 地址
30: 0x19   // asdu类型,用ASDU25
31: 0x81
32: 0x1F
33: bt_Cpu
34: 0xFF   // 功能类型
35: 0x00   // 信息序号
36: (BYTE)CmdType   // 命令类型
37: (BYTE)type   // 扰动值的类型
38: (BYTE)(SoeNo%256)   // 故障序号
39: (BYTE)(SoeNo/256)   // 故障序号
40: (BYTE)ChaNo   // 实际通道序号
41: CheckSum(&m_pSend->buf[4],13)
42: 0x16
```
## XJ_NET103  (21 字节, 来自 Net103.cpp)
```
00: 0x68   // 同步字符0x68
01: 0x13   // APDU长度18
02: (BYTE)((m_dwSendFrameCounter%128)<<1)   // 发送序列号低
03: (BYTE)(m_dwSendFrameCounter/128)   // 发送序列号高
04: (BYTE)((m_dwRecvFrameCounter%128)<<1)   // 接收序列号低
05: (BYTE)(m_dwRecvFrameCounter/128)   // 接收序列号高
06: 0x06   // 类型标识6
07: 0x81   // 可变结构限定词
08: 0x08   // 传送原因低字节(8)
09: 0x00   // 传送原因高字节
10: 0x00   // 单元公共地址低字节(支持CPU地址)
11: m_pCurrentRtu->m_btAddr   // 单元公共地址高字节(支持广播地址0xFF)
12: 0xFF   // FUN
13: 0x00   // FIN
14: (BYTE)((Time.wMilliseconds+Time.wSecond*1000)%256)
15: (BYTE)((Time.wMilliseconds+Time.wSecond*1000)/256)
16: (BYTE)Time.wMinute
17: (BYTE)Time.wHour
18: (BYTE)Time.wDay
19: (BYTE)Time.wMonth
20: (BYTE)(Time.wYear%100)
```
## XJ_NET103_WXH13  (21 字节, 来自 Net103.cpp)
```
00: 0x68   // 同步字符0x68
01: 0x13   // APDU长度18
02: (BYTE)((m_dwSendFrameCounter%128)<<1)   // 发送序列号低
03: (BYTE)(m_dwSendFrameCounter/128)   // 发送序列号高
04: (BYTE)((m_dwRecvFrameCounter%128)<<1)   // 接收序列号低
05: (BYTE)(m_dwRecvFrameCounter/128)   // 接收序列号高
06: 0x06   // 类型标识6
07: 0x81   // 可变结构限定词
08: 0x08   // 传送原因低字节(8)
09: 0x00   // 传送原因高字节
10: 0x00   // 单元公共地址低字节(支持CPU地址)
11: m_pCurrentRtu->m_btAddr   // 单元公共地址高字节(支持广播地址0xFF)
12: 0xFF   // FUN
13: 0x00   // FIN
14: (BYTE)((Time.wMilliseconds+Time.wSecond*1000)%256)
15: (BYTE)((Time.wMilliseconds+Time.wSecond*1000)/256)
16: (BYTE)Time.wMinute
17: (BYTE)Time.wHour
18: (BYTE)Time.wDay
19: (BYTE)Time.wMonth
20: (BYTE)(Time.wYear%100)
```
## YS8  (29 字节, 来自 Distribute.cpp)
```
00: 0xEB
01: 0x90
02: 0x68
03: m_iAddr
04: 0x01   // 扩展码
05: 0x0F
06: 0x02   // 数据长度
07: 0x02
08: 0x00   // 数据包的编号
09: Group%256
10: Group/256
11: 0x10
12: 0xEB
13: 0x90
14: 0x68
15: m_iAddr
16: 0x01
17: 0x0A
18: 0x02
19: 0x08
20: 0x00
21: localTime.wYear%256
22: localTime.wYear/256
23: (unsigned char)localTime.wDay
24: (unsigned char)localTime.wMonth
25: (unsigned char)localTime.wMinute
26: (unsigned char)localTime.wHour
27: 0x00
28: (unsigned char)localTime.wSecond
```
## YS88A  (27 字节, 来自 DFR.cpp)
```
00: 0x68
01: m_iAddr
02: 0x81
03: 0xff
04: 0x00
05: 0x00
06: 0x1b
07: 0x00
08: 0x00
09: 0x00
10: StartTime.wYear%256
11: StartTime.wYear/256
12: StartTime.wMonth
13: StartTime.wDay
14: StartTime.wHour
15: StartTime.wMinute
16: EndTime.wYear%256
17: EndTime.wYear/256
18: EndTime.wMonth
19: EndTime.wDay
20: EndTime.wHour
21: EndTime.wMinute
22: 0x3F
23: 0x30
24: 0x30
25: 0x00
26: 0x00
```
## YSOsc  (29 字节, 来自 Distribute.cpp)
```
00: 0xEB
01: 0x90
02: 0x68
03: m_iAddr
04: 0x01   // 扩展码
05: 0x0F
06: 0x02   // 数据长度
07: 0x02
08: 0x00   // 数据包的编号
09: Group%256
10: Group/256
11: 0x10
12: 0xEB
13: 0x90
14: 0x68
15: m_iAddr
16: 0x01
17: 0x0A
18: 0x02
19: 0x08
20: 0x00
21: localTime.wYear%256
22: localTime.wYear/256
23: (unsigned char)localTime.wDay
24: (unsigned char)localTime.wMonth
25: (unsigned char)localTime.wMinute
26: (unsigned char)localTime.wHour
27: 0x00
28: (unsigned char)localTime.wSecond
```
## YS_89A_NET  (24 字节, 来自 DFR.cpp)
```
00: 0x68
01: m_iAddr
02: 0x81
03: 0xff
04: 0x00
05: 0x00
06: 0x18   // 文件长度(这点和YS88A不一致)
07: 0x00
08: 0x00
09: 0x00
10: StartTime.wYear%256
11: StartTime.wYear/256
12: StartTime.wMonth
13: StartTime.wDay
14: StartTime.wHour
15: StartTime.wMinute
16: EndTime.wYear%256
17: EndTime.wYear/256
18: EndTime.wMonth
19: EndTime.wDay
20: EndTime.wHour
21: EndTime.wMinute
22: FileType   // 搜索的文件类型
23: 0x00
```
## YS_89_NET  (24 字节, 来自 DFR.cpp)
```
00: 0x68
01: m_iAddr
02: 0x81
03: 0xff
04: 0x00
05: 0x00
06: 0x18   // 文件长度(这点和YS88A不一致)
07: 0x00
08: 0x00
09: 0x00
10: StartTime.wYear%256
11: StartTime.wYear/256
12: StartTime.wMonth
13: StartTime.wDay
14: StartTime.wHour
15: StartTime.wMinute
16: EndTime.wYear%256
17: EndTime.wYear/256
18: EndTime.wMonth
19: EndTime.wDay
20: EndTime.wHour
21: EndTime.wMinute
22: FileType   // 搜索的文件类型
23: 0x00
```
