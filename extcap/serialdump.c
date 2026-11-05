/* serialdump.c
 * serialdump is an extcap tool that captures IEC 60870-5-101 traffic from a
 * serial port and hands each FT1.2 frame to the IEC 60870-5-101 dissector.
 *
 * The program is deliberately self-contained: it does not link libwsutil or
 * GLib, so it runs from the extcap subdirectory without needing the program
 * directory on the DLL search path.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

#define SERIALDUMP_EXTCAP_INTERFACE "serialdump"
#define SERIALDUMP_VERSION "1.0.0"

/*
 * DLT 252 (WTAP_ENCAP_WIRESHARK_UPPER_PDU) carries exported PDU records: a
 * 4-byte TLV naming the dissector, a 4-byte end-of-options marker, then the
 * frame bytes.
 */
#define SERIALDUMP_LINKTYPE 252
#define SERIALDUMP_SNAPLEN 0xffff

#define EXP_PDU_TAG_DISSECTOR_NAME 12
#define EXP_PDU_TAG_END_OF_OPT 0

#define DISSECTOR_NAME "iec60870_101_frame"
#define DISSECTOR_NAME_YUSHUN "yushun_modbus"
#define DISSECTOR_NAME_RAW "serial_raw"

/* IEC 60870-5-101 FT1.2 frame boundaries. */
#define IEC101_START_VAR 0x68
#define IEC101_START_FIXED 0x10
#define IEC101_SINGLE_CHAR 0xE5
#define IEC101_STOP_CHAR 0x16
#define IEC101_FIXED_LEN_WITH_1BYTE_ADDR 5

#define READ_BUF_SIZE 4096
#define FRAME_BUF_SIZE 4096

/* Options. */
static const char *opt_port;
static unsigned opt_baudrate = 9600;
static unsigned opt_databits = 8;
static const char *opt_parity = "even";
static unsigned opt_stopbits = 1;
static unsigned opt_linkaddrlen = 1;
static const char *opt_framing = "ft12";
static const char *opt_protocol; /* NULL = auto from framing */
static const char *opt_fifo;
static bool opt_capture;

/* Exported-PDU dissector name written into each capture record. */
static const char *
effective_protocol(void)
{
	if (opt_protocol != NULL && opt_protocol[0] != '\0')
		return opt_protocol;
	/* Raw: neutral serial_raw; UI menus try-decode into a concrete protocol. */
	if (strcmp(opt_framing, "raw") == 0)
		return DISSECTOR_NAME_RAW;
	return DISSECTOR_NAME;
}

/* --- Output -------------------------------------------------------------- */

static FILE *out;

static void
put_u16be(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)((v >> 8) & 0xFF);
	p[1] = (uint8_t)(v & 0xFF);
}

static void
put_u32be(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)((v >> 24) & 0xFF);
	p[1] = (uint8_t)((v >> 16) & 0xFF);
	p[2] = (uint8_t)((v >> 8) & 0xFF);
	p[3] = (uint8_t)(v & 0xFF);
}

static void
put_u16le(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v & 0xFF);
	p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static void
put_u32le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v & 0xFF);
	p[1] = (uint8_t)((v >> 8) & 0xFF);
	p[2] = (uint8_t)((v >> 16) & 0xFF);
	p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static bool
write_pcap_header(void)
{
	uint8_t hdr[24];

	put_u32le(hdr + 0, 0xa1b2c3d4);   /* magic */
	put_u16le(hdr + 4, 2);            /* major */
	put_u16le(hdr + 6, 4);            /* minor */
	put_u32le(hdr + 8, 0);            /* thiszone */
	put_u32le(hdr + 12, 0);           /* sigfigs */
	put_u32le(hdr + 16, SERIALDUMP_SNAPLEN);
	put_u32le(hdr + 20, SERIALDUMP_LINKTYPE);

	if (fwrite(hdr, 1, sizeof(hdr), out) != sizeof(hdr))
		return false;
	fflush(out);
	return true;
}

/* Wrap one frame in an exported PDU and write it as a pcap record. */
static bool
write_frame(const uint8_t *frame, unsigned frame_len)
{
	const char *name = effective_protocol();
	unsigned name_raw;
	unsigned name_len;
	uint8_t namebuf[64];
	uint8_t rec_hdr[16];
	uint8_t tlv[4];
	uint8_t end_opt[4] = { 0, 0, 0, 0 };
	uint32_t total;
	time_t now = time(NULL);

	name_raw = (unsigned)strlen(name) + 1; /* include NUL */
	name_len = (name_raw + 3u) & ~3u;
	if (name_len > sizeof(namebuf))
		return false;
	memset(namebuf, 0, name_len);
	memcpy(namebuf, name, strlen(name));

	total = 4u + name_len + 4u + frame_len;

	put_u32le(rec_hdr + 0, (uint32_t)now);
	put_u32le(rec_hdr + 4, 0);
	put_u32le(rec_hdr + 8, total);
	put_u32le(rec_hdr + 12, total);

	/* Exported PDU tags and lengths are big-endian. */
	tlv[0] = (uint8_t)(EXP_PDU_TAG_DISSECTOR_NAME >> 8);
	tlv[1] = (uint8_t)(EXP_PDU_TAG_DISSECTOR_NAME & 0xFF);
	tlv[2] = (uint8_t)(name_len >> 8);
	tlv[3] = (uint8_t)(name_len & 0xFF);

	if (fwrite(rec_hdr, 1, sizeof(rec_hdr), out) != sizeof(rec_hdr))
		return false;
	if (fwrite(tlv, 1, sizeof(tlv), out) != sizeof(tlv))
		return false;
	if (fwrite(namebuf, 1, name_len, out) != name_len)
		return false;
	if (fwrite(end_opt, 1, sizeof(end_opt), out) != sizeof(end_opt))
		return false;
	if (frame_len > 0 && fwrite(frame, 1, frame_len, out) != frame_len)
		return false;

	fflush(out);
	return true;
}

/* --- FT1.2 framer -------------------------------------------------------- */

typedef struct {
	uint8_t buf[FRAME_BUF_SIZE];
	unsigned len;
	unsigned linkaddr_len;
} ft12_framer;

/* Length of the complete frame at the head of the buffer, 0 if more data is
 * needed, or -1 if the head byte cannot start a frame (drop one byte). */
static int
ft12_frame_length(const ft12_framer *f)
{
	const uint8_t *d = f->buf;

	if (f->len == 0)
		return 0;

	switch (d[0]) {
	case IEC101_SINGLE_CHAR:
		return 1;
	case IEC101_START_FIXED: {
		int len = IEC101_FIXED_LEN_WITH_1BYTE_ADDR + ((int)f->linkaddr_len - 1);
		if (f->len < (unsigned)len)
			return 0;
		if (d[len - 1] != IEC101_STOP_CHAR)
			return -1;
		return len;
	}
	case IEC101_START_VAR: {
		int len;
		if (f->len < 2)
			return 0;
		/* Both length octets must agree; otherwise this is not a frame. */
		if (f->len >= 3 && d[1] != d[2])
			return -1;
		len = (int)d[1] + 6;
		if ((unsigned)len > FRAME_BUF_SIZE)
			return -1;
		if (f->len < (unsigned)len)
			return 0;
		if (d[len - 1] != IEC101_STOP_CHAR)
			return -1;
		return len;
	}
	default:
		return -1;
	}
}

static void
ft12_drop(ft12_framer *f, unsigned n)
{
	if (n >= f->len) {
		f->len = 0;
		return;
	}
	memmove(f->buf, f->buf + n, f->len - n);
	f->len -= n;
}

static bool
ft12_feed(ft12_framer *f, const uint8_t *data, unsigned len)
{
	while (len > 0) {
		unsigned space = FRAME_BUF_SIZE - f->len;
		unsigned take = len < space ? len : space;

		memcpy(f->buf + f->len, data, take);
		f->len += take;
		data += take;
		len -= take;

		for (;;) {
			int frame_len = ft12_frame_length(f);

			if (frame_len == 0)
				break;
			if (frame_len < 0) {
				/* Not frame-aligned; drop a byte and resynchronise. */
				ft12_drop(f, 1);
				continue;
			}
			if (!write_frame(f->buf, (unsigned)frame_len))
				return false;
			ft12_drop(f, (unsigned)frame_len);
		}

		/* Guard against a stream that never yields a frame. */
		if (f->len == FRAME_BUF_SIZE)
			ft12_drop(f, FRAME_BUF_SIZE / 2);
	}
	return true;
}

/* --- Configuration output ------------------------------------------------ */

static void
list_config(void)
{
	printf("arg {number=0}{call=--port}{display=Serial port}"
		"{type=string}{default=}"
		"{tooltip=Serial port device, for example COM3. Leave empty to use the "
		"first available port.}\n");
	printf("arg {number=1}{call=--baudrate}{display=Baud rate}"
		"{type=unsigned}{range=300,4000000}{default=9600}"
		"{tooltip=Line speed of the IEC 60870-5-101 link}\n");
	printf("arg {number=2}{call=--databits}{display=Data bits}"
		"{type=selector}{default=8}\n");
	printf("value {arg=2}{value=7}{display=7}\n");
	printf("value {arg=2}{value=8}{display=8}{default=true}\n");
	printf("arg {number=3}{call=--parity}{display=Parity}"
		"{type=selector}{default=even}\n");
	printf("value {arg=3}{value=none}{display=None}\n");
	printf("value {arg=3}{value=odd}{display=Odd}\n");
	printf("value {arg=3}{value=even}{display=Even}{default=true}\n");
	printf("arg {number=4}{call=--stopbits}{display=Stop bits}"
		"{type=selector}{default=1}\n");
	printf("value {arg=4}{value=1}{display=1}{default=true}\n");
	printf("value {arg=4}{value=2}{display=2}\n");
	printf("arg {number=5}{call=--linkaddrlen}{display=Link address length}"
		"{type=selector}{default=1}"
		"{tooltip=FT1.2 link address field size, 1 or 2 octets}\n");
	printf("value {arg=5}{value=1}{display=1 octet}{default=true}\n");
	printf("value {arg=5}{value=2}{display=2 octets}\n");
	printf("arg {number=6}{call=--framing}{display=Framing}"
		"{type=selector}{default=ft12}"
		"{tooltip=How frames are delimited on the line}\n");
	printf("value {arg=6}{value=ft12}{display=IEC 60870-5-101 FT1.2}{default=true}\n");
	printf("value {arg=6}{value=raw}{display=Raw bytes (no framing)}\n");
	printf("arg {number=7}{call=--protocol}{display=Payload protocol}"
		"{type=selector}{default=auto}"
		"{tooltip=Exported-PDU dissector for captured bytes. "
		"Auto: FT1.2->IEC101, raw->serial_raw (neutral; try-decode in UI)}\n");
	printf("value {arg=7}{value=auto}{display=Auto (from framing)}{default=true}\n");
	printf("value {arg=7}{value=serial_raw}{display=串口原始数据 (中性)}\n");
	printf("value {arg=7}{value=yushun_modbus}{display=禹舜MODBUS-下端电压硬压板}\n");
	printf("value {arg=7}{value=iec60870_101_frame}{display=IEC 60870-5-101}\n");
}

static void
print_help(const char *argv0)
{
	printf(" %s --extcap-interfaces\n", argv0);
	printf(" %s --extcap-interface=%s --extcap-dlts\n", argv0, SERIALDUMP_EXTCAP_INTERFACE);
	printf(" %s --extcap-interface=%s --extcap-config\n", argv0, SERIALDUMP_EXTCAP_INTERFACE);
	printf(" %s --extcap-interface=%s --port COM3 --baudrate 9600 --fifo myfifo --capture\n",
		argv0, SERIALDUMP_EXTCAP_INTERFACE);
	printf("\nOptions:\n");
	printf("  --help                      print this help\n");
	printf("  --version                   print the version\n");
	printf("  --port <COMx>               serial port to capture from\n");
	printf("  --baudrate <rate>           line speed, default 9600\n");
	printf("  --databits <7|8>            data bits, default 8\n");
	printf("  --parity <none|odd|even>    parity, default even\n");
	printf("  --stopbits <1|2>            stop bits, default 1\n");
	printf("  --linkaddrlen <1|2>         FT1.2 link address length, default 1\n");
	printf("  --framing <ft12|raw>        frame as FT1.2 (default) or raw chunks\n");
	printf("  --protocol <name|auto>      exported-PDU dissector name "
		"(auto: ft12->iec60870_101_frame, raw->serial_raw)\n");
	printf("  --fifo <path>               write the capture here\n");
	printf("  --capture                   start capturing\n");
}

/* --- Serial port --------------------------------------------------------- */

#ifdef _WIN32

/* Returns the first serial port that can actually be opened.
 * Tries COM1..COM64 so it does not depend on registry encoding. */
static bool
serial_first_port(char *out, size_t out_size)
{
	unsigned n;

	for (n = 1; n <= 64; n++) {
		char candidate[32];
		char path[64];
		HANDLE h;

		snprintf(candidate, sizeof(candidate), "COM%u", n);
		snprintf(path, sizeof(path), "\\\\.\\%s", candidate);
		h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
			OPEN_EXISTING, 0, NULL);
		if (h == INVALID_HANDLE_VALUE)
			continue;
		CloseHandle(h);
		snprintf(out, out_size, "%s", candidate);
		return true;
	}

	return false;
}

static bool
serial_open(HANDLE *out_handle)
{
	char path[128];
	static char auto_port[64];
	DCB dcb;
	COMMTIMEOUTS timeouts;
	HANDLE h;
	int parity;

	if (opt_port == NULL || *opt_port == '\0') {
		/* No port chosen: fall back to the first one present so a capture
		 * started with defaults still works. The buffer is static because
		 * opt_port keeps pointing at it. */
		if (!serial_first_port(auto_port, sizeof(auto_port))) {
			fprintf(stderr, "serialdump: no serial port found on this system\n");
			return false;
		}
		opt_port = auto_port;
	}
	if (_strnicmp(opt_port, "\\\\.\\", 4) == 0)
		snprintf(path, sizeof(path), "%s", opt_port);
	else
		snprintf(path, sizeof(path), "\\\\.\\%s", opt_port);

	h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
		OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "serialdump: cannot open %s: Windows error %lu\n",
			path, GetLastError());
		return false;
	}

	ZeroMemory(&dcb, sizeof(dcb));
	dcb.DCBlength = sizeof(dcb);
	if (!GetCommState(h, &dcb)) {
		fprintf(stderr, "serialdump: GetCommState failed: %lu\n", GetLastError());
		CloseHandle(h);
		return false;
	}

	if (_stricmp(opt_parity, "odd") == 0)
		parity = 1;
	else if (_stricmp(opt_parity, "even") == 0)
		parity = 2;
	else
		parity = 0;

	dcb.BaudRate = opt_baudrate;
	dcb.ByteSize = (BYTE)opt_databits;
	dcb.Parity = parity == 1 ? ODDPARITY : (parity == 2 ? EVENPARITY : NOPARITY);
	dcb.fParity = parity != 0 ? TRUE : FALSE;
	dcb.StopBits = opt_stopbits == 2 ? TWOSTOPBITS : ONESTOPBIT;
	dcb.fBinary = TRUE;
	dcb.fOutxCtsFlow = FALSE;
	dcb.fOutxDsrFlow = FALSE;
	dcb.fOutX = FALSE;
	dcb.fInX = FALSE;
	dcb.fDtrControl = DTR_CONTROL_ENABLE;
	dcb.fRtsControl = RTS_CONTROL_ENABLE;

	if (!SetCommState(h, &dcb)) {
		fprintf(stderr, "serialdump: SetCommState failed: %lu\n", GetLastError());
		CloseHandle(h);
		return false;
	}

	timeouts.ReadIntervalTimeout = 50;
	timeouts.ReadTotalTimeoutMultiplier = 0;
	timeouts.ReadTotalTimeoutConstant = 200;
	timeouts.WriteTotalTimeoutMultiplier = 0;
	timeouts.WriteTotalTimeoutConstant = 0;
	SetCommTimeouts(h, &timeouts);

	PurgeComm(h, PURGE_RXCLEAR | PURGE_TXCLEAR);

	*out_handle = h;
	return true;
}

static int
run_capture(void)
{
	HANDLE h = INVALID_HANDLE_VALUE;
	uint8_t *buf;
	ft12_framer framer;
	bool raw = strcmp(opt_framing, "raw") == 0;
	bool ok = true;

	if (opt_fifo == NULL || *opt_fifo == '\0') {
		fprintf(stderr, "serialdump: no --fifo given\n");
		return EXIT_FAILURE;
	}

	out = fopen(opt_fifo, "wb");
	if (out == NULL) {
		fprintf(stderr, "serialdump: cannot open %s: %s\n", opt_fifo, strerror(errno));
		return EXIT_FAILURE;
	}
	if (!write_pcap_header()) {
		fprintf(stderr, "serialdump: cannot write capture header\n");
		fclose(out);
		return EXIT_FAILURE;
	}

	if (!serial_open(&h)) {
		fclose(out);
		return EXIT_FAILURE;
	}

	fprintf(stderr, "serialdump: capturing on %s (%u baud, %u data bits, parity %s, %u stop bits)\n",
		opt_port, opt_baudrate, opt_databits, opt_parity, opt_stopbits);

	buf = (uint8_t *)malloc(READ_BUF_SIZE);
	if (buf == NULL) {
		CloseHandle(h);
		fclose(out);
		return EXIT_FAILURE;
	}

	memset(&framer, 0, sizeof(framer));
	framer.linkaddr_len = opt_linkaddrlen;

	while (ok) {
		DWORD got = 0;

		if (!ReadFile(h, buf, READ_BUF_SIZE, &got, NULL)) {
			fprintf(stderr, "serialdump: ReadFile failed: %lu\n", GetLastError());
			break;
		}
		if (got == 0)
			continue;

		if (raw)
			ok = write_frame(buf, (unsigned)got);
		else
			ok = ft12_feed(&framer, buf, (unsigned)got);
	}

	free(buf);
	CloseHandle(h);
	fclose(out);
	return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

#else /* _WIN32 */

static int
run_capture(void)
{
	fprintf(stderr, "serialdump: only Windows serial ports are supported\n");
	return EXIT_FAILURE;
}

#endif /* _WIN32 */

/* --- Command line -------------------------------------------------------- */

static bool
need_value(int argc, char **argv, int *i, const char **target)
{
	if (*i + 1 >= argc) {
		fprintf(stderr, "serialdump: option %s requires a value\n", argv[*i]);
		return false;
	}
	*target = argv[++(*i)];
	return true;
}

static bool
need_uint(int argc, char **argv, int *i, unsigned *target)
{
	const char *text;
	char *end = NULL;
	unsigned long value;

	if (!need_value(argc, argv, i, &text))
		return false;
	errno = 0;
	value = strtoul(text, &end, 10);
	if (errno != 0 || end == text || *end != '\0') {
		fprintf(stderr, "serialdump: invalid number: %s\n", text);
		return false;
	}
	*target = (unsigned)value;
	return true;
}

int
main(int argc, char *argv[])
{
	bool list_interfaces = false;
	bool list_dlts = false;
	bool show_config = false;
	bool do_version = false;
	int i;
	int ret = EXIT_FAILURE;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (strcmp(a, "--help") == 0) {
			print_help(argv[0]);
			return EXIT_SUCCESS;
		} else if (strcmp(a, "--version") == 0) {
			do_version = true;
		} else if (strcmp(a, "--extcap-interfaces") == 0) {
			list_interfaces = true;
		} else if (strcmp(a, "--extcap-dlts") == 0) {
			list_dlts = true;
		} else if (strcmp(a, "--extcap-config") == 0) {
			show_config = true;
		} else if (strcmp(a, "--capture") == 0) {
			opt_capture = true;
		} else if (strcmp(a, "--extcap-interface") == 0) {
			const char *iface;
			if (!need_value(argc, argv, &i, &iface))
				return EXIT_FAILURE;
			if (strcmp(iface, SERIALDUMP_EXTCAP_INTERFACE) != 0) {
				fprintf(stderr, "serialdump: invalid interface: %s\n", iface);
				return EXIT_FAILURE;
			}
		} else if (strncmp(a, "--extcap-interface=", 19) == 0) {
			if (strcmp(a + 19, SERIALDUMP_EXTCAP_INTERFACE) != 0) {
				fprintf(stderr, "serialdump: invalid interface: %s\n", a + 19);
				return EXIT_FAILURE;
			}
		} else if (strncmp(a, "--port=", 7) == 0) {
			opt_port = a + 7;
		} else if (strncmp(a, "--fifo=", 7) == 0) {
			opt_fifo = a + 7;
		} else if (strncmp(a, "--parity=", 9) == 0) {
			opt_parity = a + 9;
		} else if (strncmp(a, "--framing=", 10) == 0) {
			opt_framing = a + 10;
		} else if (strncmp(a, "--protocol=", 11) == 0) {
			opt_protocol = a + 11;
			if (strcmp(opt_protocol, "auto") == 0)
				opt_protocol = NULL;
		} else if (strncmp(a, "--extcap-version", 16) == 0) {
			/* Accepted and ignored. */
		} else if (strncmp(a, "--log-level", 11) == 0) {
			/* Accepted and ignored. */
		} else if (strcmp(a, "--fifo") == 0) {
			if (!need_value(argc, argv, &i, &opt_fifo))
				return EXIT_FAILURE;
		} else if (strcmp(a, "--port") == 0) {
			if (!need_value(argc, argv, &i, &opt_port))
				return EXIT_FAILURE;
		} else if (strcmp(a, "--parity") == 0) {
			if (!need_value(argc, argv, &i, &opt_parity))
				return EXIT_FAILURE;
		} else if (strcmp(a, "--framing") == 0) {
			if (!need_value(argc, argv, &i, &opt_framing))
				return EXIT_FAILURE;
		} else if (strcmp(a, "--protocol") == 0) {
			if (!need_value(argc, argv, &i, &opt_protocol))
				return EXIT_FAILURE;
			if (strcmp(opt_protocol, "auto") == 0)
				opt_protocol = NULL;
		} else if (strcmp(a, "--baudrate") == 0) {
			if (!need_uint(argc, argv, &i, &opt_baudrate))
				return EXIT_FAILURE;
		} else if (strcmp(a, "--databits") == 0) {
			if (!need_uint(argc, argv, &i, &opt_databits))
				return EXIT_FAILURE;
			if (opt_databits != 7 && opt_databits != 8) {
				fprintf(stderr, "serialdump: invalid data bits: %u\n", opt_databits);
				return EXIT_FAILURE;
			}
		} else if (strcmp(a, "--stopbits") == 0) {
			if (!need_uint(argc, argv, &i, &opt_stopbits))
				return EXIT_FAILURE;
			if (opt_stopbits != 1 && opt_stopbits != 2) {
				fprintf(stderr, "serialdump: invalid stop bits: %u\n", opt_stopbits);
				return EXIT_FAILURE;
			}
		} else if (strcmp(a, "--linkaddrlen") == 0) {
			if (!need_uint(argc, argv, &i, &opt_linkaddrlen))
				return EXIT_FAILURE;
			if (opt_linkaddrlen != 1 && opt_linkaddrlen != 2) {
				fprintf(stderr, "serialdump: invalid link address length: %u\n",
					opt_linkaddrlen);
				return EXIT_FAILURE;
			}
		} else if (strcmp(a, "--extcap-version") == 0 ||
		           strcmp(a, "--extcap-control-out") == 0 ||
		           strcmp(a, "--extcap-control-in") == 0) {
			/* Accepted and ignored. */
		} else if (a[0] == '-' && a[1] == '-') {
			fprintf(stderr, "serialdump: ignoring unknown option %s\n", a);
		}
	}

	if (list_interfaces) {
		printf("extcap {version=%s}\n", SERIALDUMP_VERSION);
		/* control=2 tells Wireshark the tool handles the quit message sent
		 * when a capture is stopped, so stopping is immediate. */
		printf("interface {value=%s}{control=2}{display=Serial (IEC 60870-5-101)}\n",
			SERIALDUMP_EXTCAP_INTERFACE);
		return EXIT_SUCCESS;
	}

	if (do_version) {
		printf("extcap {version=%s}\n", SERIALDUMP_VERSION);
		return EXIT_SUCCESS;
	}

	if (list_dlts) {
		printf("dlt {number=%d}{name=%s}{display=IEC 60870-5-101 FT1.2 frames over a serial port}\n",
			SERIALDUMP_LINKTYPE, SERIALDUMP_EXTCAP_INTERFACE);
		return EXIT_SUCCESS;
	}

	if (show_config) {
		list_config();
		return EXIT_SUCCESS;
	}

	if (opt_capture)
		ret = run_capture();

	return ret;
}
