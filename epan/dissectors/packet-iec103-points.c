/* packet-iec103-points.c
 *
 * IEC 60870-5-103 vendor point-table lookup (FUN/INF -> point name).
 *
 * Table format (UTF-8 CSV, first line is the header):
 *   vendor,fun,inf,name,asdu,datatype,unit,source,note
 *
 * Only fun/inf/name are used at dissection time. Load failures are silent: the
 * dissector keeps working with numeric FUN/INF. Tables are loaded once from the
 * protocol handoff (not from the dissection path) and live for the process
 * lifetime, like the other dissector data tables.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <wsutil/filesystem.h>
#include <wsutil/wslog.h>

#include "packet-iec103-points.h"

#define IEC103_POINTS_PATH_FMT "iec103/points/%s.csv"

bool iec103_points_show_names = true;

static GHashTable *points_tables[IEC103_POINTS_COUNT];
static bool points_loaded;

static const char *const points_file_names[IEC103_POINTS_COUNT] = {
	"sifang",
	"sznari",
	"nrelectric",
	"nari"
};

static const char *const points_display_names[IEC103_POINTS_COUNT] = {
	"四方",
	"深圳南瑞",
	"南瑞",
	"南自"
};

/* Strip UTF-8 BOM and trailing CR/LF/space in place. */
static char *
iec103_points_trim(char *s)
{
	if (!s)
		return s;
	if ((unsigned char)s[0] == 0xEF && (unsigned char)s[1] == 0xBB &&
	    (unsigned char)s[2] == 0xBF) {
		s += 3;
	}
	size_t len = strlen(s);
	while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' || s[len - 1] == ' ')) {
		s[--len] = '\0';
	}
	return s;
}

/* Split on ','; our CSVs never quote fields. */
static unsigned
iec103_points_split(char *line, char **fields, unsigned max_fields)
{
	unsigned n = 0;
	char *p = line;

	while (n < max_fields) {
		fields[n++] = p;
		char *comma = strchr(p, ',');
		if (!comma)
			break;
		*comma = '\0';
		p = comma + 1;
	}
	return n;
}

static void
iec103_points_load(iec103_points_vendor_t vendor)
{
	char *relative = g_strdup_printf(IEC103_POINTS_PATH_FMT, points_file_names[vendor]);
	char *path = get_datafile_path(relative, NULL);
	char *contents = NULL;
	gsize length = 0;
	GError *error = NULL;

	if (!g_file_get_contents(path, &contents, &length, &error)) {
		ws_debug("iec103: no point table for %s (%s)", points_file_names[vendor],
			 error ? error->message : "unknown");
		if (error)
			g_error_free(error);
		goto done;
	}

	points_tables[vendor] = g_hash_table_new_full(g_direct_hash, g_direct_equal,
						      NULL, g_free);

	gchar **lines = g_strsplit(contents, "\n", -1);
	bool header_seen = false;

	for (unsigned i = 0; lines[i]; i++) {
		char *line = iec103_points_trim(lines[i]);
		if (!line[0])
			continue;

		char *fields[9] = { NULL };
		unsigned nfields = iec103_points_split(line, fields, 9);

		if (!header_seen) {
			header_seen = true;
			if (g_ascii_strncasecmp(fields[0], "vendor", 6) == 0)
				continue;	/* header row */
		}
		if (nfields < 4)
			continue;

		unsigned fun = (unsigned)atoi(fields[1]);
		unsigned inf = (unsigned)atoi(fields[2]);
		if (fun > 255 || inf > 255 || fields[3][0] == '\0')
			continue;

		guint key = (fun << 8) | inf;
		if (g_hash_table_contains(points_tables[vendor], GUINT_TO_POINTER(key)))
			continue;	/* keep the first definition */

		g_hash_table_insert(points_tables[vendor], GUINT_TO_POINTER(key),
				    g_strdup(fields[3]));
	}
	g_strfreev(lines);
	g_free(contents);

	ws_debug("iec103: %s point table loaded (%u rows)", points_display_names[vendor],
		 g_hash_table_size(points_tables[vendor]));

done:
	g_free(path);
	g_free(relative);
}

void
iec103_points_init(void)
{
	if (points_loaded)
		return;
	points_loaded = true;

	for (int v = 0; v < IEC103_POINTS_COUNT; v++)
		iec103_points_load((iec103_points_vendor_t)v);
}

const char *
iec103_points_lookup(iec103_points_vendor_t vendor, uint8_t fun, uint8_t inf)
{
	if (vendor < 0 || vendor >= IEC103_POINTS_COUNT)
		return NULL;
	if (!iec103_points_show_names)
		return NULL;

	GHashTable *table = points_tables[vendor];
	if (table == NULL)
		return NULL;

	return (const char *)g_hash_table_lookup(table, GUINT_TO_POINTER((guint)((fun << 8) | inf)));
}

unsigned
iec103_points_rows(iec103_points_vendor_t vendor)
{
	if (vendor < 0 || vendor >= IEC103_POINTS_COUNT)
		return 0;
	if (points_tables[vendor] == NULL)
		return 0;
	return g_hash_table_size(points_tables[vendor]);
}

void
iec103_points_register_prefs(module_t *module, const char *title)
{
	if (!module)
		return;
	prefs_register_bool_preference(module, "show_point_names",
		"Show point names from the vendor point table",
		"Append the FUN/INF point name from iec103/points/<vendor>.csv "
		"to the function type / information number fields.",
		&iec103_points_show_names);
	(void)title;
}
