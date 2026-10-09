/** @file
 *
 * IEC 61850 SCD/SCL model index for ObjectReference description lookup.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>
#include <stdlib.h>

#include <glib.h>

#include <epan/proto.h>
#include <epan/iec61850_scd.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

typedef struct {
    char *desc;
    char *ln_type;
    GHashTable *doi_desc; /* "Pos" / "Pos.stVal" -> desc */
} scd_ln_info_t;

typedef struct {
    char *desc;
    GHashTable *da_desc; /* DA/SDO name -> desc */
} scd_do_type_t;

static GHashTable *scd_desc_table;   /* ref -> desc (owned) */
static GHashTable *scd_lntype_do;    /* lnType id -> (doName -> doType id or desc via nested) */
static GHashTable *scd_dotype;       /* doType id -> scd_do_type_t* */
static char       *scd_loaded_path;
static unsigned    scd_entry_count;

static void
scd_free_do_type(void *p)
{
    scd_do_type_t *t = (scd_do_type_t *)p;
    if (!t) {
        return;
    }
    g_free(t->desc);
    if (t->da_desc) {
        g_hash_table_destroy(t->da_desc);
    }
    g_free(t);
}

static void
scd_free_ln_info(void *p)
{
    scd_ln_info_t *ln = (scd_ln_info_t *)p;
    if (!ln) {
        return;
    }
    g_free(ln->desc);
    g_free(ln->ln_type);
    if (ln->doi_desc) {
        g_hash_table_destroy(ln->doi_desc);
    }
    g_free(ln);
}

static bool
scl_is(const xmlNode *n, const char *local)
{
    return n && n->type == XML_ELEMENT_NODE &&
           xmlStrcmp(n->name, BAD_CAST local) == 0;
}

static char *
scl_attr(const xmlNode *n, const char *name)
{
    xmlChar *v;
    char *out;

    if (!n) {
        return NULL;
    }
    v = xmlGetProp((xmlNode *)n, BAD_CAST name);
    if (!v) {
        return NULL;
    }
    out = g_strdup((const char *)v);
    xmlFree(v);
    return out;
}

static const char *
scl_attr_const(const xmlNode *n, const char *name, char **heap)
{
    g_free(*heap);
    *heap = scl_attr(n, name);
    return *heap ? *heap : "";
}

static void
scd_index_put(const char *key, const char *desc)
{
    char *norm;
    char *k;
    char *d;

    if (!key || !key[0] || !desc || !desc[0] || !scd_desc_table) {
        return;
    }
    if (g_hash_table_contains(scd_desc_table, key)) {
        return;
    }
    k = g_strdup(key);
    d = g_strdup(desc);
    g_hash_table_insert(scd_desc_table, k, d);
    scd_entry_count++;

    /* Also index '$' → '.' form */
    if (strchr(key, '$')) {
        norm = g_strdup(key);
        for (char *p = norm; *p; p++) {
            if (*p == '$') {
                *p = '.';
            }
        }
        if (!g_hash_table_contains(scd_desc_table, norm)) {
            g_hash_table_insert(scd_desc_table, norm, g_strdup(desc));
            scd_entry_count++;
        } else {
            g_free(norm);
        }
    }
}

static char *
scd_make_ln_name(const char *prefix, const char *ln_class, const char *inst)
{
    return g_strconcat(prefix ? prefix : "",
                       ln_class ? ln_class : "",
                       inst ? inst : "",
                       NULL);
}

static void
scd_index_both_ied(const char *ied, const char *ld_inst, const char *suffix,
                   const char *desc)
{
    char *with_ied;
    char *without_ied;

    if (!ld_inst || !suffix || !desc) {
        return;
    }
    without_ied = g_strconcat(ld_inst, "/", suffix, NULL);
    scd_index_put(without_ied, desc);
    g_free(without_ied);

    if (ied && ied[0]) {
        with_ied = g_strconcat(ied, ld_inst, "/", suffix, NULL);
        scd_index_put(with_ied, desc);
        g_free(with_ied);
    }
}

/* Collect DOI/SDI/DAI desc paths relative to LN (e.g. "Pos", "Pos.stVal"). */
static void
scd_collect_doi_paths(xmlNode *node, const char *prefix, GHashTable *out)
{
    for (xmlNode *c = node ? node->children : NULL; c; c = c->next) {
        char *name;
        char *desc;
        char *path;

        if (!scl_is(c, "DOI") && !scl_is(c, "SDI") && !scl_is(c, "DAI")) {
            continue;
        }
        name = scl_attr(c, "name");
        if (!name) {
            continue;
        }
        if (prefix && prefix[0]) {
            path = g_strconcat(prefix, ".", name, NULL);
        } else {
            path = g_strdup(name);
        }
        desc = scl_attr(c, "desc");
        if (desc && desc[0]) {
            if (!g_hash_table_contains(out, path)) {
                g_hash_table_insert(out, g_strdup(path), desc);
                desc = NULL;
            }
        }
        g_free(desc);
        scd_collect_doi_paths(c, path, out);
        g_free(path);
        g_free(name);
    }
}

static void
scd_parse_dotype(xmlNode *dotype_node)
{
    char *id;
    scd_do_type_t *t;

    id = scl_attr(dotype_node, "id");
    if (!id) {
        return;
    }
    t = g_new0(scd_do_type_t, 1);
    t->desc = scl_attr(dotype_node, "desc");
    t->da_desc = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    for (xmlNode *c = dotype_node->children; c; c = c->next) {
        char *name;
        char *desc;

        if (!scl_is(c, "DA") && !scl_is(c, "SDO") && !scl_is(c, "BDA")) {
            continue;
        }
        name = scl_attr(c, "name");
        desc = scl_attr(c, "desc");
        if (name && desc && desc[0]) {
            g_hash_table_insert(t->da_desc, name, desc);
            name = NULL;
            desc = NULL;
        }
        g_free(name);
        g_free(desc);
    }

    if (!scd_dotype) {
        scd_dotype = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, scd_free_do_type);
    }
    g_hash_table_insert(scd_dotype, id, t);
}

static void
scd_parse_lntype(xmlNode *lntype_node)
{
    char *id;
    GHashTable *do_map;

    id = scl_attr(lntype_node, "id");
    if (!id) {
        return;
    }
    do_map = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    for (xmlNode *c = lntype_node->children; c; c = c->next) {
        char *do_name;
        char *do_type;
        char *do_desc;

        if (!scl_is(c, "DO")) {
            continue;
        }
        do_name = scl_attr(c, "name");
        do_type = scl_attr(c, "type");
        do_desc = scl_attr(c, "desc");
        if (do_name) {
            /* value: "type\tdesc" */
            char *val = g_strconcat(do_type ? do_type : "", "\t",
                                    do_desc ? do_desc : "", NULL);
            g_hash_table_insert(do_map, do_name, val);
            do_name = NULL;
        }
        g_free(do_name);
        g_free(do_type);
        g_free(do_desc);
    }
    if (!scd_lntype_do) {
        scd_lntype_do = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                                              (GDestroyNotify)g_hash_table_destroy);
    }
    g_hash_table_insert(scd_lntype_do, id, do_map);
}

static char *
scd_resolve_fcda_desc(scd_ln_info_t *ln_info, const char *do_name, const char *da_name)
{
    char *path;
    const char *inst_desc;
    const char *tmpl;

    if (!do_name) {
        return NULL;
    }
    if (da_name && da_name[0]) {
        path = g_strconcat(do_name, ".", da_name, NULL);
    } else {
        path = g_strdup(do_name);
    }

    if (ln_info && ln_info->doi_desc) {
        inst_desc = g_hash_table_lookup(ln_info->doi_desc, path);
        if (inst_desc && inst_desc[0]) {
            g_free(path);
            return g_strdup(inst_desc);
        }
        /* try DO-only */
        inst_desc = g_hash_table_lookup(ln_info->doi_desc, do_name);
        if (inst_desc && inst_desc[0] && !(da_name && da_name[0])) {
            g_free(path);
            return g_strdup(inst_desc);
        }
    }

    if (ln_info && ln_info->ln_type) {
        /* Template: DO map value "type\tdesc" */
        GHashTable *do_map = scd_lntype_do ?
                             g_hash_table_lookup(scd_lntype_do, ln_info->ln_type) : NULL;
        if (do_map) {
            char *base_do = g_strdup(do_name);
            char *dot = strchr(base_do, '.');
            const char *packed;
            if (dot) {
                *dot = '\0';
            }
            packed = g_hash_table_lookup(do_map, base_do);
            if (packed) {
                char **parts = g_strsplit(packed, "\t", 2);
                const char *do_type_id = parts[0];
                const char *do_desc = parts[1];
                if (da_name && da_name[0] && scd_dotype && do_type_id && do_type_id[0]) {
                    scd_do_type_t *dt = g_hash_table_lookup(scd_dotype, do_type_id);
                    if (dt && dt->da_desc) {
                        tmpl = g_hash_table_lookup(dt->da_desc, da_name);
                        if (tmpl && tmpl[0]) {
                            char *out = g_strdup(tmpl);
                            g_strfreev(parts);
                            g_free(base_do);
                            g_free(path);
                            return out;
                        }
                    }
                }
                if (dot && scd_dotype && do_type_id && do_type_id[0]) {
                    scd_do_type_t *dt = g_hash_table_lookup(scd_dotype, do_type_id);
                    if (dt && dt->da_desc) {
                        tmpl = g_hash_table_lookup(dt->da_desc, dot + 1);
                        if (tmpl && tmpl[0]) {
                            char *out = g_strdup(tmpl);
                            g_strfreev(parts);
                            g_free(base_do);
                            g_free(path);
                            return out;
                        }
                    }
                }
                if (do_desc && do_desc[0]) {
                    char *out = g_strdup(do_desc);
                    g_strfreev(parts);
                    g_free(base_do);
                    g_free(path);
                    return out;
                }
                g_strfreev(parts);
            }
            g_free(base_do);
        }
    }

    g_free(path);
    return NULL;
}

static scd_ln_info_t *
scd_parse_ln_instance(xmlNode *ln_node)
{
    scd_ln_info_t *info = g_new0(scd_ln_info_t, 1);
    info->desc = scl_attr(ln_node, "desc");
    info->ln_type = scl_attr(ln_node, "lnType");
    info->doi_desc = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    scd_collect_doi_paths(ln_node, "", info->doi_desc);
    return info;
}

static void
scd_parse_dataset(xmlNode *ds_node, const char *ied, const char *ld_inst,
                  const char *ln_name, GHashTable *ln_cache)
{
    char *ds_name;
    char *ds_desc;
    char *suffix;
    scd_ln_info_t *ln_info;

    ds_name = scl_attr(ds_node, "name");
    ds_desc = scl_attr(ds_node, "desc");
    if (!ds_name) {
        g_free(ds_desc);
        return;
    }
    suffix = g_strconcat(ln_name, "$", ds_name, NULL);
    if (ds_desc && ds_desc[0]) {
        scd_index_both_ied(ied, ld_inst, suffix, ds_desc);
    }
    g_free(suffix);

    ln_info = ln_cache ? g_hash_table_lookup(ln_cache, ln_name) : NULL;

    for (xmlNode *fcda = ds_node->children; fcda; fcda = fcda->next) {
        char *fcda_ld;
        char *prefix;
        char *ln_class;
        char *ln_inst;
        char *do_name;
        char *da_name;
        char *fc;
        char *fcda_desc;
        char *member_ln;
        char *member_suffix;
        char *resolved;
        const char *use_ld;

        if (!scl_is(fcda, "FCDA")) {
            continue;
        }
        fcda_ld = scl_attr(fcda, "ldInst");
        prefix = scl_attr(fcda, "prefix");
        ln_class = scl_attr(fcda, "lnClass");
        ln_inst = scl_attr(fcda, "lnInst");
        do_name = scl_attr(fcda, "doName");
        da_name = scl_attr(fcda, "daName");
        fc = scl_attr(fcda, "fc");
        fcda_desc = scl_attr(fcda, "desc");

        use_ld = (fcda_ld && fcda_ld[0]) ? fcda_ld : ld_inst;
        member_ln = scd_make_ln_name(prefix, ln_class, ln_inst);

        if (do_name && fc) {
            if (da_name && da_name[0]) {
                member_suffix = g_strconcat(member_ln, "$", fc, "$", do_name, "$", da_name, NULL);
            } else {
                member_suffix = g_strconcat(member_ln, "$", fc, "$", do_name, NULL);
            }

            resolved = NULL;
            if (fcda_desc && fcda_desc[0]) {
                resolved = g_strdup(fcda_desc);
            } else {
                scd_ln_info_t *member_ln_info = NULL;
                if (ln_cache) {
                    member_ln_info = g_hash_table_lookup(ln_cache, member_ln);
                }
                if (!member_ln_info) {
                    member_ln_info = ln_info;
                }
                resolved = scd_resolve_fcda_desc(member_ln_info, do_name, da_name);
            }
            if (resolved) {
                scd_index_both_ied(ied, use_ld, member_suffix, resolved);
                /* Also index without FC (common in data-reference OptFld) */
                {
                    char *no_fc;
                    if (da_name && da_name[0]) {
                        no_fc = g_strconcat(member_ln, "$", do_name, "$", da_name, NULL);
                    } else {
                        no_fc = g_strconcat(member_ln, "$", do_name, NULL);
                    }
                    scd_index_both_ied(ied, use_ld, no_fc, resolved);
                    /* FCDA doName may embed '.' (e.g. DifAClc.phsA); MMS uses '$' segments */
                    if (strchr(do_name, '.')) {
                        char *mms_do = g_strdup(do_name);
                        char *mms_suffix;
                        char *mms_no_fc;
                        for (char *p = mms_do; *p; p++) {
                            if (*p == '.') {
                                *p = '$';
                            }
                        }
                        if (da_name && da_name[0]) {
                            mms_suffix = g_strconcat(member_ln, "$", fc, "$", mms_do, "$", da_name, NULL);
                            mms_no_fc = g_strconcat(member_ln, "$", mms_do, "$", da_name, NULL);
                        } else {
                            mms_suffix = g_strconcat(member_ln, "$", fc, "$", mms_do, NULL);
                            mms_no_fc = g_strconcat(member_ln, "$", mms_do, NULL);
                        }
                        scd_index_both_ied(ied, use_ld, mms_suffix, resolved);
                        scd_index_both_ied(ied, use_ld, mms_no_fc, resolved);
                        g_free(mms_suffix);
                        g_free(mms_no_fc);
                        g_free(mms_do);
                    }
                    g_free(no_fc);
                }
                g_free(resolved);
            }
            g_free(member_suffix);
        }

        g_free(fcda_ld);
        g_free(prefix);
        g_free(ln_class);
        g_free(ln_inst);
        g_free(do_name);
        g_free(da_name);
        g_free(fc);
        g_free(fcda_desc);
        g_free(member_ln);
    }

    g_free(ds_name);
    g_free(ds_desc);
}

static void
scd_parse_gse_control(xmlNode *node, const char *ied, const char *ld_inst,
                      const char *ln_name)
{
    char *cb_name;
    char *desc;
    char *dat_set;
    char *go_id;
    char *suffix;

    cb_name = scl_attr(node, "name");
    desc = scl_attr(node, "desc");
    dat_set = scl_attr(node, "datSet");
    go_id = scl_attr(node, "appID"); /* GOOSE appID often matches goID */
    if (!go_id) {
        go_id = scl_attr(node, "goID");
    }

    if (cb_name && desc && desc[0]) {
        suffix = g_strconcat(ln_name, "$GO$", cb_name, NULL);
        scd_index_both_ied(ied, ld_inst, suffix, desc);
        g_free(suffix);
    }
    if (dat_set && desc && desc[0]) {
        /* Also map control-block desc onto its dataset ref if dataset has no desc */
        suffix = g_strconcat(ln_name, "$", dat_set, NULL);
        scd_index_both_ied(ied, ld_inst, suffix, desc);
        g_free(suffix);
    }
    if (go_id && go_id[0] && desc && desc[0]) {
        scd_index_put(go_id, desc);
    }

    g_free(cb_name);
    g_free(desc);
    g_free(dat_set);
    g_free(go_id);
}

static void
scd_parse_smv_control(xmlNode *node, const char *ied, const char *ld_inst,
                      const char *ln_name)
{
    char *cb_name;
    char *desc;
    char *dat_set;
    char *smv_id;
    char *suffix;

    cb_name = scl_attr(node, "name");
    desc = scl_attr(node, "desc");
    dat_set = scl_attr(node, "datSet");
    smv_id = scl_attr(node, "smvID");
    if (!smv_id) {
        smv_id = scl_attr(node, "svID");
    }

    if (cb_name && desc && desc[0]) {
        suffix = g_strconcat(ln_name, "$MS$", cb_name, NULL);
        scd_index_both_ied(ied, ld_inst, suffix, desc);
        g_free(suffix);
    }
    if (dat_set && desc && desc[0]) {
        suffix = g_strconcat(ln_name, "$", dat_set, NULL);
        scd_index_both_ied(ied, ld_inst, suffix, desc);
        g_free(suffix);
    }
    if (smv_id && smv_id[0] && desc && desc[0]) {
        scd_index_put(smv_id, desc);
    }
    if (cb_name && cb_name[0] && desc && desc[0]) {
        scd_index_put(cb_name, desc);
    }

    g_free(cb_name);
    g_free(desc);
    g_free(dat_set);
    g_free(smv_id);
}

static void
scd_parse_ldevice(xmlNode *ld_node, const char *ied)
{
    char *ld_inst;
    GHashTable *ln_cache;
    char *prefix_h = NULL;
    char *class_h = NULL;
    char *inst_h = NULL;

    ld_inst = scl_attr(ld_node, "inst");
    if (!ld_inst) {
        return;
    }

    /* Pass 1: cache LN instance DOI/DAI descriptions */
    ln_cache = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, scd_free_ln_info);
    for (xmlNode *c = ld_node->children; c; c = c->next) {
        const char *ln_class;
        const char *prefix;
        const char *inst;
        char *ln_name;
        scd_ln_info_t *info;

        if (!scl_is(c, "LN0") && !scl_is(c, "LN")) {
            continue;
        }
        ln_class = scl_attr_const(c, "lnClass", &class_h);
        prefix = scl_attr_const(c, "prefix", &prefix_h);
        inst = scl_attr_const(c, "inst", &inst_h);
        if (!ln_class[0]) {
            ln_class = scl_is(c, "LN0") ? "LLN0" : "";
        }
        ln_name = scd_make_ln_name(prefix, ln_class, inst);
        info = scd_parse_ln_instance(c);
        if (info->desc && info->desc[0]) {
            scd_index_both_ied(ied, ld_inst, ln_name, info->desc);
        }
        g_hash_table_insert(ln_cache, ln_name, info);
    }

    /* Pass 2: DataSet / GSEControl / SampledValueControl */
    g_free(prefix_h); prefix_h = NULL;
    g_free(class_h); class_h = NULL;
    g_free(inst_h); inst_h = NULL;
    for (xmlNode *c = ld_node->children; c; c = c->next) {
        const char *ln_class;
        const char *prefix;
        const char *inst;
        char *ln_name;

        if (!scl_is(c, "LN0") && !scl_is(c, "LN")) {
            continue;
        }
        ln_class = scl_attr_const(c, "lnClass", &class_h);
        prefix = scl_attr_const(c, "prefix", &prefix_h);
        inst = scl_attr_const(c, "inst", &inst_h);
        if (!ln_class[0]) {
            ln_class = scl_is(c, "LN0") ? "LLN0" : "";
        }
        ln_name = scd_make_ln_name(prefix, ln_class, inst);
        for (xmlNode *ch = c->children; ch; ch = ch->next) {
            if (scl_is(ch, "DataSet")) {
                scd_parse_dataset(ch, ied, ld_inst, ln_name, ln_cache);
            } else if (scl_is(ch, "GSEControl")) {
                scd_parse_gse_control(ch, ied, ld_inst, ln_name);
            } else if (scl_is(ch, "SampledValueControl")) {
                scd_parse_smv_control(ch, ied, ld_inst, ln_name);
            }
        }
        g_free(ln_name);
    }

    g_free(prefix_h);
    g_free(class_h);
    g_free(inst_h);
    g_hash_table_destroy(ln_cache);
    g_free(ld_inst);
}

static void
scd_parse_ied(xmlNode *ied_node)
{
    char *ied_name = scl_attr(ied_node, "name");
    char *ied_desc = scl_attr(ied_node, "desc");

    if (ied_name && ied_desc && ied_desc[0]) {
        scd_index_put(ied_name, ied_desc);
    }

    for (xmlNode *ap = ied_node->children; ap; ap = ap->next) {
        if (!scl_is(ap, "AccessPoint")) {
            continue;
        }
        for (xmlNode *srv = ap->children; srv; srv = srv->next) {
            if (!scl_is(srv, "Server") && !scl_is(srv, "ServerAt")) {
                /* LDevice may also sit under AccessPoint directly in some files */
                if (scl_is(srv, "LDevice")) {
                    scd_parse_ldevice(srv, ied_name);
                }
                continue;
            }
            for (xmlNode *ld = srv->children; ld; ld = ld->next) {
                if (scl_is(ld, "LDevice")) {
                    scd_parse_ldevice(ld, ied_name);
                }
            }
        }
    }

    g_free(ied_name);
    g_free(ied_desc);
}

static void
scd_parse_templates(xmlNode *dtt)
{
    for (xmlNode *c = dtt->children; c; c = c->next) {
        if (scl_is(c, "LNodeType")) {
            scd_parse_lntype(c);
        } else if (scl_is(c, "DOType")) {
            scd_parse_dotype(c);
        }
    }
}

void
iec61850_scd_clear(void)
{
    if (scd_desc_table) {
        g_hash_table_destroy(scd_desc_table);
        scd_desc_table = NULL;
    }
    if (scd_lntype_do) {
        g_hash_table_destroy(scd_lntype_do);
        scd_lntype_do = NULL;
    }
    if (scd_dotype) {
        g_hash_table_destroy(scd_dotype);
        scd_dotype = NULL;
    }
    g_free(scd_loaded_path);
    scd_loaded_path = NULL;
    scd_entry_count = 0;
}

bool
iec61850_scd_load(const char *path, char **err)
{
    xmlDoc *doc;
    xmlNode *root;
    bool saw_ied = false;

    if (err) {
        *err = NULL;
    }
    if (!path || !path[0]) {
        if (err) {
            *err = g_strdup("SCD path is empty");
        }
        return false;
    }

    LIBXML_TEST_VERSION;

    doc = xmlReadFile(path, NULL,
                      XML_PARSE_NOBLANKS | XML_PARSE_NONET | XML_PARSE_NOERROR |
                      XML_PARSE_NOWARNING | XML_PARSE_HUGE);
    if (!doc) {
        if (err) {
            *err = g_strdup_printf("Failed to parse SCL file: %s", path);
        }
        return false;
    }

    root = xmlDocGetRootElement(doc);
    if (!root || (!scl_is(root, "SCL") && !scl_is(root, "scl"))) {
        xmlFreeDoc(doc);
        if (err) {
            *err = g_strdup("Root element is not SCL");
        }
        return false;
    }

    iec61850_scd_clear();
    scd_desc_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    /* Templates first so instance parsing can resolve DO/DA desc */
    for (xmlNode *c = root->children; c; c = c->next) {
        if (scl_is(c, "DataTypeTemplates")) {
            scd_parse_templates(c);
        }
    }
    for (xmlNode *c = root->children; c; c = c->next) {
        if (scl_is(c, "IED")) {
            scd_parse_ied(c);
            saw_ied = true;
        }
    }

    xmlFreeDoc(doc);

    if (!saw_ied) {
        iec61850_scd_clear();
        if (err) {
            *err = g_strdup("No IED elements found in SCL file");
        }
        return false;
    }

    scd_loaded_path = g_strdup(path);
    if (err && scd_entry_count == 0) {
        /* Still success — model loaded but no desc attributes */
        *err = NULL;
    }
    return true;
}

bool
iec61850_scd_loaded(void)
{
    return scd_desc_table != NULL && scd_loaded_path != NULL;
}

const char *
iec61850_scd_path(void)
{
    return scd_loaded_path;
}

const char *
iec61850_scd_lookup_desc(const char *ref)
{
    const char *d;
    const char *key;
    char *norm;

    if (!ref || !ref[0] || !scd_desc_table) {
        return NULL;
    }

    /* Strip accidental "k/n " ordinal prefix from display strings */
    key = ref;
    if (g_ascii_isdigit((guchar)ref[0])) {
        const char *p = ref;
        while (g_ascii_isdigit((guchar)*p)) {
            p++;
        }
        if (*p == '/') {
            p++;
            while (g_ascii_isdigit((guchar)*p)) {
                p++;
            }
            if (*p == ' ' && p[1]) {
                key = p + 1;
            }
        }
    }

    d = g_hash_table_lookup(scd_desc_table, key);
    if (d) {
        return d;
    }
    if (!strchr(key, '$') && !strchr(key, '.')) {
        return NULL;
    }
    norm = g_strdup(key);
    for (char *p = norm; *p; p++) {
        if (*p == '$') {
            *p = '.';
        }
    }
    d = g_hash_table_lookup(scd_desc_table, norm);
    if (!d && strchr(key, '.')) {
        /* Convert every '.' to '$' as a best-effort reverse normalize */
        g_free(norm);
        norm = g_strdup(key);
        for (char *p = norm; *p; p++) {
            if (*p == '.') {
                *p = '$';
            }
        }
        d = g_hash_table_lookup(scd_desc_table, norm);
    }
    g_free(norm);
    return d;
}

void
iec61850_scd_append_desc(proto_item *ti, const char *ref)
{
    const char *desc;

    if (!ti || !ref) {
        return;
    }
    desc = iec61850_scd_lookup_desc(ref);
    if (desc && desc[0]) {
        proto_item_append_text(ti, " (%s)", desc);
    }
}
