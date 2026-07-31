/*
 * Copyright (c) 2019 Danila Vershinin ( https://www.getpagespeed.com )
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>
#if (NGX_CONDITION)
#include <ngx_http_condition_module.h>
#endif


#define NGX_HTTP_SECURITY_HEADER_BYPASS              0
#define NGX_HTTP_SECURITY_HEADER_CLEAR               1

#define NGX_HTTP_XSS_HEADER_OFF                      2
#define NGX_HTTP_XSS_HEADER_ON                       3
#define NGX_HTTP_XSS_HEADER_BLOCK                    4

#define NGX_HTTP_FO_HEADER_SAME                      2
#define NGX_HTTP_FO_HEADER_DENY                      3

#define NGX_HTTP_RP_HEADER_STRICT_ORIG_WHEN_CROSS    2
#define NGX_HTTP_RP_HEADER_NO                        3
#define NGX_HTTP_RP_HEADER_DOWNGRADE                 4
#define NGX_HTTP_RP_HEADER_ORIGIN                    5
#define NGX_HTTP_RP_HEADER_ORIGIN_WHEN_CROSS         6
#define NGX_HTTP_RP_HEADER_SAME_ORIGIN               7
#define NGX_HTTP_RP_HEADER_STRICT_ORIGIN             8
#define NGX_HTTP_RP_HEADER_UNSAFE_URL                9

#define NGX_HTTP_XO_HEADER_NOSNIFF                   2

#define NGX_HTTP_HSTS_ON                             2


typedef struct {
#if (NGX_CONDITION)
#if (NGX_HTTP_SSL)
    ngx_array_t               *hsts;
    ngx_array_t               *hsts_includesubdomains;
    ngx_array_t               *hsts_preload;
    ngx_array_t               *hsts_max_age;
#endif

    ngx_array_t               *enable;
    ngx_array_t               *xss;
    ngx_array_t               *fo;
    ngx_array_t               *rp;
    ngx_array_t               *xo;
#else
#if (NGX_HTTP_SSL)
    ngx_uint_t                 hsts;
    ngx_flag_t                 hsts_includesubdomains;
    ngx_flag_t                 hsts_preload;
    time_t                     hsts_max_age;
#endif

    ngx_flag_t                 enable;
    ngx_uint_t                 xss;
    ngx_uint_t                 fo;
    ngx_uint_t                 rp;
    ngx_uint_t                 xo;
#endif

    ngx_hash_t                 types;
    ngx_array_t               *types_keys;
} ngx_http_security_headers_loc_conf_t;


#if (NGX_HTTP_SSL)

static ngx_conf_enum_t  ngx_http_hsts[] = { 
    { ngx_string("on"),     NGX_HTTP_HSTS_ON },
    { ngx_string("bypass"), NGX_HTTP_SECURITY_HEADER_BYPASS },
    { ngx_string("clear"),  NGX_HTTP_SECURITY_HEADER_CLEAR },
    { ngx_null_string, 0 }
};

#endif

static ngx_conf_enum_t  ngx_http_x_xss_protection[] = {
    { ngx_string("off"),    NGX_HTTP_XSS_HEADER_OFF },
    { ngx_string("on"),     NGX_HTTP_XSS_HEADER_ON },
    { ngx_string("block"),  NGX_HTTP_XSS_HEADER_BLOCK },
    { ngx_string("bypass"), NGX_HTTP_SECURITY_HEADER_BYPASS },
    { ngx_string("clear"),  NGX_HTTP_SECURITY_HEADER_CLEAR },
    { ngx_null_string, 0 }
};


static ngx_conf_enum_t  ngx_http_x_frame_options[] = {
    { ngx_string("sameorigin"),  NGX_HTTP_FO_HEADER_SAME },
    { ngx_string("deny"),        NGX_HTTP_FO_HEADER_DENY },
    { ngx_string("bypass"),      NGX_HTTP_SECURITY_HEADER_BYPASS },
    { ngx_string("clear"),       NGX_HTTP_SECURITY_HEADER_CLEAR },
    { ngx_null_string, 0 }
};


static ngx_conf_enum_t  ngx_http_referrer_policy[] = {

    { ngx_string("strict-origin-when-cross-origin"),
      NGX_HTTP_RP_HEADER_STRICT_ORIG_WHEN_CROSS},

    { ngx_string("no-referrer"),
      NGX_HTTP_RP_HEADER_NO },

    { ngx_string("no-referrer-when-downgrade"),
      NGX_HTTP_RP_HEADER_DOWNGRADE },

    { ngx_string("origin"),
      NGX_HTTP_RP_HEADER_ORIGIN },

    { ngx_string("origin-when-cross-origin"),
      NGX_HTTP_RP_HEADER_ORIGIN_WHEN_CROSS },

    { ngx_string("same-origin"),
      NGX_HTTP_RP_HEADER_SAME_ORIGIN },

    { ngx_string("strict-origin"),
      NGX_HTTP_RP_HEADER_STRICT_ORIGIN },

    { ngx_string("unsafe-url"),
      NGX_HTTP_RP_HEADER_UNSAFE_URL },

    { ngx_string("bypass"),
      NGX_HTTP_SECURITY_HEADER_BYPASS },

    { ngx_string("clear"),
      NGX_HTTP_SECURITY_HEADER_CLEAR },

    { ngx_null_string, 0 }
};


static ngx_conf_enum_t  ngx_http_x_content_type_options[] = {
    { ngx_string("nosniff"), NGX_HTTP_XO_HEADER_NOSNIFF },
    { ngx_string("bypass"),  NGX_HTTP_SECURITY_HEADER_BYPASS },
    { ngx_string("clear"),   NGX_HTTP_SECURITY_HEADER_CLEAR },
    { ngx_null_string, 0 }
};


static ngx_int_t ngx_http_security_headers_filter(ngx_http_request_t *r);
static void *ngx_http_security_headers_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_security_headers_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_security_headers_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_security_headers_set_by_search(ngx_http_request_t *r,
    ngx_str_t *key, ngx_str_t *value);


static ngx_str_t  ngx_http_security_headers_default_types[] = {
    ngx_string("text/html"),
    ngx_string("application/xhtml+xml"),
    ngx_string("text/xml"),
    ngx_string("text/plain"),
    ngx_null_string
};


static ngx_command_t  ngx_http_security_headers_commands[] = {

#if (NGX_HTTP_SSL)
    { ngx_string("hsts"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_FLAG,
#if (NGX_CONDITION)
      ngx_conf_set_conditional_enum_slot,
#else
      ngx_conf_set_enum_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_security_headers_loc_conf_t, hsts),
      &ngx_http_hsts },

    { ngx_string("hsts_max_age"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_FLAG,
#if (NGX_CONDITION)
      ngx_conf_set_conditional_sec_slot,
#else
      ngx_conf_set_sec_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_security_headers_loc_conf_t, hsts_max_age),
      NULL },

    { ngx_string("hsts_includesubdomains"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_FLAG,
#if (NGX_CONDITION)
      ngx_conf_set_conditional_flag_slot,
#else
      ngx_conf_set_flag_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_security_headers_loc_conf_t, hsts_includesubdomains),
      NULL },

    { ngx_string("hsts_preload"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_FLAG,
#if (NGX_CONDITION)
      ngx_conf_set_conditional_flag_slot,
#else
      ngx_conf_set_flag_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_security_headers_loc_conf_t, hsts_preload),
      NULL },
#endif

    { ngx_string("security_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_FLAG,
#if (NGX_CONDITION)
      ngx_conf_set_conditional_flag_slot,
#else
      ngx_conf_set_flag_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_security_headers_loc_conf_t, enable),
      NULL },

    { ngx_string("security_headers_x_xss_protection"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_TAKE1,
#if (NGX_CONDITION)
      ngx_conf_set_conditional_enum_slot,
#else
      ngx_conf_set_enum_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_security_headers_loc_conf_t, xss),
      &ngx_http_x_xss_protection },

     { ngx_string("security_headers_x_frame_options"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_TAKE1,
#if (NGX_CONDITION)
      ngx_conf_set_conditional_enum_slot,
#else
      ngx_conf_set_enum_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_security_headers_loc_conf_t, fo),
      &ngx_http_x_frame_options },

    { ngx_string("security_headers_referrer_policy"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_TAKE1,
#if (NGX_CONDITION)
      ngx_conf_set_conditional_enum_slot,
#else
      ngx_conf_set_enum_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_security_headers_loc_conf_t, rp),
      &ngx_http_referrer_policy },

    { ngx_string("security_headers_x_content_type_options"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_TAKE1,
#if (NGX_CONDITION)
      ngx_conf_set_conditional_enum_slot,
#else
      ngx_conf_set_enum_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_security_headers_loc_conf_t, xo),
      &ngx_http_x_content_type_options },

    { ngx_string("security_headers_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_security_headers_loc_conf_t, types_keys),
      &ngx_http_security_headers_default_types[0] },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_security_headers_filter_module_ctx = {
    NULL,                                         /* preconfiguration */
    ngx_http_security_headers_init,               /* postconfiguration */

    NULL,                                         /* create main configuration */
    NULL,                                         /* init main configuration */

    NULL,                                         /* create server configuration */
    NULL,                                         /* merge server configuration */

    ngx_http_security_headers_create_loc_conf,    /* create location config */
    ngx_http_security_headers_merge_loc_conf      /* merge location config */
};


ngx_module_t  ngx_http_security_headers_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_security_headers_filter_module_ctx, /* module context */
    ngx_http_security_headers_commands,           /* module directives */
    NGX_HTTP_MODULE,                              /* module type */
    NULL,                                         /* init master */
    NULL,                                         /* init module */
    NULL,                                         /* init process */
    NULL,                                         /* init thread */
    NULL,                                         /* exit thread */
    NULL,                                         /* exit process */
    NULL,                                         /* exit master */
    NGX_MODULE_V1_PADDING
};


/* next header filter in chain */
static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


/* header filter handler */
static ngx_int_t
ngx_http_security_headers_filter(ngx_http_request_t *r)
{
    ngx_http_security_headers_loc_conf_t  *slcf;

    ngx_str_t          key;
    ngx_str_t          val;
#if (NGX_HTTP_SSL)
    u_char             buf[128];
    u_char            *p;
#endif
#if (NGX_CONDITION)
    ngx_flag_t                           enable;
    ngx_uint_t                           xss, fo, rp, xo;
#if (NGX_HTTP_SSL)
    time_t                               hsts_max_age;
    ngx_flag_t                           hsts_includesubdomains, hsts_preload;
    ngx_uint_t                           hsts;
#endif
#endif

    slcf = ngx_http_get_module_loc_conf(r,
                                      ngx_http_security_headers_filter_module);

#if (NGX_HTTP_SSL)

#if (NGX_CONDITION)
    hsts = ngx_http_get_conditional_enum_value(r, slcf->hsts);
    hsts_max_age = ngx_http_get_conditional_sec_value(r, slcf->hsts_max_age);
    hsts_includesubdomains = ngx_http_get_conditional_flag_value(r,
                                 slcf->hsts_includesubdomains);
    hsts_preload = ngx_http_get_conditional_flag_value(r,
                       slcf->hsts_preload);

    if (hsts == NGX_HTTP_SECURITY_HEADER_BYPASS) {
#else
    if (slcf->hsts == NGX_HTTP_SECURITY_HEADER_BYPASS) {
#endif
        goto security_headers;
    }

    ngx_str_set(&key, "Strict-Transport-Security");

#if (NGX_CONDITION)
    if (hsts == NGX_HTTP_HSTS_ON && r->connection->ssl) {
#else
    if (slcf->hsts == NGX_HTTP_HSTS_ON && r->connection->ssl) {
#endif
        p = buf;
#if (NGX_CONDITION)
        p = ngx_snprintf(p, buf + sizeof(buf) - p, "max-age=%T",
            hsts_max_age);

        if (hsts_includesubdomains == 1) {
#else
        p = ngx_snprintf(p, buf + sizeof(buf) - p, "max-age=%T",
            slcf->hsts_max_age);

        if (slcf->hsts_includesubdomains == 1) {
#endif
            p = ngx_snprintf(p, buf + sizeof(buf) - p, "; includeSubDomains");
        }

#if (NGX_CONDITION)
        if (hsts_preload == 1) {
#else
        if (slcf->hsts_preload == 1) {
#endif
            p = ngx_snprintf(p, buf + sizeof(buf) - p, "; preload");
        }

        val.data = buf;
        val.len = p - buf;

    } else {
        ngx_str_null(&val);
    }

    ngx_http_security_headers_set_by_search(r, &key, &val);

#endif

#if (NGX_HTTP_SSL)
security_headers:
#endif

    /* add security headers other than hsts */
#if (NGX_CONDITION)
    enable = ngx_http_get_conditional_flag_value(r, slcf->enable);
    if (!enable) {
#else
    if (!slcf->enable) {
#endif
        return ngx_http_next_header_filter(r);
    }

    if (ngx_http_test_content_type(r, &slcf->types) == NULL) {
        return ngx_http_next_header_filter(r);
    }

#if (NGX_CONDITION)
    xss = ngx_http_get_conditional_enum_value(r, slcf->xss);
    fo = ngx_http_get_conditional_enum_value(r, slcf->fo);
    rp = ngx_http_get_conditional_enum_value(r, slcf->rp);
    xo = ngx_http_get_conditional_enum_value(r, slcf->xo);
#endif

    /* add X-Content-Type-Options */
    if (r->headers_out.status == NGX_HTTP_OK
#if (NGX_CONDITION)
        && NGX_HTTP_SECURITY_HEADER_BYPASS != xo)
#else
        && NGX_HTTP_SECURITY_HEADER_BYPASS != slcf->xo)
#endif
    {
        ngx_str_set(&key, "X-Content-Type-Options");

#if (NGX_CONDITION)
        if (xo == NGX_HTTP_XO_HEADER_NOSNIFF) {
#else
        if (slcf->xo == NGX_HTTP_XO_HEADER_NOSNIFF) {
#endif
            ngx_str_set(&val, "nosniff");

        } else {
            ngx_str_null(&val);
        }

        ngx_http_security_headers_set_by_search(r, &key, &val);
    }

    /* add X-XSS-Protection */
    if (r->headers_out.status != NGX_HTTP_NOT_MODIFIED
#if (NGX_CONDITION)
        && NGX_HTTP_SECURITY_HEADER_BYPASS != xss)
#else
        && NGX_HTTP_SECURITY_HEADER_BYPASS != slcf->xss)
#endif
    {
        ngx_str_set(&key, "X-XSS-Protection");

#if (NGX_CONDITION)
        switch (xss) {
#else
        switch (slcf->xss) {
#endif
        case NGX_HTTP_XSS_HEADER_OFF:
            ngx_str_set(&val, "0");
            break;

        case NGX_HTTP_XSS_HEADER_BLOCK:
            ngx_str_set(&val, "1; mode=block");
            break;

        case NGX_HTTP_XSS_HEADER_ON:
            ngx_str_set(&val, "1");
            break;

        default:
            ngx_str_null(&val);
        }

        ngx_http_security_headers_set_by_search(r, &key, &val);
    }

    /* add X-Frame-Options */
    if (r->headers_out.status != NGX_HTTP_NOT_MODIFIED
#if (NGX_CONDITION)
        && NGX_HTTP_SECURITY_HEADER_BYPASS != fo)
#else
        && NGX_HTTP_SECURITY_HEADER_BYPASS != slcf->fo)
#endif
    {
        ngx_str_set(&key, "X-Frame-Options");

#if (NGX_CONDITION)
        switch (fo) {
#else
        switch (slcf->fo) {
#endif
        case NGX_HTTP_FO_HEADER_SAME:
            ngx_str_set(&val, "SAMEORIGIN");
            break;

        case NGX_HTTP_FO_HEADER_DENY:
            ngx_str_set(&val, "DENY");
            break;

        default:
            ngx_str_null(&val);
        }
            
        ngx_http_security_headers_set_by_search(r, &key, &val);
    }

    /* add Referrer-Policy */
    if (r->headers_out.status != NGX_HTTP_NOT_MODIFIED
#if (NGX_CONDITION)
        && NGX_HTTP_SECURITY_HEADER_BYPASS != rp)
#else
        && NGX_HTTP_SECURITY_HEADER_BYPASS != slcf->rp)
#endif
    {
        ngx_str_set(&key, "Referrer-Policy");

#if (NGX_CONDITION)
        switch (rp) {
#else
        switch (slcf->rp) {
#endif

        case NGX_HTTP_RP_HEADER_STRICT_ORIG_WHEN_CROSS:
            ngx_str_set(&val, "strict-origin-when-cross-origin");
            break;

        case NGX_HTTP_RP_HEADER_NO:
            ngx_str_set(&val, "no-referrer");
            break;

        case NGX_HTTP_RP_HEADER_DOWNGRADE:
            ngx_str_set(&val, "no-referrer-when-downgrade");
            break;

        case NGX_HTTP_RP_HEADER_ORIGIN:
            ngx_str_set(&val, "origin");
            break;

        case NGX_HTTP_RP_HEADER_ORIGIN_WHEN_CROSS:
            ngx_str_set(&val, "origin-when-cross-origin");
            break;

        case NGX_HTTP_RP_HEADER_SAME_ORIGIN:
            ngx_str_set(&val, "same-origin");
            break;

        case NGX_HTTP_RP_HEADER_STRICT_ORIGIN:
            ngx_str_set(&val, "strict-origin");
            break;

        case NGX_HTTP_RP_HEADER_UNSAFE_URL:
            ngx_str_set(&val, "unsafe-url");
            break;

        default:
            ngx_str_null(&val);
        }

        ngx_http_security_headers_set_by_search(r, &key, &val);
    }

    /* proceed to the next handler in chain */
    return ngx_http_next_header_filter(r);
}


static void *
ngx_http_security_headers_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_security_headers_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_security_headers_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

#if !(NGX_CONDITION) && (NGX_HTTP_SSL)
    conf->hsts = NGX_CONF_UNSET_UINT;
    conf->hsts_max_age = NGX_CONF_UNSET;
    conf->hsts_includesubdomains = NGX_CONF_UNSET;
    conf->hsts_preload = NGX_CONF_UNSET_UINT;
#endif

#if !(NGX_CONDITION)
    conf->enable = NGX_CONF_UNSET;
    conf->xss = NGX_CONF_UNSET_UINT;
    conf->fo = NGX_CONF_UNSET_UINT;
    conf->rp = NGX_CONF_UNSET_UINT;
    conf->xo = NGX_CONF_UNSET_UINT;
#endif

    return conf;
}


static char *
ngx_http_security_headers_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_security_headers_loc_conf_t *prev = parent;
    ngx_http_security_headers_loc_conf_t *conf = child;

#if (NGX_CONDITION)
#if (NGX_HTTP_SSL)
    if (ngx_conf_merge_conditional_enum_value(cf, &conf->hsts, prev->hsts,
                                              NGX_HTTP_SECURITY_HEADER_BYPASS)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_conf_merge_conditional_flag_value(cf,
            &conf->hsts_includesubdomains, prev->hsts_includesubdomains, 0)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_conf_merge_conditional_flag_value(cf, &conf->hsts_preload,
                                              prev->hsts_preload, 0)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_conf_merge_conditional_sec_value(cf, &conf->hsts_max_age,
                                             prev->hsts_max_age, 31536000)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
#endif

    if (ngx_conf_merge_conditional_flag_value(cf, &conf->enable,
                                              prev->enable, 0)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_conf_merge_conditional_enum_value(cf, &conf->xss, prev->xss,
                                              NGX_HTTP_XSS_HEADER_OFF)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_conf_merge_conditional_enum_value(cf, &conf->fo, prev->fo,
                                              NGX_HTTP_FO_HEADER_SAME)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_conf_merge_conditional_enum_value(cf, &conf->rp, prev->rp,
            NGX_HTTP_RP_HEADER_STRICT_ORIG_WHEN_CROSS)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_conf_merge_conditional_enum_value(cf, &conf->xo, prev->xo,
                                              NGX_HTTP_XO_HEADER_NOSNIFF)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
#else
#if (NGX_HTTP_SSL)
    ngx_conf_merge_uint_value(conf->hsts, prev->hsts,
                         NGX_HTTP_SECURITY_HEADER_BYPASS);
    ngx_conf_merge_value(conf->hsts_includesubdomains,
        prev->hsts_includesubdomains, 0);
    ngx_conf_merge_value(conf->hsts_preload, prev->hsts_preload, 0);
    ngx_conf_merge_sec_value(conf->hsts_max_age, prev->hsts_max_age, 31536000);
#endif

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    ngx_conf_merge_uint_value(conf->xss, prev->xss,
                              NGX_HTTP_XSS_HEADER_OFF);
    ngx_conf_merge_uint_value(conf->fo, prev->fo,
                              NGX_HTTP_FO_HEADER_SAME);
    ngx_conf_merge_uint_value(conf->rp, prev->rp,
                              NGX_HTTP_RP_HEADER_STRICT_ORIG_WHEN_CROSS);
    ngx_conf_merge_uint_value(conf->xo, prev->xo,
                              NGX_HTTP_XO_HEADER_NOSNIFF);
#endif

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_security_headers_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_security_headers_init(ngx_conf_t *cf)
{
    /* install handler in header filter chain */

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_security_headers_filter;

    return NGX_OK;
}


static ngx_int_t
ngx_http_security_headers_set_by_search(ngx_http_request_t *r,
    ngx_str_t *key, ngx_str_t *value)
{
    ngx_list_part_t            *part;
    ngx_uint_t                  i;
    ngx_table_elt_t            *h;
    ngx_flag_t                  matched = 0;

    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        if (h[i].key.len == key->len
            && ngx_strncasecmp(h[i].key.data, key->data,
                               h[i].key.len) == 0)
        {
            goto matched;
        }

        /* not matched */
        continue;

matched:

        if (value->len == 0 || matched) {
            h[i].value.len = 0;
            h[i].hash = 0;

        } else {
            h[i].value = *value;
            h[i].hash = 1;
        }

        matched = 1;
    }

    if (matched){
        return NGX_OK;
    }

    /* XXX we still need to create header slot even if the value
     * is empty because some builtin headers like Last-Modified
     * relies on this to get cleared
     */
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    if (value->len == 0) {
        h->hash = 0;

    } else {
        h->hash = 1;
    }

    h->key = *key;
    h->value = *value;

    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    return NGX_OK;
}

