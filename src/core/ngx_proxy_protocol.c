
/*
 * Copyright (C) 2025 Web Server LLC
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_PROXY_PROTOCOL_V1_MAX_HEADER           107
#define NGX_PROXY_PROTOCOL_V2_MAX_HEADER           232

#define NGX_PROXY_PROTOCOL_AF_UNSPEC               0x00
#define NGX_PROXY_PROTOCOL_AF_INET                 0x01
#define NGX_PROXY_PROTOCOL_AF_INET6                0x02
#define NGX_PROXY_PROTOCOL_AF_UNIX                 0x03

#define NGX_PROXY_PROTOCOL_TYPE_UNSPEC             0x00
#define NGX_PROXY_PROTOCOL_TYPE_STREAM             0x01
#define NGX_PROXY_PROTOCOL_TYPE_DGRAM              0x02

/* TLV types */
#define NGX_PROXY_PROTOCOL_V2_TYPE_ALPN            0x01
#define NGX_PROXY_PROTOCOL_V2_TYPE_AUTHORITY       0x02
#define NGX_PROXY_PROTOCOL_V2_TYPE_CRC32C          0x03
#define NGX_PROXY_PROTOCOL_V2_TYPE_NOOP            0x04
#define NGX_PROXY_PROTOCOL_V2_TYPE_UNIQUE_ID       0x05
#define NGX_PROXY_PROTOCOL_V2_TYPE_SSL             0x20
#define NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_VERSION  0x21
#define NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_CN       0x22
#define NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_CIPHER   0x23
#define NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_SIG_ALG  0x24
#define NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_KEY_ALG  0x25
#define NGX_PROXY_PROTOCOL_V2_TYPE_NETNS           0x30

/* bits for "client" field of NGX_PROXY_PROTOCOL_V2_TYPE_SSL structure */
#define NGX_PROXY_PROTOCOL_V2_CLIENT_SSL           0x01
#define NGX_PROXY_PROTOCOL_V2_CLIENT_CERT_CONN     0x02
#define NGX_PROXY_PROTOCOL_V2_CLIENT_CERT_SESS     0x04

#define NGX_PROXY_PROTOCOL_V2_SIGNATURE  "\r\n\r\n\0\r\nQUIT\n"

#define ngx_proxy_protocol_parse_uint16(p)                                    \
    ( ((uint16_t) (p)[0] << 8)                                                \
    + (           (p)[1]) )

#define ngx_proxy_protocol_parse_uint32(p)                                    \
    ( ((uint32_t) (p)[0] << 24)                                               \
    + (           (p)[1] << 16)                                               \
    + (           (p)[2] << 8)                                                \
    + (           (p)[3]) )


typedef struct {
    u_char                                  signature[12];
    u_char                                  version_command;
    u_char                                  family_transport;
    u_char                                  len[2];
} ngx_proxy_protocol_header_t;


typedef struct {
    u_char                                  src_addr[4];
    u_char                                  dst_addr[4];
    u_char                                  src_port[2];
    u_char                                  dst_port[2];
} ngx_proxy_protocol_inet_addrs_t;


typedef struct {
    u_char                                  src_addr[16];
    u_char                                  dst_addr[16];
    u_char                                  src_port[2];
    u_char                                  dst_port[2];
} ngx_proxy_protocol_inet6_addrs_t;


typedef struct {
    u_char                                  src_addr[108];
    u_char                                  dst_addr[108];
} ngx_proxy_protocol_unix_addrs_t;


typedef struct {
    u_char                                  type;
    u_char                                  len[2];
} ngx_proxy_protocol_tlv_t;


typedef struct {
    u_char                                  client;
    u_char                                  verify[4];
} ngx_proxy_protocol_tlv_ssl_t;


typedef struct {
    ngx_str_t                               name;
    ngx_uint_t                              type;
} ngx_proxy_protocol_tlv_entry_t;


/* TLV complex value from configuration */
typedef struct {
    u_char                                  type;
    u_char                                  field;
    void                                   *cv; /* complex value */
} ngx_proxy_protocol_conf_tlv_t;


/* evaluated (from ngx_proxy_protocol_conf_tlv_t) TLV value */
typedef struct {
    u_char                                  type;
    ngx_str_t                               value;
} ngx_proxy_protocol_eval_tlv_t;


static u_char *ngx_proxy_protocol_read_addr(ngx_connection_t *c, u_char *p,
    u_char *last, ngx_str_t *addr);
static u_char *ngx_proxy_protocol_read_port(u_char *p, u_char *last,
    in_port_t *port, u_char sep);
static u_char *ngx_proxy_protocol_v2_read(ngx_connection_t *c, u_char *buf,
    u_char *last);
static u_char *ngx_proxy_protocol_v2_write(ngx_connection_t *c,
    ngx_proxy_protocol_conf_t *conf, u_char **buf_last);
#if (NGX_HAVE_INET6)
static ngx_inline void ngx_proxy_protocol_set_ipv6_addr(struct sockaddr *sa,
    u_char *addr, u_char *port);
#endif
static ngx_inline void ngx_proxy_protocol_set_ipv4_addr(struct sockaddr *sa,
    u_char *addr, u_char *port);
#if (NGX_HAVE_UNIX_DOMAIN)
static ngx_inline void ngx_proxy_protocol_set_unix_addr(struct sockaddr *sa,
    socklen_t socklen, u_char *addr);
#endif
static ngx_int_t ngx_proxy_protocol_eval_tlvs(ngx_connection_t *c,
    ngx_proxy_protocol_conf_t *conf, ngx_proxy_protocol_eval_tlv_t **tlvs,
    size_t *tlvs_nelts, size_t *len);
static ngx_inline u_char * ngx_proxy_protocol_write_tlv(ngx_connection_t *c,
    u_char type, ngx_str_t *value, u_char *buf);
static ngx_int_t ngx_proxy_protocol_lookup_tlv(ngx_connection_t *c,
    ngx_str_t *tlvs, ngx_uint_t type, ngx_str_t *value);
static ngx_int_t ngx_proxy_protocol_parse_tlv_type(ngx_str_t *name,
    u_char *tlv_type, u_char *tlv_field, ngx_flag_t *tlv_ssl_subtype);
static ngx_inline ngx_int_t ngx_proxy_protocol_conf_tlv_exist(ngx_array_t *a,
    u_char type);


static ngx_proxy_protocol_tlv_entry_t  ngx_proxy_protocol_tlv_entries[] = {
    { ngx_string("alpn"),       NGX_PROXY_PROTOCOL_V2_TYPE_ALPN },
    { ngx_string("authority"),  NGX_PROXY_PROTOCOL_V2_TYPE_AUTHORITY },
    { ngx_string("unique_id"),  NGX_PROXY_PROTOCOL_V2_TYPE_UNIQUE_ID },
    { ngx_string("ssl"),        NGX_PROXY_PROTOCOL_V2_TYPE_SSL },
    { ngx_string("netns"),      NGX_PROXY_PROTOCOL_V2_TYPE_NETNS },
    { ngx_null_string,          0x00 }
};


static ngx_proxy_protocol_tlv_entry_t  ngx_proxy_protocol_tlv_ssl_entries[] = {
    { ngx_string("version"),    NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_VERSION },
    { ngx_string("cn"),         NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_CN },
    { ngx_string("cipher"),     NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_CIPHER },
    { ngx_string("sig_alg"),    NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_SIG_ALG },
    { ngx_string("key_alg"),    NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_KEY_ALG },
    { ngx_null_string,          0x00 }
};


u_char *
ngx_proxy_protocol_read(ngx_connection_t *c, u_char *buf, u_char *last)
{
    size_t                 len;
    u_char                *p;
    ngx_proxy_protocol_t  *pp;

    p = buf;
    len = last - buf;

    if (len >= sizeof(ngx_proxy_protocol_header_t)
        && ngx_memcmp(p, NGX_PROXY_PROTOCOL_V2_SIGNATURE,
                      sizeof(NGX_PROXY_PROTOCOL_V2_SIGNATURE) - 1)
           == 0)
    {
        return ngx_proxy_protocol_v2_read(c, buf, last);
    }

    if (len < 8 || ngx_strncmp(p, "PROXY ", 6) != 0) {
        goto invalid;
    }

    p += 6;
    len -= 6;

    if (len >= 7 && ngx_strncmp(p, "UNKNOWN", 7) == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol unknown protocol");
        p += 7;
        goto skip;
    }

    if (len < 5 || ngx_strncmp(p, "TCP", 3) != 0
        || (p[3] != '4' && p[3] != '6') || p[4] != ' ')
    {
        goto invalid;
    }

    p += 5;

    pp = ngx_pcalloc(c->pool, sizeof(ngx_proxy_protocol_t));
    if (pp == NULL) {
        return NULL;
    }

    p = ngx_proxy_protocol_read_addr(c, p, last, &pp->src_addr);
    if (p == NULL) {
        goto invalid;
    }

    p = ngx_proxy_protocol_read_addr(c, p, last, &pp->dst_addr);
    if (p == NULL) {
        goto invalid;
    }

    p = ngx_proxy_protocol_read_port(p, last, &pp->src_port, ' ');
    if (p == NULL) {
        goto invalid;
    }

    p = ngx_proxy_protocol_read_port(p, last, &pp->dst_port, CR);
    if (p == NULL) {
        goto invalid;
    }

    if (p == last) {
        goto invalid;
    }

    if (*p++ != LF) {
        goto invalid;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "PROXY protocol src: %V %d, dst: %V %d",
                   &pp->src_addr, pp->src_port, &pp->dst_addr, pp->dst_port);

    c->proxy_protocol = pp;

    return p;

skip:

    for ( /* void */ ; p < last - 1; p++) {
        if (p[0] == CR && p[1] == LF) {
            return p + 2;
        }
    }

invalid:

    for (p = buf; p < last; p++) {
        if (*p == CR || *p == LF) {
            break;
        }
    }

    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                  "broken header: \"%*s\"", (size_t) (p - buf), buf);

    return NULL;
}


static u_char *
ngx_proxy_protocol_read_addr(ngx_connection_t *c, u_char *p, u_char *last,
    ngx_str_t *addr)
{
    size_t  len;
    u_char  ch, *pos;

    pos = p;

    for ( ;; ) {
        if (p == last) {
            return NULL;
        }

        ch = *p++;

        if (ch == ' ') {
            break;
        }

        if (ch != ':' && ch != '.'
            && (ch < 'a' || ch > 'f')
            && (ch < 'A' || ch > 'F')
            && (ch < '0' || ch > '9'))
        {
            return NULL;
        }
    }

    len = p - pos - 1;

    addr->data = ngx_pnalloc(c->pool, len);
    if (addr->data == NULL) {
        return NULL;
    }

    ngx_memcpy(addr->data, pos, len);
    addr->len = len;

    return p;
}


static u_char *
ngx_proxy_protocol_read_port(u_char *p, u_char *last, in_port_t *port,
    u_char sep)
{
    size_t      len;
    u_char     *pos;
    ngx_int_t   n;

    pos = p;

    for ( ;; ) {
        if (p == last) {
            return NULL;
        }

        if (*p++ == sep) {
            break;
        }
    }

    len = p - pos - 1;

    n = ngx_atoi(pos, len);
    if (n < 0 || n > 65535) {
        return NULL;
    }

    *port = (in_port_t) n;

    return p;
}


u_char *
ngx_proxy_protocol_write(ngx_connection_t *c, ngx_proxy_protocol_conf_t *conf,
    u_char **last)
{
    u_char      *buf, *pos, *end;
    ngx_uint_t   port, lport;

    if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
        return NULL;
    }

    if (conf->version == 2) {
        return ngx_proxy_protocol_v2_write(c, conf, last);
    }

    buf = ngx_pnalloc(c->pool, NGX_PROXY_PROTOCOL_V1_MAX_HEADER);
    if (buf == NULL) {
        return NULL;
    }

    pos = buf;
    end = pos + NGX_PROXY_PROTOCOL_V1_MAX_HEADER;

    switch (c->sockaddr->sa_family) {

    case AF_INET:
        pos = ngx_cpymem(pos, "PROXY TCP4 ", sizeof("PROXY TCP4 ") - 1);
        break;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        pos = ngx_cpymem(pos, "PROXY TCP6 ", sizeof("PROXY TCP6 ") - 1);
        break;
#endif

    default:
        return ngx_cpymem(pos, "PROXY UNKNOWN" CRLF,
                          sizeof("PROXY UNKNOWN" CRLF) - 1);
    }

    pos += ngx_sock_ntop(c->sockaddr, c->socklen, pos, end - pos, 0);

    *pos++ = ' ';

    pos += ngx_sock_ntop(c->local_sockaddr, c->local_socklen, pos, end - pos,
                         0);

    port = ngx_inet_get_port(c->sockaddr);
    lport = ngx_inet_get_port(c->local_sockaddr);

    pos = ngx_slprintf(pos, end, " %ui %ui" CRLF, port, lport);

    *last = pos;
    return buf;
}


static u_char *
ngx_proxy_protocol_v2_read(ngx_connection_t *c, u_char *buf, u_char *last)
{
    u_char                             *end;
    size_t                              len;
    socklen_t                           socklen;
    ngx_uint_t                          version, command, family, transport;
    ngx_sockaddr_t                      src_sockaddr, dst_sockaddr;
    ngx_proxy_protocol_t               *pp;
    ngx_proxy_protocol_header_t        *header;
    ngx_proxy_protocol_inet_addrs_t    *in;
#if (NGX_HAVE_INET6)
    ngx_proxy_protocol_inet6_addrs_t   *in6;
#endif

    header = (ngx_proxy_protocol_header_t *) buf;

    buf += sizeof(ngx_proxy_protocol_header_t);

    version = header->version_command >> 4;

    if (version != 2) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "unknown PROXY protocol version: %ui", version);
        return NULL;
    }

    len = ngx_proxy_protocol_parse_uint16(header->len);

    if ((size_t) (last - buf) < len) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "header is too large");
        return NULL;
    }

    end = buf + len;

    command = header->version_command & 0x0f;

    /* only PROXY is supported */
    if (command != 1) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 unsupported command %ui", command);
        return end;
    }

    transport = header->family_transport & 0x0f;

    /* only STREAM is supported */
    if (transport != 1) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 unsupported transport %ui",
                       transport);
        return end;
    }

    pp = ngx_pcalloc(c->pool, sizeof(ngx_proxy_protocol_t));
    if (pp == NULL) {
        return NULL;
    }

    family = header->family_transport >> 4;

    switch (family) {

    case NGX_PROXY_PROTOCOL_AF_INET:

        if ((size_t) (end - buf) < sizeof(ngx_proxy_protocol_inet_addrs_t)) {
            return NULL;
        }

        in = (ngx_proxy_protocol_inet_addrs_t *) buf;

        src_sockaddr.sockaddr_in.sin_family = AF_INET;
        src_sockaddr.sockaddr_in.sin_port = 0;
        ngx_memcpy(&src_sockaddr.sockaddr_in.sin_addr, in->src_addr, 4);

        dst_sockaddr.sockaddr_in.sin_family = AF_INET;
        dst_sockaddr.sockaddr_in.sin_port = 0;
        ngx_memcpy(&dst_sockaddr.sockaddr_in.sin_addr, in->dst_addr, 4);

        pp->src_port = ngx_proxy_protocol_parse_uint16(in->src_port);
        pp->dst_port = ngx_proxy_protocol_parse_uint16(in->dst_port);

        socklen = sizeof(struct sockaddr_in);

        buf += sizeof(ngx_proxy_protocol_inet_addrs_t);

        break;

#if (NGX_HAVE_INET6)

    case NGX_PROXY_PROTOCOL_AF_INET6:

        if ((size_t) (end - buf) < sizeof(ngx_proxy_protocol_inet6_addrs_t)) {
            return NULL;
        }

        in6 = (ngx_proxy_protocol_inet6_addrs_t *) buf;

        src_sockaddr.sockaddr_in6.sin6_family = AF_INET6;
        src_sockaddr.sockaddr_in6.sin6_port = 0;
        ngx_memcpy(&src_sockaddr.sockaddr_in6.sin6_addr, in6->src_addr, 16);

        dst_sockaddr.sockaddr_in6.sin6_family = AF_INET6;
        dst_sockaddr.sockaddr_in6.sin6_port = 0;
        ngx_memcpy(&dst_sockaddr.sockaddr_in6.sin6_addr, in6->dst_addr, 16);

        pp->src_port = ngx_proxy_protocol_parse_uint16(in6->src_port);
        pp->dst_port = ngx_proxy_protocol_parse_uint16(in6->dst_port);

        socklen = sizeof(struct sockaddr_in6);

        buf += sizeof(ngx_proxy_protocol_inet6_addrs_t);

        break;

#endif

    default:
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 unsupported address family %ui",
                       family);
        return end;
    }

    pp->src_addr.data = ngx_pnalloc(c->pool, NGX_SOCKADDR_STRLEN);
    if (pp->src_addr.data == NULL) {
        return NULL;
    }

    pp->src_addr.len = ngx_sock_ntop(&src_sockaddr.sockaddr, socklen,
                                     pp->src_addr.data, NGX_SOCKADDR_STRLEN, 0);

    pp->dst_addr.data = ngx_pnalloc(c->pool, NGX_SOCKADDR_STRLEN);
    if (pp->dst_addr.data == NULL) {
        return NULL;
    }

    pp->dst_addr.len = ngx_sock_ntop(&dst_sockaddr.sockaddr, socklen,
                                     pp->dst_addr.data, NGX_SOCKADDR_STRLEN, 0);

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "PROXY protocol v2 src: %V %d, dst: %V %d",
                   &pp->src_addr, pp->src_port, &pp->dst_addr, pp->dst_port);

    if (buf < end) {
        pp->tlvs.data = ngx_pnalloc(c->pool, end - buf);
        if (pp->tlvs.data == NULL) {
            return NULL;
        }

        ngx_memcpy(pp->tlvs.data, buf, end - buf);
        pp->tlvs.len = end - buf;
    }

    c->proxy_protocol = pp;

    return end;
}


static u_char *
ngx_proxy_protocol_v2_write(ngx_connection_t *c,
    ngx_proxy_protocol_conf_t *conf, u_char **buf_last)
{
    u_char                            *data_start, *buf;
    size_t                             len, tlv_ssl_len;
    size_t                             pp_hdr_len, tlvs_nelts;
    ngx_uint_t                         af, af_s, af_d, type, i;
    ngx_proxy_protocol_tlv_t          *tlv_ssl;
    ngx_proxy_protocol_header_t       *header;
    ngx_proxy_protocol_eval_tlv_t     *eval_tlv, *tlvs;
    ngx_proxy_protocol_inet_addrs_t   *in;
#if (NGX_HAVE_UNIX_DOMAIN)
    ngx_proxy_protocol_unix_addrs_t   *ud;
#endif
#if (NGX_HAVE_INET6)
    ngx_proxy_protocol_inet6_addrs_t  *in6;
#endif

    /* evaluate TLV values and calculate TLVs length */
    if (ngx_proxy_protocol_eval_tlvs(c, conf, &tlvs, &tlvs_nelts, &pp_hdr_len)
        != NGX_OK)
    {
        return NULL;
    }

    pp_hdr_len += NGX_PROXY_PROTOCOL_V2_MAX_HEADER;

    header = ngx_pnalloc(c->pool, pp_hdr_len);
    if (header == NULL) {
        return NULL;
    }

    buf = (u_char *) header;

    memcpy(header->signature, NGX_PROXY_PROTOCOL_V2_SIGNATURE,
           sizeof(header->signature));

    header->version_command = 0x20 | 0x01; /* version: 2, command: PROXY */

    buf += sizeof(ngx_proxy_protocol_header_t);
    data_start = buf;

    /* find out protocol family for the PROXY protocol header */

    af_s = c->sockaddr->sa_family;
    af_d = c->local_sockaddr->sa_family;

#if (NGX_HAVE_INET6)
    if (af_s == AF_INET6 || af_d == AF_INET6) {
        af = NGX_PROXY_PROTOCOL_AF_INET6;

    } else
#endif
    if (af_s == AF_INET || af_d == AF_INET) {
        af = NGX_PROXY_PROTOCOL_AF_INET;

#if (NGX_HAVE_INET6)
    } else if (af_s == AF_UNIX || af_d == AF_UNIX) {
        af = NGX_PROXY_PROTOCOL_AF_UNIX;
#endif

    } else {
        af = NGX_PROXY_PROTOCOL_AF_UNSPEC;
    }

    /* find out protocol type for the PROXY protocol header */
    switch (c->type) {

    case SOCK_STREAM:
        type = NGX_PROXY_PROTOCOL_TYPE_STREAM;
        break;

    case SOCK_DGRAM:
        type = NGX_PROXY_PROTOCOL_TYPE_DGRAM;
        break;

    default:
        type = NGX_PROXY_PROTOCOL_TYPE_UNSPEC;
        break;
    }

    header->family_transport = (af << 4) | type;

    /* fill the address structure */

    switch (af) {

    case NGX_PROXY_PROTOCOL_AF_INET:
        in = (ngx_proxy_protocol_inet_addrs_t *) buf;

        ngx_proxy_protocol_set_ipv4_addr(c->sockaddr,
                                         in->src_addr, in->src_port);
        ngx_proxy_protocol_set_ipv4_addr(c->local_sockaddr,
                                         in->dst_addr, in->dst_port);

        buf += sizeof(ngx_proxy_protocol_inet_addrs_t);

        break;

#if (NGX_HAVE_INET6)
    case NGX_PROXY_PROTOCOL_AF_INET6:
        in6 = (ngx_proxy_protocol_inet6_addrs_t *) buf;

        ngx_proxy_protocol_set_ipv6_addr(c->sockaddr,
                                         in6->src_addr, in6->src_port);
        ngx_proxy_protocol_set_ipv6_addr(c->local_sockaddr,
                                         in6->dst_addr, in6->dst_port);

        buf += sizeof(ngx_proxy_protocol_inet6_addrs_t);

        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    case NGX_PROXY_PROTOCOL_AF_UNIX:
        ud = (ngx_proxy_protocol_unix_addrs_t *) buf;

        ngx_proxy_protocol_set_unix_addr(c->sockaddr, c->socklen,
                                         ud->src_addr);
        ngx_proxy_protocol_set_unix_addr(c->local_sockaddr, c->local_socklen,
                                         ud->dst_addr);

        buf += sizeof(ngx_proxy_protocol_unix_addrs_t);

        break;
#endif
    }

    if (tlvs) {

        tlv_ssl = NULL;

        for (i = 0; i < tlvs_nelts; i++) {
            eval_tlv = &tlvs[i];

            /* if SSL TLV length need correction */
            if (eval_tlv->type == NGX_PROXY_PROTOCOL_V2_TYPE_SSL
                && (i + 1 < tlvs_nelts))
            {
                tlv_ssl = (ngx_proxy_protocol_tlv_t *) buf;
            }

            buf = ngx_proxy_protocol_write_tlv(c, eval_tlv->type,
                                               &eval_tlv->value, buf);
        }

        if (tlv_ssl) {
            tlv_ssl_len = (size_t) (buf - (u_char *) tlv_ssl
                                    - sizeof(ngx_proxy_protocol_tlv_t));

            tlv_ssl->len[0] = (u_char) ((tlv_ssl_len >> 8) & 0xff);
            tlv_ssl->len[1] = (u_char) (tlv_ssl_len & 0xff);
        }
    }

    len = (size_t) (buf - data_start);

    header->len[0] = (u_char) ((len >> 8) & 0xff);
    header->len[1] = (u_char) (len & 0xff);

    *buf_last = buf;
    return (u_char *) header;
}


static ngx_int_t
ngx_proxy_protocol_eval_tlvs(ngx_connection_t *c,
    ngx_proxy_protocol_conf_t *conf, ngx_proxy_protocol_eval_tlv_t **tlvsp,
    size_t *neltsp, size_t *len)
{
    size_t                          tlvs_nelts, cur;
    uint32_t                        verify_n;
    ngx_int_t                       verify;
    ngx_str_t                       verify_str;
    ngx_uint_t                      i;
    ngx_array_t                    *a, *as;
    ngx_proxy_protocol_tlv_ssl_t   *tlv_ssl_data;
    ngx_proxy_protocol_eval_tlv_t  *eval_tlv, *tlvs;
    ngx_proxy_protocol_conf_tlv_t  *conf_tlv;

    *tlvsp = NULL;
    *len = 0;

    a = conf->tlvs;
    as = conf->tlvs_ssl;

    /* no TLVs defined */
    if (a == NGX_CONF_UNSET_PTR && as == NGX_CONF_UNSET_PTR) {
        return NGX_OK;
    }

    /* number of TLV elements in both arrays */
    tlvs_nelts = ((a != NGX_CONF_UNSET_PTR) ? a->nelts : 0)
                  + ((as != NGX_CONF_UNSET_PTR) ? as->nelts : 0);

    tlvs = ngx_palloc(c->pool, sizeof(ngx_proxy_protocol_eval_tlv_t)
                               * tlvs_nelts);
    if (tlvs == NULL) {
        return NGX_ERROR;
    }

    cur = 0;

    /* TLV types processing */
    if (a != NGX_CONF_UNSET_PTR) {

        for (i = 0; i < a->nelts; i++) {
            conf_tlv = &((ngx_proxy_protocol_conf_tlv_t *) a->elts)[i];
            eval_tlv = &tlvs[cur];
            cur++;

            eval_tlv->type = conf_tlv->type;

            if (conf->complex_value(c->data, conf_tlv->cv, &eval_tlv->value)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            *len += sizeof(ngx_proxy_protocol_tlv_t) + eval_tlv->value.len;
        }
    }

    /* TLV SSL processing */
    if (as != NGX_CONF_UNSET_PTR) {

        /* the first entry is SSL TLV */
        conf_tlv = &((ngx_proxy_protocol_conf_tlv_t *) as->elts)[0];
        i = 0;
        tlv_ssl_data = NULL;

        /* create SSL TLV if entry has no binary value */
        if (conf_tlv->cv == NULL || conf_tlv->field != 0) {

            i = 1;
            eval_tlv = &tlvs[cur];
            cur++;

            tlv_ssl_data = ngx_pcalloc(c->pool,
                                       sizeof(ngx_proxy_protocol_tlv_ssl_t));
            if (tlv_ssl_data == NULL) {
                return NGX_ERROR;
            }

            eval_tlv->type = NGX_PROXY_PROTOCOL_V2_TYPE_SSL;
            eval_tlv->value.data = (u_char *) tlv_ssl_data;
            eval_tlv->value.len = sizeof(ngx_proxy_protocol_tlv_ssl_t);

            *len += sizeof(ngx_proxy_protocol_tlv_t) + eval_tlv->value.len;

            if (conf_tlv->field != 0) {

                /* now the only TLV SSL "verify" field is supported */
                if (conf->complex_value(c->data, conf_tlv->cv, &verify_str)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

                verify = ngx_atoi(verify_str.data, verify_str.len);
                if (verify == NGX_ERROR) {
                    ngx_log_error(NGX_LOG_CRIT, c->log, 0,
                                  "can't convert \"verify\" field of PROXY "
                                  "protocol TLV SSL");
                    return NGX_ERROR;
                }

                verify_n = htonl((uint32_t) verify);
                ngx_memcpy(tlv_ssl_data->verify, &verify_n,
                           sizeof(tlv_ssl_data->verify));
            }
        }

        for (/* void */; i < as->nelts; i++) {
            conf_tlv = &((ngx_proxy_protocol_conf_tlv_t *) as->elts)[i];
            eval_tlv = &tlvs[cur];
            cur++;

            eval_tlv->type = conf_tlv->type;

            if (conf->complex_value(c->data, conf_tlv->cv, &eval_tlv->value)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            if (eval_tlv->type == NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_CN) {
                tlv_ssl_data->client |= NGX_PROXY_PROTOCOL_V2_CLIENT_CERT_SESS;

#if (NGX_SSL)
                if (c->ssl) {

                    if (!SSL_session_reused(c->ssl->connection)) {
                        tlv_ssl_data->client |=
                                        NGX_PROXY_PROTOCOL_V2_CLIENT_CERT_CONN;
                    }
                }
#endif
            }

            *len += sizeof(ngx_proxy_protocol_tlv_t) + eval_tlv->value.len;
        }
    }

    *tlvsp = tlvs;
    *neltsp = tlvs_nelts;

    return NGX_OK;
}


#if (NGX_HAVE_INET6)
/*
 * Put or previously convert and put address belongs to arbitrary address
 * family to the IPv6 address structure.
 */
static ngx_inline void
ngx_proxy_protocol_set_ipv6_addr(struct sockaddr *sa,
                                 u_char *addr, u_char *port)
{
    struct sockaddr_in   *sin;
    struct sockaddr_in6  *sin6;
    static const u_char   rfc4291[] =   { 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0xff, 0xff };
    static const u_char   unix_ipv6[] = { 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x01 };

    switch (sa->sa_family) {

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;
        ngx_memcpy(addr, &sin6->sin6_addr, sizeof(sin6->sin6_addr));
        ngx_memcpy(port, &sin6->sin6_port, sizeof(sin6->sin6_port));
        break;

    case AF_INET:
        /* IPv4 mapping to IPv6 */
        sin = (struct sockaddr_in *) sa;
        ngx_memcpy(addr, rfc4291, sizeof(rfc4291));
        ngx_memcpy(addr + sizeof(rfc4291),
                   &sin->sin_addr, sizeof(sin->sin_addr));
        ngx_memcpy(port, &sin->sin_port, sizeof(sin->sin_port));
        break;

    case AF_UNIX:
        /* use "[::1]:0" address to mark UNIX socket address as local */
        ngx_memcpy(addr, unix_ipv6, sizeof(unix_ipv6));
        ngx_memzero(port, sizeof(sin6->sin6_port));
        break;

    default:
        /* use "[::]:0" for unknown protocol address family */
        ngx_memzero(addr, sizeof(sin6->sin6_addr));
        ngx_memzero(port, sizeof(sin6->sin6_port));
        break;
    }
}
#endif


/*
 * Put or previously convert and put address belongs to arbitrary address
 * family to the IPv4 address structure.
 */
static ngx_inline void
ngx_proxy_protocol_set_ipv4_addr(struct sockaddr *sa,
                                 u_char *addr, u_char *port)
{
    struct sockaddr_in   *sin;
    static const u_char   unix_ipv4[] = { 127, 0, 0, 1 };

    switch (sa->sa_family) {

    case AF_INET:
        sin = (struct sockaddr_in *) sa;
        ngx_memcpy(addr, &sin->sin_addr, sizeof(sin->sin_addr));
        ngx_memcpy(port, &sin->sin_port, sizeof(sin->sin_port));
        break;

    case AF_UNIX:
        /* use "127.0.0.1:0" address to mark UNIX socket address as local */
        ngx_memcpy(addr, unix_ipv4, sizeof(unix_ipv4));
        ngx_memzero(port, sizeof(sin->sin_port));
        break;

    default:
        /* use "0.0.0.0:0" for unknown protocol address family */
        ngx_memzero(addr, sizeof(sin->sin_addr));
        ngx_memzero(port, sizeof(sin->sin_port));
        break;
    }
}


#if (NGX_HAVE_UNIX_DOMAIN)
/*
 * Put address to Unix domain structure.
 */
static ngx_inline void
ngx_proxy_protocol_set_unix_addr(struct sockaddr *sa, socklen_t socklen,
                                 u_char *addr)
{
    struct sockaddr_un  *saun;

    if (sa->sa_family == AF_UNIX) {
        saun = (struct sockaddr_un *) sa;

        /* on Linux sockaddr might not include sun_path at all */

        if (socklen <= (socklen_t) offsetof(struct sockaddr_un, sun_path)) {
            *addr = '\0';

        } else {
            ngx_cpystrn(addr, (u_char *) saun->sun_path, 108);
        }

    } else {
        /* use "\0" for unknown protocol address family */
        *addr = '\0';
    }
}
#endif


static ngx_inline u_char *
ngx_proxy_protocol_write_tlv(ngx_connection_t *c, u_char type,
    ngx_str_t *value, u_char *buf)
{
    ngx_proxy_protocol_tlv_t  *tlv;

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "add PROXY protocol TLV %ui: %V", type, value);

    tlv = (ngx_proxy_protocol_tlv_t *) buf;

    tlv->type = type;
    tlv->len[0] = (u_char) ((value->len >> 8) & 0xff);
    tlv->len[1] = (u_char) (value->len & 0xff);

    buf += sizeof(ngx_proxy_protocol_tlv_t);

    ngx_memcpy(buf, value->data, value->len);

    buf += value->len;

    return buf;
}


ngx_int_t
ngx_proxy_protocol_get_tlv(ngx_connection_t *c, ngx_str_t *name,
    ngx_str_t *value)
{
    u_char                         tlv_type, tlv_field;
    uint32_t                       verify;
    ngx_str_t                      ssl, *tlvs;
    ngx_int_t                      rc;
    ngx_flag_t                     tlv_ssl_subtype;
    ngx_proxy_protocol_tlv_ssl_t  *tlv_ssl;

    if (c->proxy_protocol == NULL) {
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "PROXY protocol v2 get tlv \"%V\"", name);

    if (ngx_proxy_protocol_parse_tlv_type(name, &tlv_type, &tlv_field,
                                          &tlv_ssl_subtype)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "unknown PROXY protocol TLV \"%V\"", name);
        return NGX_ERROR;
    }

    tlvs = &c->proxy_protocol->tlvs;

    if (tlv_ssl_subtype || tlv_field) {

        rc = ngx_proxy_protocol_lookup_tlv(c, tlvs,
                                           NGX_PROXY_PROTOCOL_V2_TYPE_SSL,
                                           &ssl);
        if (rc != NGX_OK) {
            return rc;
        }

        if (ssl.len < sizeof(ngx_proxy_protocol_tlv_ssl_t)) {
            return NGX_ERROR;
        }

        /* now the only field is "verify" */
        if (tlv_field == 1) {

            tlv_ssl = (ngx_proxy_protocol_tlv_ssl_t *) ssl.data;
            verify = ngx_proxy_protocol_parse_uint32(tlv_ssl->verify);

            value->data = ngx_pnalloc(c->pool, NGX_INT32_LEN);
            if (value->data == NULL) {
                return NGX_ERROR;
            }

            value->len = ngx_sprintf(value->data, "%uD", verify)
                         - value->data;
            return NGX_OK;
        }

        ssl.data += sizeof(ngx_proxy_protocol_tlv_ssl_t);
        ssl.len -= sizeof(ngx_proxy_protocol_tlv_ssl_t);

        tlvs = &ssl;
    }

    return ngx_proxy_protocol_lookup_tlv(c, tlvs, tlv_type, value);
}


static ngx_int_t
ngx_proxy_protocol_lookup_tlv(ngx_connection_t *c, ngx_str_t *tlvs,
    ngx_uint_t type, ngx_str_t *value)
{
    u_char                    *p;
    size_t                     n, len;
    ngx_proxy_protocol_tlv_t  *tlv;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "PROXY protocol v2 lookup tlv:%02xi", type);

    p = tlvs->data;
    n = tlvs->len;

    while (n) {
        if (n < sizeof(ngx_proxy_protocol_tlv_t)) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "broken PROXY protocol TLV");
            return NGX_ERROR;
        }

        tlv = (ngx_proxy_protocol_tlv_t *) p;
        len = ngx_proxy_protocol_parse_uint16(tlv->len);

        p += sizeof(ngx_proxy_protocol_tlv_t);
        n -= sizeof(ngx_proxy_protocol_tlv_t);

        if (n < len) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "broken PROXY protocol TLV");
            return NGX_ERROR;
        }

        if (tlv->type == type) {
            value->data = p;
            value->len = len;
            return NGX_OK;
        }

        p += len;
        n -= len;
    }

    return NGX_DECLINED;
}


char *
ngx_proxy_protocol_conf_add_tlv(ngx_conf_t *cf,
    ngx_proxy_protocol_conf_t *conf, ngx_str_t *name, void *cv)
{
    u_char                           type, field;
    ngx_flag_t                       ssl_subtype;
    ngx_array_t                    **a;
    ngx_proxy_protocol_conf_tlv_t   *conf_tlv;

    /* find out the TLV type */
    if (ngx_proxy_protocol_parse_tlv_type(name, &type, &field, &ssl_subtype)
        != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid PROXY protocol TLV type \"%V\"", name);
        return NGX_CONF_ERROR;
    }

    /*
     * The following TLVs is stored within conf->tlvs_ssl:
     *     - SSL subtypes;
     *     - binary SSL TLV filled by complex value;
     *     - field ("verify") of SSL TLV;
     *     - default SSL TLV if subtypes present.
     *
     * The others TLVs is stored within conf->tlvs.
     */
    if (ssl_subtype || type == NGX_PROXY_PROTOCOL_V2_TYPE_SSL) {

        a = &conf->tlvs_ssl;

        if (*a == NGX_CONF_UNSET_PTR) {

            *a = ngx_array_create(cf->pool, 4,
                                  sizeof(ngx_proxy_protocol_conf_tlv_t));
            if (*a == NULL) {
                return NGX_CONF_ERROR;
            }

            /* the first element within conf->tlvs_ssl is SSL TLV itself */
            if (ssl_subtype) {

                conf_tlv = ngx_array_push(*a);
                if (conf_tlv == NULL) {
                    return NGX_CONF_ERROR;
                }

                /* default SSL TLV content */
                conf_tlv->type = NGX_PROXY_PROTOCOL_V2_TYPE_SSL;
                conf_tlv->field = 0;
                conf_tlv->cv = NULL;
            }

        } else {

            if (type == NGX_PROXY_PROTOCOL_V2_TYPE_SSL && field == 0) {
                return "PROXY protocol completed binary TLV type "
                       "\"ssl\" can't coexist with TLV subtypes";
            }

            /* get SSL TLV */
            conf_tlv = &((ngx_proxy_protocol_conf_tlv_t *) (*a)->elts)[0];

            if (conf_tlv->cv != NULL && conf_tlv->field == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "PROXY protocol TLV subtype \"%V\" can't "
                                   "coexist with completed binary \"ssl\" TLV",
                                   name);
                return NGX_CONF_ERROR;
            }

            if (field != 0) {

                if (conf_tlv->field != 0) {
                    return "duplicate PROXY protocol TLV field \"verify\"";
                }

                /* merge "verify" field to the default SSL TLV */
                conf_tlv->field = 1;
                conf_tlv->cv = cv;

                return NGX_CONF_OK;
            }
        }

    } else {

        a = &conf->tlvs;

        if (*a == NGX_CONF_UNSET_PTR) {
            *a = ngx_array_create(cf->pool, 4,
                                  sizeof(ngx_proxy_protocol_conf_tlv_t));
            if (*a == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    if (ngx_proxy_protocol_conf_tlv_exist(*a, type) == NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate PROXY protocol TLV type or field \"%V\"",
                           name);
        return NGX_CONF_ERROR;
    }

    conf_tlv = ngx_array_push(*a);
    if (conf_tlv == NULL) {
        return NGX_CONF_ERROR;
    }

    conf_tlv->type = type;
    conf_tlv->field = field;
    conf_tlv->cv = cv;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_proxy_protocol_parse_tlv_type(ngx_str_t *name, u_char *tlv_type,
    u_char *tlv_field, ngx_flag_t *tlv_ssl_subtype)
{
    u_char                          *p;
    size_t                           n;
    ngx_int_t                        type;
    ngx_proxy_protocol_tlv_entry_t  *te;

    p = name->data;
    n = name->len;

    /* SSL subtype */
    if (n >= 4 && ngx_strncmp(p, "ssl_", 4) == 0) {
        p += 4;
        n -= 4;

        /*
         * It's a special case.  The "verify" is not actually TLV type but
         * field within structure of type NGX_PROXY_PROTOCOL_V2_TYPE_SSL.
         * So return NGX_PROXY_PROTOCOL_V2_TYPE_SSL as a type and mark entry as
         * a "field".
         */
        if (n == 6 && ngx_strncmp("verify", p, 6) == 0) {
            *tlv_type = NGX_PROXY_PROTOCOL_V2_TYPE_SSL;
            *tlv_field = 1; /* there is just a single field for now */
            *tlv_ssl_subtype = 0;

            return NGX_OK;
        }

        *tlv_ssl_subtype = 1;
        te = ngx_proxy_protocol_tlv_ssl_entries;

    /* common type */
    } else {
        *tlv_ssl_subtype = 0;
        te = ngx_proxy_protocol_tlv_entries;
    }

    *tlv_field = 0;

    /* type in hexadecimal form */
    if (n >= 2 && p[0] == '0' && p[1] == 'x') {
        type = ngx_hextoi(p + 2, n - 2);
        if (type == NGX_ERROR) {
            return NGX_ERROR;
        }

        *tlv_type = type;
        return NGX_OK;
    }

    /* type in string form */
    for ( /* void */ ; te->type; te++) {

        if (te->name.len == n && ngx_strncmp(te->name.data, p, n) == 0) {
            *tlv_type = te->type;
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}


static ngx_inline ngx_int_t
ngx_proxy_protocol_conf_tlv_exist(ngx_array_t *a, u_char type)
{
    ngx_uint_t                      i;
    ngx_proxy_protocol_conf_tlv_t  *conf_tlv;

    for (i = 0; i < a->nelts; i++) {
        conf_tlv = &((ngx_proxy_protocol_conf_tlv_t *) a->elts)[i];

        if (conf_tlv->type == type) {
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}
