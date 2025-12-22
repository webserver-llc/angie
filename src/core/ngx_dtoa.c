
/*
 * Copyright (C) 2025 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_DTOA_HIDDEN_BIT     ((uint64_t) 0x0010000000000000)

#define NGX_DTOA_EXPONENT_MIN   -348
#define NGX_DTOA_EXPONENT_BIAS  1075

#define NGX_DTOA_SIGN_MASK      0x01
#define NGX_DTOA_EXPONENT_MASK  ((uint16_t) 0x07ff)
#define NGX_DTOA_SIGNIFIC_MASK  ((uint64_t) 0x000fffffffffffff)

#define NGX_DTOA_1_LOG_2_10     0.30102999566398114  /* 1 / lg(10) */


#ifdef NGX_HAVE_GCC_CLZLL
#define ngx_dtoa_leading_zeros(x)  (((x) == 0) ? 64 : __builtin_clzll(x))
#else
uint64_t
ngx_dtoa_leading_zeros(uint64_t x)
{
    uint64_t  n;

    if (x == 0) {
        return 64;
    }

    n = 0;

    while ((x & 0x8000000000000000) == 0) {
        n++;
        x <<= 1;
    }

    return n;
}
#endif


#ifdef NGX_HAVE_GCC_CEIL
#define ngx_dtoa_ceil(x)  __builtin_ceil((x))
#else
double
ngx_dtoa_ceil(double x)
{
    ngx_int_t  y;

    y = (ngx_int_t) x;

    if (y < 0 || (double) y == x) {
        return (double) y;
    }

    return (double) y + 1;
}
#endif


typedef struct {
    uint64_t   significand;
    ngx_int_t  exponent;
} ngx_dtoa_t;


static const ngx_dtoa_t ngx_dtoa_cache[] = {
    { 0xfa8fd5a0081c0288, -1220 },
    { 0xbaaee17fa23ebf76, -1193 },
    { 0x8b16fb203055ac76, -1166 },
    { 0xcf42894a5dce35ea, -1140 },
    { 0x9a6bb0aa55653b2d, -1113 },
    { 0xe61acf033d1a45df, -1087 },
    { 0xab70fe17c79ac6ca, -1060 },
    { 0xff77b1fcbebcdc4f, -1034 },
    { 0xbe5691ef416bd60c, -1007 },
    { 0x8dd01fad907ffc3c, -980 },
    { 0xd3515c2831559a83, -954 },
    { 0x9d71ac8fada6c9b5, -927 },
    { 0xea9c227723ee8bcb, -901 },
    { 0xaecc49914078536d, -874 },
    { 0x823c12795db6ce57, -847 },
    { 0xc21094364dfb5637, -821 },
    { 0x9096ea6f3848984f, -794 },
    { 0xd77485cb25823ac7, -768 },
    { 0xa086cfcd97bf97f4, -741 },
    { 0xef340a98172aace5, -715 },
    { 0xb23867fb2a35b28e, -688 },
    { 0x84c8d4dfd2c63f3b, -661 },
    { 0xc5dd44271ad3cdba, -635 },
    { 0x936b9fcebb25c996, -608 },
    { 0xdbac6c247d62a584, -582 },
    { 0xa3ab66580d5fdaf6, -555 },
    { 0xf3e2f893dec3f126, -529 },
    { 0xb5b5ada8aaff80b8, -502 },
    { 0x87625f056c7c4a8b, -475 },
    { 0xc9bcff6034c13053, -449 },
    { 0x964e858c91ba2655, -422 },
    { 0xdff9772470297ebd, -396 },
    { 0xa6dfbd9fb8e5b88f, -369 },
    { 0xf8a95fcf88747d94, -343 },
    { 0xb94470938fa89bcf, -316 },
    { 0x8a08f0f8bf0f156b, -289 },
    { 0xcdb02555653131b6, -263 },
    { 0x993fe2c6d07b7fac, -236 },
    { 0xe45c10c42a2b3b06, -210 },
    { 0xaa242499697392d3, -183 },
    { 0xfd87b5f28300ca0e, -157 },
    { 0xbce5086492111aeb, -130 },
    { 0x8cbccc096f5088cc, -103 },
    { 0xd1b71758e219652c, -77 },
    { 0x9c40000000000000, -50 },
    { 0xe8d4a51000000000, -24 },
    { 0xad78ebc5ac620000, 3 },
    { 0x813f3978f8940984, 30 },
    { 0xc097ce7bc90715b3, 56 },
    { 0x8f7e32ce7bea5c70, 83 },
    { 0xd5d238a4abe98068, 109 },
    { 0x9f4f2726179a2245, 136 },
    { 0xed63a231d4c4fb27, 162 },
    { 0xb0de65388cc8ada8, 189 },
    { 0x83c7088e1aab65db, 216 },
    { 0xc45d1df942711d9a, 242 },
    { 0x924d692ca61be758, 269 },
    { 0xda01ee641a708dea, 295 },
    { 0xa26da3999aef774a, 322 },
    { 0xf209787bb47d6b85, 348 },
    { 0xb454e4a179dd1877, 375 },
    { 0x865b86925b9bc5c2, 402 },
    { 0xc83553c5c8965d3d, 428 },
    { 0x952ab45cfa97a0b3, 455 },
    { 0xde469fbd99a05fe3, 481 },
    { 0xa59bc234db398c25, 508 },
    { 0xf6c69a72a3989f5c, 534 },
    { 0xb7dcbf5354e9bece, 561 },
    { 0x88fcf317f22241e2, 588 },
    { 0xcc20ce9bd35c78a5, 614 },
    { 0x98165af37b2153df, 641 },
    { 0xe2a0b5dc971f303a, 667 },
    { 0xa8d9d1535ce3b396, 694 },
    { 0xfb9b7cd9a4a7443c, 720 },
    { 0xbb764c4ca7a44410, 747 },
    { 0x8bab8eefb6409c1a, 774 },
    { 0xd01fef10a657842c, 800 },
    { 0x9b10a4e5e9913129, 827 },
    { 0xe7109bfba19c0c9d, 853 },
    { 0xac2820d9623bf429, 880 },
    { 0x80444b5e7aa7cf85, 907 },
    { 0xbf21e44003acdd2d, 933 },
    { 0x8e679c2f5e44ff8f, 960 },
    { 0xd433179d9c8cb841, 986 },
    { 0x9e19db92b4e31ba9, 1013 },
    { 0xeb96bf6ebadf77d9, 1039 },
    { 0xaf87023b9bf0ee6b, 1066 },
};


static const uint64_t ngx_dtoa_pow10[] = {
    1,
    10,
    100,
    1000,
    10000,
    100000,
    1000000,
    10000000,
    100000000,
    1000000000
};

static size_t ngx_dtoa_grisu2(u_char *p, ngx_dtoa_t *v);
static void ngx_dtoa_multiply(ngx_dtoa_t *x, ngx_dtoa_t *y);
static size_t ngx_dtoa_grisu2_digits(u_char *start, ngx_dtoa_t *w,
    ngx_dtoa_t *r, uint64_t delta, ngx_int_t *dec_exp);
static ngx_uint_t ngx_dtoa_dec_count(uint32_t n);
static void ngx_dtoa_round(u_char *p, size_t length, uint64_t delta,
    uint64_t rest, uint64_t kappa, uint64_t margin);
static size_t ngx_dtoa_output(u_char *start, size_t length, ngx_int_t point);
static size_t ngx_dtoa_output_exp(u_char *start, ngx_int_t exp);


size_t
ngx_dtoa(u_char *p, double value)
{
    uint8_t     s;
    uint16_t    e;
    uint64_t    f;
    ngx_dtoa_t  v;

    union {
        double    value;
        uint64_t  bits;
    } u;

    if (value == 0) {
        *p = '0';
        return 1;
    }

    u.value = value;

    s = (u.bits >> 63) & NGX_DTOA_SIGN_MASK;
    e = (u.bits >> 52) & NGX_DTOA_EXPONENT_MASK;
    f = u.bits & NGX_DTOA_SIGNIFIC_MASK;

    if (e != 0) {
        v.exponent = e - NGX_DTOA_EXPONENT_BIAS;
        v.significand = f + NGX_DTOA_HIDDEN_BIT;

    } else {
        v.exponent = 1 - NGX_DTOA_EXPONENT_BIAS;
        v.significand = f;
    }

    if (s) {
        *p++ = '-';
    }

    return (size_t) s + ngx_dtoa_grisu2(p, &v);
}


static size_t
ngx_dtoa_grisu2(u_char *p, ngx_dtoa_t *v)
{
    size_t      length;
    uint64_t    delta;
    ngx_int_t   mk, index, dec_exp;
    ngx_dtoa_t  cache, l, r, w;

    /* right boundary */

    r.significand = (v->significand << 1) + 1;
    r.exponent = v->exponent - 1;

    /* normalizing */

    while ((r.significand & (NGX_DTOA_HIDDEN_BIT << 1)) == 0) {
        r.significand <<= 1;
        r.exponent--;
    }

    r.significand <<= 10;
    r.exponent -= 10;

    /* left boundary */

    if (v->significand == NGX_DTOA_HIDDEN_BIT) {
        l.significand = (v->significand << 2) - 1;
        l.exponent = v->exponent - 2;

    } else {
        l.significand = (v->significand << 1) - 1;
        l.exponent = v->exponent - 1;
    }

    l.significand <<= l.exponent - r.exponent;
    l.exponent = r.exponent;

    /* processing power index */

    mk = (int) ngx_dtoa_ceil((-61 - r.exponent) * NGX_DTOA_1_LOG_2_10) + 347;

    /* cache step 2^3 = 8 */
    index = (mk >> 3) + 1;

    /* retrieving a cached power */

    cache = ngx_dtoa_cache[index];

    /* normalizing v */

    w = *v;

    w.significand <<= ngx_dtoa_leading_zeros(v->significand);
    w.exponent -= ngx_dtoa_leading_zeros(v->significand);

    ngx_dtoa_multiply(&w, &cache);
    ngx_dtoa_multiply(&l, &cache);
    ngx_dtoa_multiply(&r, &cache);

    l.significand++;
    r.significand--;

    delta = r.significand - l.significand;

    dec_exp = -(NGX_DTOA_EXPONENT_MIN + (index << 3));

    length = ngx_dtoa_grisu2_digits(p, &w, &r, delta, &dec_exp);

    return ngx_dtoa_output(p, length, length + dec_exp);
}


static void
ngx_dtoa_multiply(ngx_dtoa_t *x, ngx_dtoa_t *y)
{
    uint64_t  a, b, c, d, ac, bc, ad, bd, tmp;

    a = x->significand >> 32;
    c = y->significand >> 32;

    b = x->significand & 0xffffffff;
    d = y->significand & 0xffffffff;

    ac = a * c;
    bc = b * c;
    ad = a * d;
    bd = b * d;

    tmp = (bd >> 32) + (ad & 0xffffffff) + (bc & 0xffffffff);
    tmp += 1U << 31;

    x->significand = ac + (ad >> 32) + (bc >> 32) + (tmp >> 32);
    x->exponent = x->exponent + y->exponent + 64;
}


static size_t
ngx_dtoa_grisu2_digits(u_char *start, ngx_dtoa_t *w, ngx_dtoa_t *r,
    uint64_t delta, ngx_int_t *dec_exp)
{
    u_char      *p;
    uint32_t     integer, d;
    uint64_t     fraction, rest, margin;
    ngx_dtoa_t   one;
    ngx_uint_t   kappa;

    one.significand = ((uint64_t) 1) << -r->exponent;
    one.exponent = r->exponent;

    integer = r->significand >> -one.exponent;
    fraction = r->significand & (one.significand - 1);

    margin = r->significand - w->significand;

    p = start;

    kappa = ngx_dtoa_dec_count(integer);

    while (kappa > 0) {
        kappa--;

        d = integer / ngx_dtoa_pow10[kappa];
        integer %= ngx_dtoa_pow10[kappa];

        if (d != 0 || p != start) {
            *p++ = '0' + d;
        }

        rest = ((uint64_t) integer << -one.exponent) + fraction;

        if (rest < delta) {
            *dec_exp += kappa;

            ngx_dtoa_round(start, p - start, delta, rest,
                           ngx_dtoa_pow10[kappa] << -one.exponent, margin);

            return p - start;
        }
    }

    /* kappa == 0 */

    for ( ;; ) {
        fraction *= 10;
        delta *= 10;

        d = (uint32_t) (fraction >> -one.exponent);

        if (d != 0 || p != start) {
            *p++ = '0' + d;
        }

        fraction &= one.significand - 1;
        kappa++;

        if (fraction < delta) {
            *dec_exp -= kappa;
            margin *= (kappa < 10) ? ngx_dtoa_pow10[kappa] : 0;

            ngx_dtoa_round(start, p - start, delta, fraction,
                           one.significand, margin);

            return p - start;
        }
    }
}


static ngx_uint_t
ngx_dtoa_dec_count(uint32_t n)
{
    if (n < 10000) {
        if (n < 100) {
            return (n < 10) ? 1 : 2;
        }

        return (n < 1000) ? 3 : 4;
    }

    if (n < 1000000) {
        return (n < 100000) ? 5 : 6;
    }

    if (n < 100000000) {
        return (n < 10000000) ? 7 : 8;
    }

    return (n < 1000000000) ? 9 : 10;
}


static void
ngx_dtoa_round(u_char *p, size_t length, uint64_t delta, uint64_t rest,
    uint64_t kappa, uint64_t margin)
{
    while (rest < margin
           && delta - rest >= kappa
           && (rest + kappa < margin || margin - rest > rest + kappa - margin))
    {
        p[length - 1]--;
        rest += kappa;
    }
}


static size_t
ngx_dtoa_output(u_char *start, size_t length, ngx_int_t point)
{
    off_t   off;
    size_t  size;

    if ((ngx_int_t) length <= point && point <= 21) {
        /* 1234e7 -> 12340000000 */

        if (point - length > 0) {
            ngx_memset(&start[length], '0', point - (ngx_int_t) length);
        }

        return point;
    }

    if (0 < point && point <= 21) {
        /* 1234e-2 -> 12.34 */

        ngx_memmove(&start[point + 1], &start[point],
                    (ngx_int_t) length - point);
        start[point] = '.';

        return length + 1;
    }

    if (-6 < point && point <= 0) {
        /* 1234e-6 -> 0.001234 */

        off = 2 - point;
        ngx_memmove(&start[off], start, length);

        start[0] = '0';
        start[1] = '.';

        if (off - 2 > 0) {
            ngx_memset(&start[2], '0', off - 2);
        }

        return length + off;
    }

    /* 1234e30 -> 1.234e33 */

    if (length == 1) {
        /* 1e30 */

        start[1] = 'e';

        size = ngx_dtoa_output_exp(&start[2], point - 1);

        return size + 2;
    }

    ngx_memmove(&start[2], &start[1], length - 1);
    start[1] = '.';
    start[length + 1] = 'e';

    size = ngx_dtoa_output_exp(&start[length + 2], point - 1);

    return size + length + 2;
}


static size_t
ngx_dtoa_output_exp(u_char *start, ngx_int_t exp)
{
    u_char    *p;
    size_t     length;
    uint32_t   tmp;
    u_char     buf[4];

    /* -324 <= exp <= 308 */

    if (exp < 0) {
        *start++ = '-';
        exp = -exp;

    } else {
        *start++ = '+';
    }

    tmp = exp;
    p = buf + 3;

    do {
        *--p = tmp % 10 + '0';
        tmp /= 10;
    } while (tmp != 0);

    length = buf + 3 - p;

    ngx_memcpy(start, p, length);

    return length + 1;
}
