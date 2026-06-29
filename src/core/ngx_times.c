
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


static ngx_msec_t ngx_monotonic_time(time_t sec, ngx_uint_t msec);


/*
 * The time may be updated by signal handler or by several threads.
 * The time update operations are rare and require to hold the ngx_time_lock.
 * The time read operations are frequent, so they are lock-free and get time
 * values and strings from the current slot.  Thus thread may get the corrupted
 * values only if it is preempted while copying and then it is not scheduled
 * to run more than NGX_TIME_SLOTS seconds.
 */

#define NGX_TIME_SLOTS   64

static ngx_uint_t        slot;
static ngx_atomic_t      ngx_time_lock;

volatile ngx_msec_t      ngx_current_msec;
volatile ngx_time_t     *ngx_cached_time;
volatile ngx_str_t       ngx_cached_err_log_time;
volatile ngx_str_t       ngx_cached_http_time;
volatile ngx_str_t       ngx_cached_http_log_time;
volatile ngx_str_t       ngx_cached_http_log_iso8601;
volatile ngx_str_t       ngx_cached_syslog_time;

#if !(NGX_WIN32)

/*
 * localtime() and localtime_r() are not Async-Signal-Safe functions, therefore,
 * they must not be called by a signal handler, so we use the cached
 * GMT offset value. Fortunately the value is changed only two times a year.
 */

static ngx_int_t         cached_gmtoff;
#endif

static ngx_time_t        cached_time[NGX_TIME_SLOTS];
static u_char            cached_err_log_time[NGX_TIME_SLOTS]
                                    [sizeof("1970/09/28 12:00:00")];
static u_char            cached_http_time[NGX_TIME_SLOTS]
                                    [sizeof("Mon, 28 Sep 1970 06:00:00 GMT")];
static u_char            cached_http_log_time[NGX_TIME_SLOTS]
                                    [sizeof("28/Sep/1970:12:00:00 +0600")];
static u_char            cached_http_log_iso8601[NGX_TIME_SLOTS]
                                    [sizeof("1970-09-28T12:00:00+06:00")];
static u_char            cached_syslog_time[NGX_TIME_SLOTS]
                                    [sizeof("Sep 28 12:00:00")];


static char  *week[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

static ngx_str_t  week_full[] = {
    ngx_string("Sunday"),    ngx_string("Monday"),   ngx_string("Tuesday"),
    ngx_string("Wednesday"), ngx_string("Thursday"), ngx_string("Friday"),
    ngx_string("Saturday"),
};

static ngx_str_t  months_full[] = {
    ngx_string("January"), ngx_string("February"), ngx_string("March"),
    ngx_string("April"),   ngx_string("May"),      ngx_string("June"),
    ngx_string("July"),    ngx_string("August"),   ngx_string("September"),
    ngx_string("October"), ngx_string("November"), ngx_string("December"),
};


void
ngx_time_init(void)
{
    ngx_cached_err_log_time.len = sizeof("1970/09/28 12:00:00") - 1;
    ngx_cached_http_time.len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1;
    ngx_cached_http_log_time.len = sizeof("28/Sep/1970:12:00:00 +0600") - 1;
    ngx_cached_http_log_iso8601.len = sizeof("1970-09-28T12:00:00+06:00") - 1;
    ngx_cached_syslog_time.len = sizeof("Sep 28 12:00:00") - 1;

    ngx_cached_time = &cached_time[0];

    ngx_time_update();
}


void
ngx_time_update(void)
{
    u_char          *p0, *p1, *p2, *p3, *p4;
    ngx_tm_t         tm, gmt;
    time_t           sec;
    ngx_uint_t       msec;
    ngx_time_t      *tp;
    struct timeval   tv;

    if (!ngx_trylock(&ngx_time_lock)) {
        return;
    }

    ngx_gettimeofday(&tv);

    sec = tv.tv_sec;
    msec = tv.tv_usec / 1000;

    ngx_current_msec = ngx_monotonic_time(sec, msec);

    tp = &cached_time[slot];

    if (tp->sec == sec) {
        tp->msec = msec;
        ngx_unlock(&ngx_time_lock);
        return;
    }

    if (slot == NGX_TIME_SLOTS - 1) {
        slot = 0;
    } else {
        slot++;
    }

    tp = &cached_time[slot];

    tp->sec = sec;
    tp->msec = msec;

    ngx_gmtime(sec, &gmt);


    p0 = &cached_http_time[slot][0];

    (void) ngx_sprintf(p0, "%s, %02d %s %4d %02d:%02d:%02d GMT",
                       week[gmt.ngx_tm_wday], gmt.ngx_tm_mday,
                       months[gmt.ngx_tm_mon - 1], gmt.ngx_tm_year,
                       gmt.ngx_tm_hour, gmt.ngx_tm_min, gmt.ngx_tm_sec);

#if (NGX_HAVE_GETTIMEZONE)

    tp->gmtoff = ngx_gettimezone();
    ngx_gmtime(sec + tp->gmtoff * 60, &tm);

#elif (NGX_HAVE_GMTOFF)

    ngx_localtime(sec, &tm);
    cached_gmtoff = (ngx_int_t) (tm.ngx_tm_gmtoff / 60);
    tp->gmtoff = cached_gmtoff;

#else

    ngx_localtime(sec, &tm);
    cached_gmtoff = ngx_timezone(tm.ngx_tm_isdst);
    tp->gmtoff = cached_gmtoff;

#endif


    p1 = &cached_err_log_time[slot][0];

    (void) ngx_sprintf(p1, "%4d/%02d/%02d %02d:%02d:%02d",
                       tm.ngx_tm_year, tm.ngx_tm_mon,
                       tm.ngx_tm_mday, tm.ngx_tm_hour,
                       tm.ngx_tm_min, tm.ngx_tm_sec);


    p2 = &cached_http_log_time[slot][0];

    (void) ngx_sprintf(p2, "%02d/%s/%d:%02d:%02d:%02d %c%02i%02i",
                       tm.ngx_tm_mday, months[tm.ngx_tm_mon - 1],
                       tm.ngx_tm_year, tm.ngx_tm_hour,
                       tm.ngx_tm_min, tm.ngx_tm_sec,
                       tp->gmtoff < 0 ? '-' : '+',
                       ngx_abs(tp->gmtoff / 60), ngx_abs(tp->gmtoff % 60));

    p3 = &cached_http_log_iso8601[slot][0];

    (void) ngx_sprintf(p3, "%4d-%02d-%02dT%02d:%02d:%02d%c%02i:%02i",
                       tm.ngx_tm_year, tm.ngx_tm_mon,
                       tm.ngx_tm_mday, tm.ngx_tm_hour,
                       tm.ngx_tm_min, tm.ngx_tm_sec,
                       tp->gmtoff < 0 ? '-' : '+',
                       ngx_abs(tp->gmtoff / 60), ngx_abs(tp->gmtoff % 60));

    p4 = &cached_syslog_time[slot][0];

    (void) ngx_sprintf(p4, "%s %2d %02d:%02d:%02d",
                       months[tm.ngx_tm_mon - 1], tm.ngx_tm_mday,
                       tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec);

    ngx_memory_barrier();

    ngx_cached_time = tp;
    ngx_cached_http_time.data = p0;
    ngx_cached_err_log_time.data = p1;
    ngx_cached_http_log_time.data = p2;
    ngx_cached_http_log_iso8601.data = p3;
    ngx_cached_syslog_time.data = p4;

    ngx_unlock(&ngx_time_lock);
}


static ngx_msec_t
ngx_monotonic_time(time_t sec, ngx_uint_t msec)
{
#if (NGX_HAVE_CLOCK_MONOTONIC)
    struct timespec  ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    sec = ts.tv_sec;
    msec = ts.tv_nsec / 1000000;

#endif

    return (ngx_msec_t) sec * 1000 + msec;
}


#if !(NGX_WIN32)

void
ngx_time_sigsafe_update(void)
{
    u_char          *p, *p2;
    ngx_tm_t         tm;
    time_t           sec;
    ngx_time_t      *tp;
    struct timeval   tv;

    if (!ngx_trylock(&ngx_time_lock)) {
        return;
    }

    ngx_gettimeofday(&tv);

    sec = tv.tv_sec;

    tp = &cached_time[slot];

    if (tp->sec == sec) {
        ngx_unlock(&ngx_time_lock);
        return;
    }

    if (slot == NGX_TIME_SLOTS - 1) {
        slot = 0;
    } else {
        slot++;
    }

    tp = &cached_time[slot];

    tp->sec = 0;

    ngx_gmtime(sec + cached_gmtoff * 60, &tm);

    p = &cached_err_log_time[slot][0];

    (void) ngx_sprintf(p, "%4d/%02d/%02d %02d:%02d:%02d",
                       tm.ngx_tm_year, tm.ngx_tm_mon,
                       tm.ngx_tm_mday, tm.ngx_tm_hour,
                       tm.ngx_tm_min, tm.ngx_tm_sec);

    p2 = &cached_syslog_time[slot][0];

    (void) ngx_sprintf(p2, "%s %2d %02d:%02d:%02d",
                       months[tm.ngx_tm_mon - 1], tm.ngx_tm_mday,
                       tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec);

    ngx_memory_barrier();

    ngx_cached_err_log_time.data = p;
    ngx_cached_syslog_time.data = p2;

    ngx_unlock(&ngx_time_lock);
}

#endif


u_char *
ngx_http_time(u_char *buf, time_t t)
{
    ngx_tm_t  tm;

    ngx_gmtime(t, &tm);

    return ngx_sprintf(buf, "%s, %02d %s %4d %02d:%02d:%02d GMT",
                       week[tm.ngx_tm_wday],
                       tm.ngx_tm_mday,
                       months[tm.ngx_tm_mon - 1],
                       tm.ngx_tm_year,
                       tm.ngx_tm_hour,
                       tm.ngx_tm_min,
                       tm.ngx_tm_sec);
}


u_char *
ngx_http_cookie_time(u_char *buf, time_t t)
{
    ngx_tm_t  tm;

    ngx_gmtime(t, &tm);

    /*
     * Netscape 3.x does not understand 4-digit years at all and
     * 2-digit years more than "37"
     */

    return ngx_sprintf(buf,
                       (tm.ngx_tm_year > 2037) ?
                                         "%s, %02d-%s-%d %02d:%02d:%02d GMT":
                                         "%s, %02d-%s-%02d %02d:%02d:%02d GMT",
                       week[tm.ngx_tm_wday],
                       tm.ngx_tm_mday,
                       months[tm.ngx_tm_mon - 1],
                       (tm.ngx_tm_year > 2037) ? tm.ngx_tm_year:
                                                 tm.ngx_tm_year % 100,
                       tm.ngx_tm_hour,
                       tm.ngx_tm_min,
                       tm.ngx_tm_sec);
}


void
ngx_gmtime(time_t t, ngx_tm_t *tp)
{
    ngx_int_t   yday;
    ngx_uint_t  sec, min, hour, mday, mon, year, wday, days, leap;

    /* the calculation is valid for positive time_t only */

    if (t < 0) {
        t = 0;
    }

    days = t / 86400;
    sec = t % 86400;

    /*
     * no more than 4 year digits supported,
     * truncate to December 31, 9999, 23:59:59
     */

    if (days > 2932896) {
        days = 2932896;
        sec = 86399;
    }

    /* January 1, 1970 was Thursday */

    wday = (4 + days) % 7;

    hour = sec / 3600;
    sec %= 3600;
    min = sec / 60;
    sec %= 60;

    /*
     * the algorithm based on Gauss' formula,
     * see src/core/ngx_parse_time.c
     */

    /* days since March 1, 1 BC */
    days = days - (31 + 28) + 719527;

    /*
     * The "days" should be adjusted to 1 only, however, some March 1st's go
     * to previous year, so we adjust them to 2.  This causes also shift of the
     * last February days to next year, but we catch the case when "yday"
     * becomes negative.
     */

    year = (days + 2) * 400 / (365 * 400 + 100 - 4 + 1);

    yday = days - (365 * year + year / 4 - year / 100 + year / 400);

    if (yday < 0) {
        leap = (year % 4 == 0) && (year % 100 || (year % 400 == 0));
        yday = 365 + leap + yday;
        year--;
    }

    /*
     * The empirical formula that maps "yday" to month.
     * There are at least 10 variants, some of them are:
     *     mon = (yday + 31) * 15 / 459
     *     mon = (yday + 31) * 17 / 520
     *     mon = (yday + 31) * 20 / 612
     */

    mon = (yday + 31) * 10 / 306;

    /* the Gauss' formula that evaluates days before the month */

    mday = yday - (367 * mon / 12 - 30) + 1;

    if (yday >= 306) {

        year++;
        mon -= 10;

        /*
         * there is no "yday" in Win32 SYSTEMTIME
         *
         * yday -= 306;
         */

    } else {

        mon += 2;

        /*
         * there is no "yday" in Win32 SYSTEMTIME
         *
         * yday += 31 + 28 + leap;
         */
    }

    tp->ngx_tm_sec = (ngx_tm_sec_t) sec;
    tp->ngx_tm_min = (ngx_tm_min_t) min;
    tp->ngx_tm_hour = (ngx_tm_hour_t) hour;
    tp->ngx_tm_mday = (ngx_tm_mday_t) mday;
    tp->ngx_tm_mon = (ngx_tm_mon_t) mon;
    tp->ngx_tm_year = (ngx_tm_year_t) year;
    tp->ngx_tm_wday = (ngx_tm_wday_t) wday;
}


/*
 * Computes the exact maximum number of bytes ngx_format_time() can write
 * for the given format string.
 */
size_t
ngx_format_time_max_len(ngx_str_t *format)
{
    u_char  *p, *end;
    size_t   len;

    len = 0;
    p = format->data;
    end = p + format->len;

    while (p < end) {
        if (*p != '%') {
            len++;
            p++;
            continue;
        }

        p++;  /* skip '%' */

        if (p == end) {
            break;
        }

        switch (*p++) {
        case 'A': len += sizeof("Wednesday") - 1; break;  /* 9 */
        case 'B': len += sizeof("September") - 1; break;  /* 9 */
        case 'Z': len += sizeof("+03:00") - 1;    break;  /* 6 */
        case 'z': len += sizeof("+0300") - 1;     break;  /* 5 */
        case 'Y': len += 4;                       break;
        case 'L': len += 3;                       break;
        case 'a': case 'b': case 'h': len += 3;   break;
        case 'y': case 'm': case 'd': case 'e':
        case 'H': case 'I': case 'M': case 'S':
        case 'p': case 'P':
            len += 2;
            break;
        case 'n': case 't': case '%':
            len += 1;
            break;
        default:
            len += 2;  /* '%' + unknown char passed through */
            break;
        }
    }

    return len;
}


/*
 * supported specifiers:
 *    %Y    4-digit year
 *    %y    2-digit year
 *    %m    month (01-12)
 *    %d    day of month (01-31)
 *    %e    day of month, space-padded ( 1-31)
 *    %H    hour (00-23)
 *    %I    hour (01-12)
 *    %M    minute (00-59)
 *    %S    second (00-59)
 *    %L    milliseconds (000-999)
 *    %p    AM/PM
 *    %P    am/pm
 *    %a    abbreviated weekday name (Sun-Sat)
 *    %A    full weekday name (Sunday-Saturday)
 *    %b    abbreviated month name (Jan-Dec)
 *    %h    same as %b
 *    %B    full month name (January-December)
 *    %z    timezone offset (+0300)
 *    %Z    timezone offset, ISO 8601 (+03:00)
 *    %n    newline
 *    %t    tab
 *    %%    literal %
 *
 * All wall-clock fields (%Y, %y, %m, %d, %e, %H, %I, %M, %S, %p, %P,
 * %a, %A, %b, %h, %B) are computed in the timezone given by tp->gmtoff.
 * The %z and %Z specifiers output that same offset.
 */

u_char *
ngx_format_time(u_char *buf, ngx_str_t *format, ngx_time_t *tp)
{
    u_char      *p, *fmt, *end;
    ngx_tm_t     tm;
    ngx_int_t    gmtoff;
    ngx_uint_t   hour12;

    ngx_gmtime(tp->sec + tp->gmtoff * 60, &tm);
    gmtoff = tp->gmtoff;

    p = buf;
    fmt = format->data;
    end = fmt + format->len;

    while (fmt < end) {
        if (*fmt != '%') {
            *p++ = *fmt++;
            continue;
        }

        fmt++;  /* skip '%' */

        if (fmt == end) {
            break;
        }

        switch (*fmt) {

        case 'Y':
            p = ngx_sprintf(p, "%04d", tm.ngx_tm_year);
            break;

        case 'y':
            p = ngx_sprintf(p, "%02d", tm.ngx_tm_year % 100);
            break;

        case 'm':
            p = ngx_sprintf(p, "%02d", tm.ngx_tm_mon);
            break;

        case 'd':
            p = ngx_sprintf(p, "%02d", tm.ngx_tm_mday);
            break;

        case 'e':
            p = ngx_sprintf(p, "%2d", tm.ngx_tm_mday);
            break;

        case 'H':
            p = ngx_sprintf(p, "%02d", tm.ngx_tm_hour);
            break;

        case 'I':
            hour12 = tm.ngx_tm_hour % 12;
            if (hour12 == 0) {
                hour12 = 12;
            }
            p = ngx_sprintf(p, "%02ui", hour12);
            break;

        case 'M':
            p = ngx_sprintf(p, "%02d", tm.ngx_tm_min);
            break;

        case 'S':
            p = ngx_sprintf(p, "%02d", tm.ngx_tm_sec);
            break;

        case 'L':
            p = ngx_sprintf(p, "%03M", tp->msec);
            break;

        case 'p':
            p = ngx_cpymem(p, tm.ngx_tm_hour < 12 ? "AM" : "PM", 2);
            break;

        case 'P':
            p = ngx_cpymem(p, tm.ngx_tm_hour < 12 ? "am" : "pm", 2);
            break;

        case 'a':
            p = ngx_cpymem(p, week[tm.ngx_tm_wday], 3);
            break;

        case 'A':
            p = ngx_cpymem(p, week_full[tm.ngx_tm_wday].data,
                              week_full[tm.ngx_tm_wday].len);
            break;

        case 'b':
        case 'h':
            p = ngx_cpymem(p, months[tm.ngx_tm_mon - 1], 3);
            break;

        case 'B':
            p = ngx_cpymem(p, months_full[tm.ngx_tm_mon - 1].data,
                              months_full[tm.ngx_tm_mon - 1].len);
            break;

        case 'z':
            p = ngx_sprintf(p, "%c%02i%02i",
                            gmtoff < 0 ? '-' : '+',
                            ngx_abs(gmtoff / 60),
                            ngx_abs(gmtoff % 60));
            break;

        case 'Z':
            p = ngx_sprintf(p, "%c%02i:%02i",
                            gmtoff < 0 ? '-' : '+',
                            ngx_abs(gmtoff / 60),
                            ngx_abs(gmtoff % 60));
            break;

        case 'n':
            *p++ = LF;
            break;

        case 't':
            *p++ = '\t';
            break;

        case '%':
            *p++ = '%';
            break;

        default:
            *p++ = '%';
            *p++ = *fmt;
            break;
        }

        fmt++;
    }

    return p;
}


time_t
ngx_next_time(time_t when)
{
    time_t     now, next;
    struct tm  tm;

    now = ngx_time();

    ngx_libc_localtime(now, &tm);

    tm.tm_hour = (int) (when / 3600);
    when %= 3600;
    tm.tm_min = (int) (when / 60);
    tm.tm_sec = (int) (when % 60);

    next = mktime(&tm);

    if (next == -1) {
        return -1;
    }

    if (next - now > 0) {
        return next;
    }

    tm.tm_mday++;

    /* mktime() should normalize a date (Jan 32, etc) */

    next = mktime(&tm);

    if (next != -1) {
        return next;
    }

    return -1;
}
