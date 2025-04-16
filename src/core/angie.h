
/*
 * Copyright (C) 2022 Web Server LLC
 */


#ifndef _ANGIE_H_INCLUDED_
#define _ANGIE_H_INCLUDED_


#define angie_version      1010000
#define ANGIE_VERSION      "1.10.0"
#define ANGIE_VER          "Angie/" ANGIE_VERSION

#ifdef NGX_BUILD
#define ANGIE_VER_BUILD    ANGIE_VER " (" NGX_BUILD ")"
#else
#define ANGIE_VER_BUILD    ANGIE_VER
#endif

#define ANGIE_VAR          "ANGIE"
#define NGX_OLDPID_EXT     ".oldbin"

#define ngx_angie_sign     ('A' + 'n' + 'g' + 'i' + 'e')


extern ngx_time_t  ngx_build_time;


#endif /* _ANGIE_H_INCLUDED_ */
