
/*
 * Copyright (C) 2024 Web Server LLC
 */

#ifndef _NGX_FIBER_H_INCLUDED_
#define _NGX_FIBER_H_INCLUDED_

/*
 * A simple implementation of fibers[1] based on ideas of Simon Tatham[2]
 * and Protothreads[3].
 *
 * -------
 * [1] https://en.wikipedia.org/wiki/Fiber_(computer_science)
 * [2] https://www.chiark.greenend.org.uk/~sgtatham/coroutines.html
 * [3] https://dunkels.com/adam/pt/
 */

#include <ngx_config.h>
#include <ngx_core.h>

typedef ngx_uint_t ngx_fiber_state_t;

/* Initializes a fiber. This macro must be invoked only once before the fiber
 * execution is completed. */
#define NGX_FIBER_INIT(state)      do { state = 0; } while (0)

/* Defines the beginning of a code block which we want to treat as a fiber.
 * The block must be terminated by a matching NGX_FIBER_END macro.
 * A function may contain only one fiber. */
#define NGX_FIBER_BEGIN(state)     switch (state) { case 0:

/* Defines the end of a fiber. Must be preceded by a matching NGX_FIBER_BEGIN
 * macro. */
#define NGX_FIBER_END(state)       state = (ngx_fiber_state_t) -1; }

/* Yields true if the fiber has reached its NGX_FIBER_END statement. */
#define NGX_FIBER_IS_ENDED(state)  ((state) == (ngx_fiber_state_t) -1)

#ifdef __GNUC__
#if __GNUC__ >= 7
/* Disable the "this statement may fall through" warning. */
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#endif
#endif

/* Memorizes the position of code execution. If the function containing
 * the fiber is called once more, execution resumes at this position. */
#define NGX_FIBER_REMEMBER(state) \
    do { \
        state = __LINE__; \
    case __LINE__:; \
    } while (0)

/* Memorizes the position of code execution and yields control back
 * to the calling function. Returns the value ret. If the function containing
 * the fiber is called once more, execution resumes at this position. */
#define NGX_FIBER_YIELD(state, ret) \
    do { \
        state = __LINE__; \
        return ret; \
    case __LINE__:; \
    } while (0)

/* Blocks execution of a fiber while the condition cond is true. During this
 * time, the value ret is returned. */
#define NGX_FIBER_WAIT_WHILE(state, cond, ret) \
    do { \
        NGX_FIBER_REMEMBER(state); \
        if (cond) \
            return ret; \
    } while(0)

/* The same as NGX_FIBER_WAIT_WHILE but blocks execution of a fiber until
 * the condition cond becomes true. */
#define NGX_FIBER_WAIT_UNTIL(state, cond, ret) \
    NGX_FIBER_WAIT_WHILE(state, !(cond), ret)

/* Launches a child fiber and waits while the condition cond is true. */
#define NGX_FIBER_SPAWN(state, child, cond, ret) \
    do { \
        NGX_FIBER_INIT(child); \
        NGX_FIBER_WAIT_WHILE(state, cond, ret); \
    } \
    while (0)


/* Return value for a void function. Used as a placeholder. */
#define NGX_FIBER_RET_VOID


#endif /* _NGX_FIBER_H_INCLUDED_ */
