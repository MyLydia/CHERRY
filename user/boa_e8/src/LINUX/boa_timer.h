#ifndef INCLUDE_BOATIMER_H
#define INCLUDE_BOATIMER_H

/* BEGIN: Modified by piyajee_chen, 2016/9/7   PN:support logout by system self when timeout. */
// Mason Yu
struct	webserver_callout {
    struct timeval	c_time;		/* time at which to call routine */
    void		*c_arg;		/* argument to routine */
    void		(*c_func) __P((void *)); /* routine */
    struct		webserver_callout *c_next;
};
/* END:   Modified by piyajee_chen, 2016/9/7   PN:support logout by system self when timeout. */

#endif
