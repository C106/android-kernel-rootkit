#ifndef LK1337_TTBR_VIEW_H
#define LK1337_TTBR_VIEW_H

#include <linux/uaccess.h>

struct lk1337_session;

int lk1337_ttbr_init(void);
void lk1337_ttbr_exit(void);
void lk1337_ttbr_session_release(struct lk1337_session *session);
long lk1337_ttbr_dispatch(struct lk1337_session *session, unsigned int cmd,
				  void __user *arg);

#endif
