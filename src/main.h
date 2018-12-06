#ifndef	__MAIN_H_
#define	__MIAN_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>


typedef int INT32;

typedef char CHAR;

#define GOS_ASSERT(cond) if (!(cond)) \
                      {\
                        printf("\r\nAssertion Failed:"#cond", file %s, line %d, pid %d\r\n", __FILE__, __LINE__, getpid()); \
                        abort();\
                      }\
                      else {}

#define GOS_NELEM(array)   (sizeof(array)/sizeof(array[0]))
#endif
