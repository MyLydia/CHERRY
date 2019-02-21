#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "mib.h"
#include "utility.h"

int main(int argc, char **argv)
{
	char buf[64] = {0};
	mib_get(MIB_LOID, (void *)buf);
	printf("LOID1=%s\n", buf);

	return 0;
}

