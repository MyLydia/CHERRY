#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{

	char arr[20]="./replace.sh ";
    char buf[20]="192.168.3.2";
    strcat(arr,buf);
    system(arr);

	return 0;
}
