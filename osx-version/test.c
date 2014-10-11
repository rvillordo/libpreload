#include <stdio.h>

int main(void)
{
    int i = 10;
lero:
    if(i == 10) {
        printf("test\n");
        i = 20;
        goto lero;
    }
	for(;;) sleep(1);

}
