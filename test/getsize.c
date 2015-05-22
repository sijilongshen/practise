#include <stdio.h>

int main()
{
	int ret = 0;

	unsigned int i = 1, j = 0;
	int len = sizeof(i);
	printf("sizeof int = %d \n", len);

	for ( j=1; j <= len*8; j++)
	{
		printf(" you yi %2d: %u \n", j, i << j);
	}

	return ret;
}
