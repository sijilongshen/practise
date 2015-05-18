#include <stdio.h>
#include <unistd.h>


int main()
{
	int ret = 0;
	long cpu_num = 0;

	cpu_num = sysconf(_SC_NPROCESSORS_CONF);
	printf("cpu num is : %ld \n", cpu_num);
	
	return ret ;
}
