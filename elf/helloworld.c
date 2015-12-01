#include <stdio.h>

#define BUILD_SVN   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
char* a = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

void print_version()
{
	printf("hello ubuntu!\n");
	printf("BUILD_SVN = %s, a = %s\n",BUILD_SVN, a);	
}

int main()
{
	print_version();
	return 0;
}


