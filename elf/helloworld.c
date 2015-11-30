#include <stdio.h>

#ifdef BUILD_SVN_PREDEF
    #define BUILD_SVN BUILD_SVN_PREDEF
#endif

int main()
{
	printf("hello ubuntu!\n");
	printf("BUILD_SVN = %s\n",BUILD_SVN);
	return 0;
}
