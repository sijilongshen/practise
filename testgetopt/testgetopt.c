#include <stdio.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
	int ret = 0;

	int opt;
	while ( (opt = getopt(argc,argv,"a:b::c:d:e:")) != -1 )
	{
		switch(opt)
		{
			case 'a':
				printf(" a: %s\n", optarg);
				break;
			case 'b':
				printf(" b: %s\n", optarg);
				break;
			case 'c':
				printf(" c: %s\n", optarg);
				break;
			case 'd':
				printf(" d: %s\n", optarg);
				break;		
			case 'e':
				printf(" e: %s\n", optarg);
				break;	
		}
		
	}
	return 0;
}
