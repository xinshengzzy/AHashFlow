#include <stdio.h>

int main()
{
	FILE* file = fopen("/home/zongyi/workspace/flag.cmd", "w");
	fprintf(file, "Hello, world.\n");
	fclose(file);
	return 0;
}
