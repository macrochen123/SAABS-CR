#include "common.h"

void copyChar(char *sourceA, char *sourceR, int length)
{
	for (int i = 0; i < length; i++)
	{
		sourceR[i] = sourceA[i];
		/* code */
	}
	
}

void SPrint(char *source, int length)
{
	int i;
	for ( i = 0; i < length; i++)
	{
		printf("%02X", (unsigned char)source[i]);
	}
	printf("\n");
}