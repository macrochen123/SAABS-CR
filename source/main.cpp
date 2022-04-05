#include <windows.h>
#define MR_PAIRING_SSP 
#define Security 128
#define SL128

#include "test.h"

PFC pfc(Security);
void main()
{
	int i, choose;
	time_t seed;
	time(&seed);
	irand((long)seed);
	srand((unsigned)time(NULL));
	//Setuptest(&pfc);
	//Signtest(&pfc);
	//Gentest(&pfc);
	//Verifytest(&pfc);

	//SAKeyGentest(&pfc);
	//SAVerifytest(&pfc);
	//TKeyGentest(&pfc);
	//TVerifytest(&pfc);
	//AVerifytest(&pfc);
	//ASUVerifytest(&pfc);

	//DKeyGentest(&pfc);
	//DVerifytest(&pfc);
	//Timetest(&pfc);
	//Sizetest(&pfc);
	for(i = 1; i< 12; i++)
	{
	
		choose = i;
		printf("the number of matching attributes is  %d\n", choose);
		KeyGenTimetest(&pfc, choose);

	}
	
	//system("pause");
}