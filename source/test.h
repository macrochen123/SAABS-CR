#ifndef _HEADER_TEST_H_
#define _HEADER_TEST_H_

#include "me.h"
#include "avs.h"
#include "sa2.h"
#include "dabs.h"

///////////our//////////////////
void Setuptest(PFC *pfc);
void Signtest(PFC *pfc);
void GenLSSStest(PFC *pfc);
void Verifytest(PFC *pfc);

///////////sa-abs-2019//////////////////

void SAKeyGentest(PFC *pfc);
void SAVerifytest(PFC *pfc);

////////////trams-2-21///////////////////////////
void TKeyGentest(PFC *pfc);
void TVerifytest(PFC *pfc);

//////////////abs-svs//////////////////////////
void AVerifytest(PFC *pfc);
void ASUVerifytest(PFC *pfc);

///////////////dabs/////////////////
void DKeyGentest(PFC *pfc);
void DVerifytest(PFC *pfc);

//////////////time-test////////////////////
void Timetest(PFC *pfc);
void Sizetest(PFC *pfc);

/////////////////////////////////////////
void KeyGenTimetest(PFC *pfc, int choose);
void MeTime(PFC *pfc, int ul, int *M, int ML, int *S, int SL, char *mess, int ml, int counter);
void SA2Time(PFC *pfc, int ul, int *M, int ML, int *S, int SL, int row, char *mess, int ml, int counter);
void TramsTime(PFC *pfc, int ul,  int *M, int ML, int *S, int SL, int nl, char *mess, int ml, int counter);
void AVSTime(PFC *pfc, int ul, int *M, int ML, int *S, int SL, int nl, char *mess, int ml, int counter);
void DABSTime(PFC *pfc, int ul, int *S, int SL, int *M, int ML, int nl, char *mess, int ml, int counter);

#endif