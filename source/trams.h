#ifndef __HEADER_TRAMS_H__
#define __HEADER_TRAMS_H__

#define MR_PAIRING_SSP 
#ifdef SL128
#define Security 128
#else
#define Security 80
#endif

#include <ctime>
#include "pairing_1.h"
#include "common.h"
#include "me.h"
#ifdef MR_CPP
#include "miracl.h"
#else
extern "C"                    
{
    #include "miracl.h"
}
#endif

#define HASHLEN 32


#ifdef __cplusplus //|| defined(c_plusplus)
extern "C"{
#endif

typedef struct {
G1 g;
G1 g1;
G1 g2;
G1 R;
GT Z;
G1 U[USIZE];
} TMPK;

typedef struct {
G1 sk;
G1 dk0[VSIZE];
G1 dk1[VSIZE];
} TSK;

typedef struct {
G1 tk0[LSIZE];
G1 tk1[LSIZE];
} TPK;

typedef struct {
G1 sigma0;
G1 sigma1;
G1 sigmai0[LSIZE];
G1 sigmai1[LSIZE];
} TSign;

void TSetup(PFC *pfc, TMPK& mpk, Big& msk, int UL);
void TKeyGen(PFC *pfc, TSK& tsk, TPK& tpk, LSSS& la, TMPK mpk, Big msk, int *S, int SL, int *M, int ML, int nl);
void TSignGen(PFC *pfc, TSign& signature, TSK tsk, TPK tpk, TMPK mpk, int *S, int SL, int *M, int ML, int nl, char *mess, int ml);
BOOL TVerify(PFC *pfc, TSign signature, TPK tpk, LSSS la, TMPK mpk, int *M, int ML, int nl, char *mess, int ml);

#ifdef __cplusplus 
}
#endif

#endif