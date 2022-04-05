#ifndef __HEADER_ME_H__
#define __HEADER_ME_H__

#define MR_PAIRING_SSP 

#ifdef SL128
#define Security 128
#else
#define Security 80
#endif

#include <ctime>
#include "pairing_1.h"
#include "common.h"

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
Big t[USIZE];
Big alpha;
Big beta;
} MSK;

typedef struct {
G1 T[USIZE];
G1 P;
G1 g1;
GT Y;
} MPK;

typedef struct {
G1 K3[VSIZE];
G1 K1;
G1 K2;
} SK;

typedef struct {
Big l[DSIZE];
Big w[DSIZE];
} LSSS;

typedef struct {
G1 sigma0;
G1 sigma1;
G1 sigma2[DSIZE];
G1 sigma3;
} Sigma;

typedef struct {
G1 EI1[DSIZE];
G1 EI2[DSIZE];
G1 sigma3;
} EI;


void ABS_Setup(PFC *pfc, MPK& mpk, MSK& msk, int Ul);
void ABS_KeyGen(PFC *pfc, SK& sk, MPK mpk, MSK msk, int *S, int SL);
void ABS_Sign(PFC *pfc, Sigma& signature, MPK mpk, SK sk, int *S, int SL, int *M, int ML, char *mess, int ml);
void ABS_Trans(PFC *pfc, EI& ei, Big& vk, LSSS& la, Sigma signature, MPK mpk, int *S, int SL, int *M, int ML);
void ABS_SV(PFC *pfc, GT& ai, EI ei, Sigma signature, MPK mpk, LSSS la, int ML);
BOOL ABS_UV(PFC *pfc, GT ai, Big vk, Sigma signature, MPK mpk, int ML, char *mess, int ml, char *hash);


BOOL ABS_UV2(PFC *pfc, GT ai, Big vk, Sigma signature, MPK mpk, int ML, char *mess, int ml);
BOOL ABS_Verify(PFC *pfc, Sigma signature, MPK mpk, int *S, int SL, int *M, int ML, char *mess, int ml);

//index
void SignHash(PFC *pfc, char *hash, Sigma signature, int ML);
//lambda
void genLambda(PFC *pfc, LSSS& la, int ML, Big s);

#ifdef __cplusplus 
}
#endif

#endif