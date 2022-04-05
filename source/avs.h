#ifndef __HEADER_AVS_H__
#define __HEADER_AVS_H__

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
G1 U[USIZE];
GT Z;
} AMPK;

typedef struct {
G1 d;
G1 dk0[VSIZE];
G1 dk1[VSIZE];
} ASK;

typedef struct {
G1 D0[LSIZE];
G1 H1[LSIZE];
} APK;

typedef struct {
G1 sigma0;
G1 sigma1;
G1 sigmai0[LSIZE];
G1 sigmai1[LSIZE];
} ASign;


void ASetup(PFC *pfc, AMPK& mpk, Big& msk, int UL);
void AKeyGen(PFC *pfc, ASK& ask, APK& apk, LSSS& la, AMPK mpk, Big msk, int *S, int SL, int *M, int ML, int nl);
void ASignGen(PFC *pfc, ASign& signature, ASK ask, APK apk, LSSS la, AMPK mpk, int *S, int SL, int *M, int ML, int nl, char *mess, int ml);

void ASTrans(PFC *pfc, Big& vk, ASign& newSign, ASign signature, int nl);
void ASVerify(PFC *pfc, GT& Sigma, ASign newSign, APK apk, LSSS la, AMPK mpk, int *M, int ML, int nl);
BOOL AUVerify(PFC *pfc, Big vk, GT Sigma, ASign newSign, AMPK mpk, char *mess, int ml);

//////////////
BOOL AVerify(PFC *pfc, ASign signature, APK apk, LSSS la, AMPK mpk, int *M, int ML, int nl, char *mess, int ml);

#ifdef __cplusplus 
}
#endif

#endif