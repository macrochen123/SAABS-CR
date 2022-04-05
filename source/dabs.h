#ifndef __HEADER_DABS_H__
#define __HEADER_DABS_H__

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
G1 Y1;
G1 U[USIZE];
GT Z;
} DMPK;

typedef struct {
Big x1;
Big v1;
} DMSK;

typedef struct {
G1 D;
G1 dk0[VSIZE];
G1 dk1[VSIZE];
} DUSK;

typedef struct {
G1 s0;
G1 ss;
G1 dk0[LSIZE];
} DSign;

typedef struct {
G1 s0;
G1 dk0[LSIZE];
} DTSign;

void DSetup(PFC *pfc, DMPK& mpk, DMSK& msk, int UL);
void DKeyGen(PFC *pfc, DUSK& usk, G1& D, LSSS& la, DMPK mpk, DMSK msk, int *S, int SL, int *M, int ML);
void DSSignGen(PFC *pfc, DSign& Sigma, LSSS la, DUSK usk, DMPK mpk, int *S, int SL, int *M, int ML, int nl, char *mess, int ml);
void DUSignGen(PFC *pfc, DSign& signature, G1 D, DSign Sigma, DMPK mpk, int nl, char *mess, int ml);
void DTrans(PFC *pfc, Big& vk, DTSign& ts, DSign signature, int nl);
void DSVerify(PFC *pfc, GT& Sigma2, DTSign ts, DMPK mpk, int nl);
BOOL DUVerify(PFC *pfc, Big vk, GT Sigma2, DSign signature, DMPK mpk, char *mess, int ml);


void D2KeyGen(PFC *pfc, DUSK& usk, LSSS& la, DMPK mpk, DMSK msk, int *S, int SL, int *M, int ML);
void DSignGen(PFC *pfc, DSign& newSign, DSign& signature, LSSS la, DUSK usk, DMPK mpk, int *S, int SL, int *M, int ML, int nl, char *mess, int ml);
BOOL DVerify(PFC *pfc, DSign newSign, DMPK mpk, int nl, char *mess, int ml);

#ifdef __cplusplus 
}
#endif

#endif