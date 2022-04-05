#ifndef __HEADER_SA_H__
#define __HEADER_SA_H__

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
Big a1;
Big a2;
} SAMSK;

typedef struct {
G1 R0;
G1 R[USIZE];
G1 a;
G1 g;
GT Z;
} SAMPK;

typedef struct {
G1 dk1[LSIZE];
G1 dk2[LSIZE];
G1 dk3[LSIZE][USIZE];
} SAK;

typedef struct {
G1 dk1;
G1 dk2;
} SAKU;

typedef struct {
G1 sigma0;
G1 sigma1;
G1 sigma2;
} SSign;

typedef struct {
G1 sigma0;
G1 sigma1;
G1 sigma11;
G1 sigma2;
} SSignature;

typedef struct {
G1 sigma0;
G1 sigma1;
G1 sigma11;
} SST;

void SASetup(PFC *pfc, SAMPK& mpk, SAMSK& msk, int Ul);
void SAKeyGenS(PFC *pfc, SAK& sk,  LSSS& la, SAMPK mpk, SAMSK msk, int row, int *M, int ML);
void SAKeyGenU(PFC *pfc, SAKU& usk, SAMPK mpk, SAMSK msk);
void SASSign(PFC *pfc, SSign& sigma, SAK sk, LSSS la, SAMPK mpk, int *M, int ML, char *mess, int ml);
void SAUSign(PFC *pfc, SSignature& signature, SAKU usk, SSign sigma, SAMPK mpk, char *mess, int ml);

void SATrans(PFC *pfc, Big& vk, SST& st, SSignature signature, SAMPK mpk);
void SASVeri(PFC *pfc, GT& result, SST st, SAMPK mpk, int *M, int ML);
BOOL SAUVeri(PFC *pfc, GT result, SSignature signature, Big vk, SAMPK mpk, char *mess, int ml);


void SASign(PFC *pfc, SSignature& signature, SSign& sigma, SAK sk, SAKU usk, LSSS la, SAMPK mpk, int *M, int ML, char *mess, int ml);
void SAVerify(PFC *pfc, SSignature signature, SAMPK mpk, int *M, int ML, char *mess, int ml);


#ifdef __cplusplus 
}
#endif

#endif