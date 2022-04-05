#ifndef _HEADER_COM_H_
#define _HEADER_COM_H_

#ifdef __cplusplus
extern "C" {
#include "miracl.h"
}
#else
#include "miracl.h"
#endif

#define USIZE 35
#define LSIZE 35
#define VSIZE 35
#define DSIZE 35



#ifdef  __cplusplus
extern "C" {
#endif


void copyChar(char *sourceA, char *sourceR, int length);
void SPrint(char *source, int length);


#ifdef  __cplusplus
}
#endif

#endif // !_HEADER_Curve_CURVE_H_
