#include "dabs.h"

void DSetup(PFC *pfc, DMPK& mpk, DMSK& msk, int UL)
{
    int i;

    pfc->random(msk.v1);
    pfc->random(mpk.g);
    pfc->random(mpk.g1);

    mpk.Y1 = pfc->mult(mpk.g1, msk.v1);

    mpk.Z = pfc->pairing(mpk.Y1, mpk.g);

    for ( i = 0; i < UL; i++)
    {
        pfc->random(mpk.U[i]);
    }
}

void D2KeyGen(PFC *pfc, DUSK& usk, LSSS& la, DMPK mpk, DMSK msk, int *S, int SL, int *M, int ML)
{
    int i, j, k;
    int flag = 0;

    Big r, l, rj;
    Big pk;
    G1 g1, g2;

    pfc->random(r);
    
    usk.D = pfc->mult(mpk.g, r);
    pk = (pfc->order() + msk.v1 - r)%pfc->order();

    genLambda(pfc, la, ML, pk);// shared (v-r)

    for ( i = 0; i < SL; i++)
    {
        j = S[i];
        flag = 0;
        for(k = 0; k < ML; k++)
        {
            if (j == M[k])
            {
                flag = 1;
                break;
            }   
        }
        if (flag != 1)
        {
            pfc->random(l);
            pfc->random(rj);
            g1 = pfc->mult(mpk.g, l);
            g2 = pfc->mult(mpk.U[j], rj);
            usk.dk0[i] = g1 + g2;
            usk.dk1[i] = pfc->mult(mpk.g1, rj);    
        }
    }

    for ( i = 0; i < ML; i++)
    {
        j = M[i];
        for (k = 0; k < SL; k++)
        {
            if(j == S[k])
            {
                break;
            }
        }
        pfc->random(rj);
        g1 = pfc->mult(mpk.g, la.l[i]);
        g2 = pfc->mult(mpk.U[j], rj);
        usk.dk0[k] = g1 + g2;
        usk.dk1[k] = pfc->mult(mpk.g1, rj);
    }
    
}

void DKeyGen(PFC *pfc, DUSK& usk, G1& D, LSSS& la, DMPK mpk, DMSK msk, int *S, int SL, int *M, int ML)
{
     int i, j, k;
    int flag = 0;

    Big r, l, rj;
    Big pk;
    G1 g1, g2;

    pfc->random(r);
    
    D = pfc->mult(mpk.g, r);
    pk = (pfc->order() + msk.v1 - r)%pfc->order();

    genLambda(pfc, la, ML, pk);// shared (v-r)

    for ( i = 0; i < SL; i++)
    {
        j = S[i];
        flag = 0;
        for(k = 0; k < ML; k++)
        {
            if (j == M[k])
            {
                flag = 1;
                break;
            }   
        }
        if (flag != 1)
        {
            pfc->random(l);
            pfc->random(rj);
            g1 = pfc->mult(mpk.g, l);
            g2 = pfc->mult(mpk.U[j], rj);
            usk.dk0[i] = g1 + g2;
            usk.dk1[i] = pfc->mult(mpk.g1, rj);    
        }
    }

    for ( i = 0; i < ML; i++)
    {
        j = M[i];
        for (k = 0; k < SL; k++)
        {
            if(j == S[k])
            {
                break;
            }
        }
        pfc->random(rj);
        g1 = pfc->mult(mpk.g, la.l[i]);
        g2 = pfc->mult(mpk.U[j], rj);
        usk.dk0[k] = g1 + g2;
        usk.dk1[k] = pfc->mult(mpk.g1, rj);
    }   

}


void DSSignGen(PFC *pfc, DSign& Sigma, LSSS la, DUSK usk, DMPK mpk, int *S, int SL, int *M, int ML, int nl, char *mess, int ml)
{
    int i, j, k;
    int flag =0;
    char hash[HASHLEN];

    Big sk, s;
    G1 g1, g2;
    G1 hk1, hk2;
    G1 tmp1, tmp2;
    G1 hm;

    for ( i = 0; i < ML; i++)
    {
        pfc->random(sk);
        j = M[i];
        for (k = 0; k < SL; k++)
        {
            if(j == S[k])
            {
                break;
            }
        }
        g1 = pfc->mult(usk.dk0[k], la.w[i]);
        hk1 = pfc->mult(mpk.U[j], sk);

        tmp1 = pfc->mult(mpk.g1, sk);
        Sigma.dk0[j] = pfc->mult(usk.dk1[k], la.w[i]) + tmp1;

        if(i == 0)
        {
            g2 = g1;
            hk2 = hk1;
        }else{
            g2 = g2 + g1;
            hk2 = hk2 + hk1;
        }
    }

    for ( i = 0; i < nl; i++)
    {
        flag = 0;
        pfc->random(sk);
        for (k = 0; k < ML; k++)
        {
            if(i ==M[k])
            {
                flag = 1;
                break;
            }
        }
        if (flag != 1)
        {
           Sigma.dk0[i] = pfc->mult(mpk.g1, sk);
           hk1 = pfc->mult(mpk.U[i], sk); 
           hk2 = hk2 + hk1;
        }     
    }
    pfc->random(s);

    pfc->start_hash();
    pfc->add_to_hash(mess, ml);
    copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(hm, hash, HASHLEN);
    tmp1 = pfc->mult(hm, s);//H(m)^{s}

    Sigma.s0 = g2 + hk2 + tmp1;
    Sigma.ss = pfc->mult(mpk.g1, s);
}
void DUSignGen(PFC *pfc, DSign& signature, G1 D, DSign Sigma, DMPK mpk, int nl, char *mess, int ml)
{
    int i;
    int flag =0;
    char hash[HASHLEN];

    Big su;
    G1 tmp1;
    G1 hm;
    G1 gu1;

    pfc->random(su);
   
    pfc->start_hash();
    pfc->add_to_hash(mess, ml);
    copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(hm, hash, HASHLEN);
    tmp1 = pfc->mult(hm, su);//H(m)^su
    signature.s0 = D + Sigma.s0 + tmp1;

    gu1 = pfc->mult(mpk.g1, su);
    signature.ss = Sigma.ss + gu1;

    for (i = 0; i < nl; i++)
    {
        signature.dk0[i] = Sigma.dk0[i];
    }

}

void DTrans(PFC *pfc, Big& vk, DTSign& ts, DSign signature, int nl)
{
    int i;
    pfc->random(vk);
    //cout<<vk<<endl;

    ts.s0 = pfc->mult(signature.s0, vk);
    for ( i = 0; i < nl; i++)
    {
        ts.dk0[i] = pfc->mult(signature.dk0[i], vk);
    }
}

void DSVerify(PFC *pfc, GT& Sigma2, DTSign ts, DMPK mpk, int nl)
{
     int i;

    GT gt1, gt2;
    GT tmp1;
    GT result;

    gt1 = pfc->pairing(mpk.g1, ts.s0);

    for ( i = 0; i < nl; i++)
    {
        tmp1 = pfc->pairing(ts.dk0[i], mpk.U[i]);
        if (i==0)
        {
            gt2 = tmp1;
        }else{
            gt2 = gt2*tmp1;
        }

    }
    result = gt1/gt2;
    Sigma2 = result;

    //Sigma2.GT_Print();
}
BOOL DUVerify(PFC *pfc, Big vk, GT Sigma2, DSign signature, DMPK mpk, char *mess, int ml)
{
    char hash[HASHLEN];

    G1 hm;
    G1 tmp1;
    GT result, gt;

    pfc->start_hash();
    pfc->add_to_hash(mess, ml);
    copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(hm, hash, HASHLEN);

    tmp1 = pfc->mult(signature.ss, vk);
    result = pfc->pairing(tmp1, hm); 
    gt = pfc->power(mpk.Z, vk);
    result = result*gt;

   // result.GT_Print();

    if (result == Sigma2)
    {
       // printf("D verify success!\n");
        return TRUE;
    }
    //printf("D verify error!\n");
    return FALSE;
}


void DSignGen(PFC *pfc, DSign& newSign, DSign& signature, LSSS la, DUSK usk, DMPK mpk, int *S, int SL, int *M, int ML, int nl, char *mess, int ml)
{
    int i, j, k;
    int flag =0;
    char hash[HASHLEN];

    Big sk, s;
    G1 g1, g2;
    G1 hk1, hk2;
    G1 tmp1, tmp2;
    G1 hm;

    for ( i = 0; i < ML; i++)
    {
        pfc->random(sk);
        j = M[i];
        for (k = 0; k < SL; k++)
        {
            if(j == S[k])
            {
                break;
            }
        }
        g1 = pfc->mult(usk.dk0[k], la.w[i]);
        hk1 = pfc->mult(mpk.U[j], sk);

        tmp1 = pfc->mult(mpk.g1, sk);
        signature.dk0[j] = pfc->mult(usk.dk1[k], la.w[i]) + tmp1;

        if(i == 0)
        {
            g2 = g1;
            hk2 = hk1;
        }else{
            g2 = g2 + g1;
            hk2 = hk2 + hk1;
        }
    }

    for ( i = 0; i < nl; i++)
    {
        flag = 0;
        pfc->random(sk);
        for (k = 0; k < ML; k++)
        {
            if(i ==M[k])
            {
                flag = 1;
                break;
            }
        }
        if (flag != 1)
        {
           signature.dk0[i] = pfc->mult(mpk.g1, sk);
           hk1 = pfc->mult(mpk.U[i], sk); 
           hk2 = hk2 + hk1;
        }     
    }
    pfc->random(s);

    pfc->start_hash();
    pfc->add_to_hash(mess, ml);
    copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(hm, hash, HASHLEN);
    tmp1 = pfc->mult(hm, s);//H(m)^{s}

    signature.s0 = g2 + hk2 + tmp1;
    signature.ss = pfc->mult(mpk.g1, s);
    ////////////////////////////////////////
    Big su;
    G1 gu1;
    pfc->random(su);
   
    pfc->start_hash();
    pfc->add_to_hash(mess, ml);
    copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(hm, hash, HASHLEN);
    tmp1 = pfc->mult(hm, su);//H(m)^su
    newSign.s0 = usk.D + signature.s0 + tmp1;

    gu1 = pfc->mult(mpk.g1, su);
    newSign.ss = signature.ss + gu1;

    for (i = 0; i < nl; i++)
    {
        newSign.dk0[i] = signature.dk0[i];
    }
}

BOOL DVerify(PFC *pfc, DSign newSign, DMPK mpk, int nl, char *mess, int ml)
{
    int i;
    char hash[HASHLEN];

    G1 hm;
    GT gt1, gt2;
    GT tmp1;
    GT result, test;

    gt1 = pfc->pairing(mpk.g1, newSign.s0);
    pfc->start_hash();
    pfc->add_to_hash(mess, ml);
    copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(hm, hash, HASHLEN);
    test = pfc->pairing(newSign.ss, hm);
    test.GT_Print();
    for ( i = 0; i < nl; i++)
    {
        tmp1 = pfc->pairing(newSign.dk0[i], mpk.U[i]);
        if (i==0)
        {
            gt2 = tmp1;
        }else{
            gt2 = gt2*tmp1;
        }

    }

    result = gt1/gt2;
    result = result/mpk.Z;
    result.GT_Print();

    if (result == test)
    {
        printf("D verify success!\n");
        return TRUE;
    }
    printf("D verify error!\n");
    return FALSE;
}