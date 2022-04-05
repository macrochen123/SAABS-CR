#include "avs.h"


void ASetup(PFC *pfc, AMPK& mpk, Big& msk, int UL)
{
    int i;
    for ( i = 0; i < UL; i++)
    {
        pfc->random(mpk.U[i]);
    }
    
    pfc->random(msk);
    pfc->random(mpk.g);
    pfc->random(mpk.g2);
    mpk.g1 = pfc->mult(mpk.g, msk);
    mpk.Z = pfc->pairing(mpk.g1, mpk.g2);
    
}

void AKeyGen(PFC *pfc, ASK& ask, APK& apk, LSSS& la, AMPK mpk, Big msk, int *S, int SL, int *M, int ML, int nl)
{
    int i, j, k;

    int flag = 0;

    Big a1, a2, r;
    Big tmp, tmp1;
    Big ri;
    Big l;

    G1 g1, g2;
 
    pfc->random(a1);
    pfc->random(r);
    genLambda(pfc, la, ML, a1);//share a1;

    a2 = (pfc->order() + msk - a1)%pfc->order();//a-a1;
    tmp = a1 + r;
    ask.d = pfc->mult(mpk.g2, tmp);//

    tmp = inverse(a1, pfc->order());//1/a1
    tmp1 = (pfc->order() + r - a2)%pfc->order();//(r-a2)
    tmp = (tmp*tmp1)%pfc->order();
    g1 = pfc->mult(mpk.g2, tmp);//



    for ( i = 0; i < SL; i++)
    {
        j = S[i];
        pfc->random(ri);
        g2 = pfc->mult(mpk.U[j], ri);
        ask.dk0[i] = g1 + g2;
        ask.dk1[i] = pfc->mult(mpk.g, ri);

    }

    for ( i = 0; i < nl; i++)
    {
        flag = 0;
        for (k = 0; k < ML; k++)
        {
            if(i == M[k])
            {
                flag = 1;
                break;
            }
        }
        if (flag != 1)
        {
            pfc->random(l);
            apk.D0[i] = pfc->mult(mpk.g, l);
            apk.H1[i] = pfc->mult(mpk.U[i], l);
        }  
       
    }

    /////auth set
    for ( i = 0; i < ML; i++)
    {
        j = M[i];//aut
        apk.D0[j] = pfc->mult(mpk.g, la.l[i]);
        apk.H1[j] = pfc->mult(mpk.U[j], la.l[i]);
    } 
}

void ASignGen(PFC *pfc, ASign& signature, ASK ask, APK apk, LSSS la, AMPK mpk, int *S, int SL, int *M, int ML, int nl, char *mess, int ml)
{
    int i, j, k;
    int flag = 0;
	char hash[HASHLEN];

    Big s;
    Big r;
    G1 g1, hm;

    pfc->random(s);
    signature.sigma1 = pfc->mult(mpk.g, s);

    pfc->start_hash();
    pfc->add_to_hash(mess, ml);
    copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(hm, hash, HASHLEN);

    g1 = pfc->mult(hm, s);//H(m)^s
    signature.sigma0 = g1 + ask.d;

    for ( i = 0; i < nl; i++)
    {
        pfc->random(r);
        flag =0;
        for (k = 0; k < ML; k++)
        {
            if(i == M[k])
            {
                flag = 1;
                break;
            }
        }
        if (flag != 1)
        {
            signature.sigmai0[i] = pfc->mult(mpk.U[i], r);
            signature.sigmai1[i] = pfc->mult(mpk.g, r);
        }
    }

    for ( i = 0; i < ML; i++)
    {
        pfc->random(r);
        j = M[i];//aut
        for (k = 0; k < SL; k++)
        {
            if(j == S[k])
            {
                break;
            }
        }
        g1 = pfc->mult(mpk.U[j], r);
        signature.sigmai0[j] = ask.dk0[k] + g1;

        g1 = pfc->mult(mpk.g, r);
        signature.sigmai1[j] = ask.dk1[k] + g1;

    }
}

BOOL AVerify(PFC *pfc, ASign signature, APK apk, LSSS la, AMPK mpk, int *M, int ML, int nl, char *mess, int ml)
{
    int i, j, k;
    int flag = 0;
	char hash[HASHLEN];

    G1 hm;
    GT gt1, gt2, gt3, gt4, result;

    for ( i = 0; i < nl; i++)
    {
        flag =0;
        for (k = 0; k < ML; k++)
        {
            if(i == M[k])
            {
                flag = 1;
                break;
            }
        }
        if (flag != 1)
        {

            gt1 = pfc->pairing(signature.sigmai0[i], apk.D0[i]);
            gt2 = pfc->pairing(signature.sigmai1[i], apk.H1[i]);
            gt3 = gt1/gt2;
            gt3.GT_Print();
        }
    }
    for ( i = 0; i < ML; i++)
    {
   
        j = M[i];//aut
        gt1 = pfc->pairing(signature.sigmai0[j], apk.D0[j]);
        gt2 = pfc->pairing(signature.sigmai1[j], apk.H1[j]);
        gt3 = gt1/gt2;
        gt3 = pfc->power(gt3, la.w[i]);
        if (i == 0)
        {
            gt4 = gt3;
        }else{
            gt4 = gt4 *gt3;
        }
    }
///////////////
    pfc->start_hash();
    pfc->add_to_hash(mess, ml);
    copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(hm, hash, HASHLEN);

    gt1 = pfc->pairing(hm, signature.sigma1);
    gt2 = pfc->pairing(mpk.g, signature.sigma0);
    gt2 = gt2/gt4;
    result = gt2/gt1;
    if (result == mpk.Z)
    {
        printf("ABSSVS verify success!\n");
        return TRUE;
    }
    printf("ABSSVS verify error!\n");
    return FALSE;    
}

void ASTrans(PFC *pfc, Big& vk, ASign& newSign, ASign signature, int nl)
{
    int i;
    pfc->random(vk);

    newSign.sigma0 = pfc->mult(signature.sigma0, vk);
    newSign.sigma1 = signature.sigma1;
    //newSign.sigma1 = pfc->mult(signature.sigma1, vk);

    for(i = 0; i < nl; i++)
    {
        newSign.sigmai0[i] = pfc->mult(signature.sigmai0[i], vk);
        newSign.sigmai1[i] = pfc->mult(signature.sigmai1[i], vk);
    }
}
void ASVerify(PFC *pfc, GT& Sigma, ASign newSign, APK apk, LSSS la, AMPK mpk, int *M, int ML, int nl)
{
        int i, j, k;
    int flag = 0;


    G1 hm;
    GT gt1, gt2, gt3, gt4, result;

    for ( i = 0; i < nl; i++)
    {
        flag =0;
        for (k = 0; k < ML; k++)
        {
            if(i == M[k])
            {
                flag = 1;
                break;
            }
        }
        if (flag != 1)
        {

            gt1 = pfc->pairing(newSign.sigmai0[i], apk.D0[i]);
            gt2 = pfc->pairing(newSign.sigmai1[i], apk.H1[i]);
            gt3 = gt1/gt2;
            //gt3.GT_Print();
        }
    }
    for ( i = 0; i < ML; i++)
    {
   
        j = M[i];//aut
        gt1 = pfc->pairing(newSign.sigmai0[j], apk.D0[j]);
        gt2 = pfc->pairing(newSign.sigmai1[j], apk.H1[j]);
        gt3 = gt1/gt2;
        gt3 = pfc->power(gt3, la.w[i]);
        if (i == 0)
        {
            gt4 = gt3;
        }else{
            gt4 = gt4 *gt3;
        }
    }
    gt2 = pfc->pairing(mpk.g, newSign.sigma0);
    Sigma = gt2/gt4;
}

BOOL AUVerify(PFC *pfc, Big vk, GT Sigma, ASign newSign, AMPK mpk, char *mess, int ml)
{
	char hash[HASHLEN];

    G1 hm;
    GT gt1, gt2, gt3, gt4, result;
    pfc->start_hash();
    pfc->add_to_hash(mess, ml);
    copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(hm, hash, HASHLEN);
    
    newSign.sigma1 = pfc->mult(newSign.sigma1, vk);
    gt1 = pfc->pairing(hm, newSign.sigma1);
    gt2 = pfc->power(mpk.Z, vk);
    result = gt1*gt2;
    if (result == Sigma)
    {
       // printf("ABSSVS U verify success!!\n");
        return TRUE;
    }
    //printf("ABSSVS U verify error!\n");
    return FALSE;       
}