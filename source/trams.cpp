#include "trams.h"

void TSetup(PFC *pfc, TMPK& mpk, Big& msk, int UL)
{
    Big tmp;
    int i;

    pfc->random(msk);
    pfc->random(mpk.g);
    pfc->random(mpk.g2);
    mpk.g1 = pfc->mult(mpk.g, msk);

   tmp = inverse(msk, pfc->order());
   mpk.R = pfc->mult(mpk.g2, tmp);//

   mpk.Z = pfc->pairing(mpk.g1, mpk.g2);
   for ( i = 0; i < UL; i++)
   {
       pfc->random(mpk.U[i]);
   }
   

}

void TKeyGen(PFC *pfc, TSK& tsk, TPK& tpk, LSSS& la, TMPK mpk, Big msk, int *S, int SL, int *M, int ML, int nl)
{
    int i, j, k;
    int flag = 0;
	char hash[HASHLEN];

    Big y;
    Big bt1, bt2;
    Big r;
    Big l;
    G1 gt1, gt2;

    genLambda(pfc, la, ML, msk);

    pfc->random(y);
    bt1 = (pfc->order() + msk -y)%pfc->order();//a-y
    tsk.sk = pfc->mult(mpk.g2, bt1);

    gt2 = pfc->mult(mpk.R, y);

    for ( i = 0; i < SL; i++)
    {
        pfc->random(r);

        j = S[i];//attribute of user
        // pfc->start_hash();
        // pfc->add_to_hash((Big)j);
	    // copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	    // pfc->hash_and_map(gt1, hash, HASHLEN);
        gt1 = mpk.U[j];
        gt1 = pfc->mult(gt1, r);//h(i)^{r}

        tsk.dk0[i] = gt2 + gt1;
        tsk.dk1[i] = pfc->mult(mpk.g, r);
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
            tpk.tk0[i] = pfc->mult(mpk.g, l);

            // pfc->start_hash();
            // pfc->add_to_hash((Big)i);
	        // copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	        // pfc->hash_and_map(gt1, hash, HASHLEN);
            gt1 = mpk.U[i];
            tpk.tk1[i] = pfc->mult(gt1, l);
        }  
       
    }
    /////auth set
    for ( i = 0; i < ML; i++)
    {
        j = M[i];//aut
        tpk.tk0[j] = pfc->mult(mpk.g, la.l[i]);
        // pfc->start_hash();
        // pfc->add_to_hash((Big)j);
	    // copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	    // pfc->hash_and_map(gt1, hash, HASHLEN);
        gt1 = mpk.U[j];
        tpk.tk1[j] = pfc->mult(gt1, la.l[i]);
    }

}

void TSignGen(PFC *pfc, TSign& signature, TSK tsk, TPK tpk, TMPK mpk, int *S, int SL, int *M, int ML, int nl, char *mess, int ml)
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
	pfc->hash_and_map(g1, hash, HASHLEN);

    g1 = pfc->mult(g1, s);//H(m)^s
    signature.sigma0 = g1 + tsk.sk;

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

            // pfc->start_hash();
            // pfc->add_to_hash((Big)i);
            // copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
            // pfc->hash_and_map(hm, hash, HASHLEN);
            hm = mpk.U[i];
            signature.sigmai0[i] = pfc->mult(hm, r);
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
        // pfc->start_hash();
        // pfc->add_to_hash((Big)j);
        // copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
        // pfc->hash_and_map(hm, hash, HASHLEN);
        hm = mpk.U[j];
        g1 = pfc->mult(hm, r);
        signature.sigmai0[j] = tsk.dk0[k] + g1;

        g1 = pfc->mult(mpk.g, r);
        signature.sigmai1[j] = tsk.dk1[k] + g1;

    }
}

BOOL TVerify(PFC *pfc, TSign signature, TPK tpk, LSSS la, TMPK mpk, int *M, int ML, int nl, char *mess, int ml)
{
    int i, j, k;
    int flag = 0;
	char hash[HASHLEN];

    G1 hm;
    GT gt1, gt2, gt3, gt4,result;

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

            gt1 = pfc->pairing(signature.sigmai0[i], tpk.tk0[i]);
            gt2 = pfc->pairing(signature.sigmai1[i], tpk.tk1[i]);
            gt3 = gt1/gt2;
        }
    }
    for ( i = 0; i < ML; i++)
    {
   
        j = M[i];//aut
        gt1 = pfc->pairing(signature.sigmai0[j], tpk.tk0[j]);
        gt2 = pfc->pairing(signature.sigmai1[j], tpk.tk1[j]);
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
    gt2 = gt2*gt4;
    result = gt2/gt1;
    if (result == mpk.Z)
    {
        //printf("T verify success!\n");
        return TRUE;
    }
    //printf("T verify error!\n");
    return FALSE;
    
}