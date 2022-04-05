#include "sa2.h"


void SASetup(PFC *pfc, SAMPK& mpk, SAMSK& msk, int Ul)
{
    int i;
    Big tmp;
    G1 t1;
    for ( i = 0; i < Ul; i++)
    {
       pfc->random(mpk.R[i]);
    }
    pfc->random(mpk.a);
    pfc->random(mpk.g);
    pfc->random(mpk.R0);

    pfc->random(msk.a1);
    pfc->random(msk.a2);

    tmp = msk.a1 + msk.a2;
    t1 = pfc->mult(mpk.g, tmp);//g^{a1+a2}
    mpk.Z = pfc->pairing(t1, mpk.g);//e(g, g)^{a1+a2}
}

void SAKeyGenS(PFC *pfc, SAK& sk,  LSSS& la, SAMPK mpk, SAMSK msk, int row, int *M, int ML)
{
    int i, j, k;
    int flag = 0;
    Big x, l;
    G1 t1, t2;
    genLambda(pfc, la, ML, msk.a1);//share a1, 
    ////unauth set
    for ( i = 0; i < row; i++)
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
            pfc->random(x);
            pfc->random(l);

            t1 = pfc->mult(mpk.g, l);
            t2 = mpk.R0 + mpk.R[i];
            t2 = pfc->mult(t2, x);
            sk.dk1[i] =  t1 + t2;
            sk.dk2[i] = pfc->mult(mpk.g, x);
            for (j = 0; j < USIZE; j++)
            {
                if (j != i)
                {
                   sk.dk3[i][j]= pfc->mult(mpk.R[j], x);
                }
                
            }
        }  
       
    }
    /////auth set
    for ( i = 0; i < ML; i++)
    {
        pfc->random(x);
        j = M[i];//auth
        sk.dk1[j] = pfc->mult(mpk.g, la.l[i]); //g^{l}
        t1 = mpk.R0 + mpk.R[j];
        t2 = pfc->mult(t1, x);

        sk.dk1[j] = sk.dk1[j] + t2;
        sk.dk2[j] = pfc->mult(mpk.g, x);
        for (k = 0; k < USIZE; k++)
        {
            if (k != j)
            {
                sk.dk3[j][k]= pfc->mult(mpk.R[k], x);
            } 
        }
    }

    
}
void SAKeyGenU(PFC *pfc, SAKU& usk, SAMPK mpk, SAMSK msk)
{
    Big x;
    G1 t1, t2;

    pfc->random(x);
    t1 = pfc->mult(mpk.g, msk.a2);
    t2 = mpk.R0 + mpk.a;
    t2 = pfc->mult(t2, x);
    usk.dk1 = t1 + t2;
    usk.dk2 = pfc->mult(mpk.g, x);
}



void SASSign(PFC *pfc, SSign& sigma, SAK sk, LSSS la, SAMPK mpk, int *M, int ML, char *mess, int ml)
{
    int i, j, k, l;
    char hash[HASHLEN];

    Big eta, zeta;

    G1 t1, t2;
    G1 tr, hm;
    G1 td;
    pfc->random(eta);
    pfc->random(zeta);


    tr = mpk.R0;
    for ( i = 0; i < ML; i++)
    {
        j = M[i];
        t1 = sk.dk1[j];//d_k
        for(k =0; k < ML; k++)
        {
            if (k != i)
            {
                l = M[k];
                t1 = t1 + sk.dk3[j][l];//d_k
            }  
        }
        if(i == 0)
        {
            t2 = pfc->mult(t1, la.w[i]);
        }else{
            t2 =  t2 + pfc->mult(t1, la.w[i]);
        } 
        tr = tr + mpk.R[j];

        if (i==0)
        {
            td = pfc->mult(sk.dk2[j], la.w[i]);
        }else{
            td = td + pfc->mult(sk.dk2[j], la.w[i]);
        }
        
    }
    tr = pfc->mult(tr, eta);
    pfc->start_hash();
	pfc->add_to_hash(mess, ml);//add m
	copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(hm, hash, HASHLEN);
    hm = pfc->mult(hm, zeta);
    sigma.sigma0 = t2 + tr + hm;
    sigma.sigma1 = pfc->mult(mpk.g, eta) + td;
    sigma.sigma2 = pfc->mult(mpk.g, zeta);


}

void SAUSign(PFC *pfc, SSignature& signature, SAKU usk, SSign sigma, SAMPK mpk, char *mess, int ml)
{
    char hash[HASHLEN];

    Big x;
    Big zeta;
    G1 t1, t2;
    G1 hm;

    pfc->random(x);
    pfc->random(zeta);


    t1 = mpk.R0 + mpk.a;
    t1 = pfc->mult(t1, x);

    pfc->start_hash();
	pfc->add_to_hash(mess, ml);//add m
	copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(hm, hash, HASHLEN);
    hm = pfc->mult(hm, zeta);
    signature.sigma0 = sigma.sigma0 + usk.dk1 + t1 + hm;

    t2 = pfc->mult(mpk.g, x);
    signature.sigma1 = sigma.sigma1;
    signature.sigma11 = t2 + usk.dk2;
    t1 = pfc->mult(mpk.g, zeta);
    signature.sigma2 = sigma.sigma2 + t1;

}


void SAVerify(PFC *pfc, SSignature signature, SAMPK mpk, int *M, int ML, char *mess, int ml)
{
    int i, j;
    char hash[HASHLEN];

    G1 tr, hm;
    GT tt1, tt2, tt3, tt4;
    GT result, test;

    tr = mpk.R0;
    for ( i = 0; i < ML; i++)
    {
        j = M[i];
        tr = tr + mpk.R[j];
    }
    printf("v--tr\n");
    tr.G1_Print();
    tt1 = pfc->pairing(signature.sigma0, mpk.g);
    tt2 = pfc->pairing(signature.sigma1, tr);
    tr = mpk.R0 + mpk.a;
    tt3 = pfc->pairing(signature.sigma11, tr);


    pfc->start_hash();
	pfc->add_to_hash(mess, ml);//add m
	copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(hm, hash, HASHLEN);
    tt4 = pfc->pairing(signature.sigma2, hm);

    result = tt1/tt2;
    result = result/tt3;
    result.GT_Print();

    test = tt4*mpk.Z;
    if (result == test)
    {
        printf("SA verify success!\n");
        return;
    }
    printf("SA verify error!\n");

}

void SASign(PFC *pfc, SSignature& signature, SSign& sigma, SAK sk, SAKU usk, LSSS la, SAMPK mpk, int *M, int ML, char *mess, int ml)
{
    int i, j, k, l;
    char hash[HASHLEN];

    Big eta, zeta;

    G1 t1, t2, tsk3;
    G1 tr, hm;
    G1 td;
    //////////////////////
    Big xu;
    Big zetau;
    Big tmp;
    G1 ttmp;
    GT tt1, tt2, tt3, tt4;


    pfc->random(eta);
    pfc->random(zeta);
    /////////////
    pfc->random(xu);
    pfc->random(zetau);

    tr = mpk.R0;
    for ( i = 0; i < ML; i++)
    {
        j = M[i];
        t1 = sk.dk1[j];//d_k
        for(k =0; k < ML; k++)
        {
            if (k != i)
            {
                l = M[k];
                tsk3 = sk.dk3[j][l]; 
                t1 = t1 + tsk3;//d_k
            }  
        }

        if(i == 0)
        {
            t2 = pfc->mult(t1, la.w[i]);
        }else{
            t2 =  t2 + pfc->mult(t1, la.w[i]);
        } 
        tr = tr + mpk.R[j];

        if (i==0)
        {
            td = pfc->mult(sk.dk2[j], la.w[i]);
        }else{
            td = td + pfc->mult(sk.dk2[j], la.w[i]);
        }
        
    }
    printf("tr\n");
    tr.G1_Print();
    tr = pfc->mult(tr, eta);

    pfc->start_hash();
	pfc->add_to_hash(mess, ml);//add m
	copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(hm, hash, HASHLEN);
    hm = pfc->mult(hm, zeta);

    sigma.sigma0 = t2 + tr + hm;

    sigma.sigma1 = pfc->mult(mpk.g, eta) + td;
    sigma.sigma2 = pfc->mult(mpk.g, zeta);

///////////////////////////////////
    t1 = mpk.R0 + mpk.a;
    t1 = pfc->mult(t1, xu);
    pfc->start_hash();
	pfc->add_to_hash(mess, ml);//add m
	copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(hm, hash, HASHLEN);
    hm = pfc->mult(hm, zetau);
    signature.sigma0 = sigma.sigma0 + usk.dk1 + t1 + hm;

    t2 = pfc->mult(mpk.g, xu);
    signature.sigma1 = sigma.sigma1;
    signature.sigma11 = t2 + usk.dk2;

    t1 = pfc->mult(mpk.g, zetau);
    signature.sigma2 = sigma.sigma2 + t1;

}
void SATrans(PFC *pfc, Big& vk, SST& st, SSignature signature, SAMPK mpk)
{
    pfc->random(vk);
    st.sigma0 = pfc->mult(signature.sigma0, vk);
    st.sigma1 = pfc->mult(signature.sigma1, vk);
    st.sigma11 = pfc->mult(signature.sigma11, vk);
    
}
void SASVeri(PFC *pfc, GT& result, SST st, SAMPK mpk, int *M, int ML)
{
    int i, j;
    G1 tr;
    GT tt1, tt2, tt3;

    tr = mpk.R0;
    for ( i = 0; i < ML; i++)
    {
        j = M[i];
        tr = tr + mpk.R[j];
    }
    tt1 = pfc->pairing(st.sigma0, mpk.g);
    tt2 = pfc->pairing(st.sigma1, tr);
    tr = mpk.R0 + mpk.a;
    tt3 = pfc->pairing(st.sigma11, tr);
    result = tt1/tt2;
    result = result/tt3;
}

BOOL SAUVeri(PFC *pfc, GT result, SSignature signature, Big vk, SAMPK mpk, char *mess, int ml)
{
    char hash[HASHLEN];
    G1 tr, hm;
    GT tt4;
    GT test;
    pfc->start_hash();
	pfc->add_to_hash(mess, ml);//add m
	copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(hm, hash, HASHLEN);
    tr = pfc->mult(signature.sigma2, vk);
    tt4 = pfc->pairing(tr, hm);
    test =  pfc->power(mpk.Z, vk);

    test = tt4*test;
    if (result == test)
    {
        //printf("SA-U verify success!\n");
        return TRUE;
    }
    //printf("SA-U verify error!\n");
    return FALSE;
}