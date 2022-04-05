#include <windows.h>
#include "test.h"
#include "me.h"
#include "sa2.h"
#include "trams.h"
#include "avs.h"
#include "dabs.h"

void Setuptest(PFC *pfc)
{
    int Ul = 0;
    int i = 0;

    MPK mpk;
    MSK msk;
    Big bt, bt1, bt2, bt3;
    G1 P;
    G1 tmp1, tmp11, tmp12;
    GT tmp2, tmp3;
    ////////////////////////////
    Ul = 3;
    pfc->random(bt);
    pfc->random(P);

    tmp1 = pfc->mult(P, bt);
    tmp2 = pfc->pairing(P, P);
    tmp2 = pfc->power(tmp2, bt);
    tmp2.GT_Print();
    tmp3 = pfc->pairing(tmp1, P);
   // tmp3.GT_Print();
    if(tmp2 == tmp3)
    {
        printf("e(g, g)^{a} = e(g^{a}, g)\n");
    }
    
    bt = bt + pfc->order();
    tmp2 = pfc->power(pfc->pairing(P, P), bt);
    bt1 = inverse(bt, pfc->order());
    bt2 = bt*bt1%pfc->order();
    cout<<pfc->order()<<endl;
    cout<<bt2<<endl;
    tmp2.GT_Print();
    if (tmp2 == tmp3)
    {
       printf("e(g, g)^{a+order} = e(g^{a}, g)\n");
      
    }
    pfc->power(tmp2, bt1).GT_Print();
    pfc->pairing(P, P).GT_Print();
    




    pfc->random(bt1);
    bt2 = bt + bt1;
    tmp11 = pfc->mult(P, bt1);
    tmp12 = pfc->mult(P, bt2);
    tmp11 = tmp11 + tmp1;
    if(tmp11 == tmp12)
    {
        printf("aP + bP = cP\n");
    }
    pfc->random(bt3);
    bt2 = bt + bt1*bt3;
    tmp11 = pfc->mult(mpk.P, bt2);
    tmp12 = pfc->mult(mpk.P, bt);
    tmp1 = pfc->mult(mpk.P, bt1);
    tmp1 = pfc->mult(tmp1, bt3);
    tmp12 = tmp12 + tmp1;
    if(tmp12 == tmp11)
    {
        printf("g^ag^{bc} = g^{a+bc}\n");
    }

    //ABS_Setup(pfc, mpk, msk, Ul);
    pfc->random(bt1);
    pfc->random(bt);
    bt2 = bt1 + bt;
    tmp11 = pfc->mult(mpk.P, bt2);//g^{a+b}

    tmp1 = -pfc->mult(mpk.P, bt1);
    tmp11 = tmp11 + tmp1;

    tmp12 = pfc->mult(mpk.P, bt);//g^b

    if (tmp11 == tmp12)
    {
       printf("-operation is right\n");
    }
    tmp12 = pfc->mult(tmp12, inverse(bt, pfc->order()));
    if(tmp12 == mpk.P)
    {
        printf("inverse is right\n");
    }
    //ABS_Setup(pfc, mpk, msk, Ul);
    pfc->random(bt1);
    pfc->random(bt);
    pfc->random(mpk.g1);
    pfc->random(mpk.P);
    tmp1 = pfc->mult(mpk.P, bt);
    tmp12 = pfc->mult(mpk.g1, bt);
    tmp11 = tmp1 + tmp12;
    tmp11.G1_Print();

    tmp1 = mpk.P + mpk.g1;
    tmp12 = pfc->mult(tmp1, bt);
    tmp12.G1_Print();
}

void Signtest(PFC *pfc)
{
    int ul = 8;//number of attribute set, 0, 1,2,3,4,5,6,7
    int S[VSIZE] ={0, 2, 4, 5};// attribute set of each signature;
    int SL = 4;
    int M[DSIZE] = {0, 1, 2}; 
    int ML = 3;
    char mess[5]={1,2,3,4,5};
    int ml = 5;

    MPK mpk;
    MSK msk;
    SK sk;
    Sigma signature;

    ABS_Setup(pfc, mpk, msk, ul);
    ABS_KeyGen(pfc, sk, mpk, msk, S, SL);
    ABS_Sign(pfc, signature, mpk, sk, S, SL, M, ML, mess, ml);
    printf("Sign-success!\n");
    ABS_Verify(pfc, signature, mpk, S, SL, M, ML, mess, ml);

}

void GenLSSStest(PFC *pfc)
{
    int ML = 3;
    int i;
    LSSS la;
    Big s;
    Big result = 0;

    pfc->random(s);
    cout<<s<<endl;
    genLambda(pfc, la, ML, s);
    for ( i = 0; i < ML; i++)
    {
        result = (result+la.l[i]*la.w[i])%pfc->order();
    }
    cout<<result<<endl;

}

void Verifytest(PFC *pfc)
{
    int ul = 8;//number of attribute set, 0, 1,2,3,4,5,6,7
    int S[VSIZE] ={0, 2, 4, 5};// attribute set of each signature;
    int SL = 4;
    int M[DSIZE] = {0, 1, 2}; 
    int ML = 3;
    char mess[5]={1,2,3,4,5};
    int ml = 5;
    char hash[HASHLEN];

    MPK mpk;
    MSK msk;
    SK sk;
    Sigma signature;
    EI ei;
    Big vk;
    LSSS la;
    GT ai;

    Big result = 0;

    ABS_Setup(pfc, mpk, msk, ul);
    ABS_KeyGen(pfc, sk, mpk, msk, S, SL); 
    ABS_Sign(pfc, signature, mpk, sk, S, SL, M, ML, mess, ml);
    ABS_Trans(pfc, ei, vk, la, signature, mpk, S, SL, M, ML);
    ABS_SV(pfc, ai, ei, signature, mpk, la, ML);

    SignHash(pfc, hash, signature, ML);
    ABS_UV(pfc, ai, vk, signature, mpk, ML, mess, ml, hash);
}


///////////////////////////////////////////////////////
void SAKeyGentest(PFC *pfc)
{
    int ul = 8;//number of attribute set, 0, 1,2,3,4,5,6,7
    int row = 6;
    int M[DSIZE] = {0, 4, 5}; 
    int ML = 3;
    char mess[5]={1,2,3,4,5};
    int ml = 5;


    int i, j, k, l;
    Big b0 = 0;
    G1 t1, t2;
    GT tt1, tt2, tt3;

    SAMPK mpk;
    SAMSK msk;
    SAK sk;
    SAKU usk;
    LSSS la;
    SSign sigma;
    SSignature signature;


    SASetup(pfc, mpk, msk, ul);
    SAKeyGenS(pfc, sk, la, mpk, msk, row, M, ML);
    SAKeyGenU(pfc, usk, mpk, msk);
    SASSign(pfc, sigma, sk, la, mpk, M, ML, mess, ml); 

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
    }
    printf("g^a1(r)^{xw + xw}\n");
    pfc->pairing(t2, mpk.g).GT_Print();//e(g^a1, g)e(r^{xw}, g);

    t1 = pfc->mult(mpk.g, msk.a1);
    tt1 = pfc->pairing(t1, mpk.g);//e(g^a1, g);
 ////////
    t1 = mpk.R0;
    for ( i = 0; i < ML; i++)
    {
        j = M[i];
        t1 = t1 + mpk.R[j];
        if(i == 0)
        {
            t2 = pfc->mult(sk.dk2[j], la.w[i]);
        }else{
            t2 =  t2 + pfc->mult(sk.dk2[j], la.w[i]);
        } 
    }
    tt2 = pfc->pairing(t1, t2);
    tt2 = tt1 *tt2;
    tt2.GT_Print();
    //////////////////////
    tt2 = pfc->pairing(usk.dk1, mpk.g);//e(g^a2, g)e(r^x, g)
    t1 = mpk.R0 + mpk.a;
    tt3 = pfc->pairing(t1, usk.dk2);//e(r, g^x);
    tt2 = tt2/tt3;
    tt1 = tt2*tt1;
    printf("Z:\n");
    tt1.GT_Print();
    mpk.Z.GT_Print();
    ///
    for ( i = 0; i < ML; i++)
    {
        j = M[i];
        tt1 = pfc->pairing(sk.dk1[j], mpk.g);
        t1 = mpk.R0+mpk.R[j];
        tt3 = pfc->pairing(t1, sk.dk2[j]);//e(r, g^x);
        t1 = pfc->mult(mpk.g, la.l[i]);
        tt2 = pfc->pairing(t1, mpk.g);
        if (tt1 == tt2*tt3)
        {
            printf("success-%d\n", i);
        }   
    }
}

void SAVerifytest(PFC *pfc)
{
    int ul = 8;//number of attribute set, 0, 1,2,3,4,5,6,7
    int row = 6;
    int M[DSIZE] = {0, 4, 5}; 
    int ML = 3;
    char mess[5]={1,2,3,4,5};
    int ml = 5;

    Big vk;
    G1 t1, t2;
    GT tt1, tt2, tt3;
    GT result;

    SAMPK mpk;
    SAMSK msk;
    SAK sk;
    SAKU usk;
    LSSS la;
    SSign sigma;
    SST st;
    SSignature signature;


    SASetup(pfc, mpk, msk, ul);
    SAKeyGenS(pfc, sk, la, mpk, msk, row, M, ML);
    SAKeyGenU(pfc, usk, mpk, msk);

//SASign(pfc, signature, sigma, sk, usk, la, mpk, M, ML, mess, ml);
    SASSign(pfc, sigma, sk, la, mpk, M, ML, mess, ml); 
    SAUSign(pfc, signature, usk, sigma, mpk, mess, ml);
    SATrans(pfc, vk, st, signature, mpk);
    SASVeri(pfc, result,st, mpk, M, ML);
    SAUVeri(pfc, result, signature, vk, mpk, mess, ml);

   // SAVerify(pfc, signature, mpk, M, ML, mess, ml);  
}

void TKeyGentest(PFC *pfc)
{
    int ul = 8;//number of attribute set, 0, 1,2,3,4,5,6,7
    int nl = 6;
    int S[VSIZE] = {0, 1, 4, 5, 6};
    int SL = 5;
    int M[DSIZE] = {0, 4, 5}; 
    int ML = 3;
    char mess[5]={1,2,3,4,5};
    int ml = 5;

    TMPK mpk;
    Big msk;
    TSK tsk;
    TPK tpk;
    LSSS la;
///////////////////////
    int i, j, k;
    Big bt;
    G1 t1, t2;
    GT gt1, gt2, gt3, gt;
    char hash[HASHLEN];


    TSetup(pfc, mpk, msk, ul);

    TKeyGen(pfc, tsk, tpk, la, mpk, msk, S, SL, M, ML, nl);

    for ( i = 0; i < SL; i++)
    {
        j = S[i];
        t1 = tsk.dk0[i];
        gt1 = pfc->pairing(t1, mpk.g);
        pfc->start_hash();
        pfc->add_to_hash((Big)j);
	    copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	    pfc->hash_and_map(t1, hash, HASHLEN);
        gt2 = pfc->pairing(t1, tsk.dk1[i]);
        gt1 = gt1/gt2;
        printf("e(R, g)^{y}\n");
        gt1.GT_Print();
        bt = msk;
        gt1 = pfc->power(gt1, bt);
         printf("e(g2, g)^{y}\n");
        gt1.GT_Print();

    }

        /////auth set

    for ( i = 0; i < ML; i++)
    {
        j = M[i];//aut
        for (k = 0; k < SL; k++)
        {
            if(j == S[k])
            {
                break;
            }
        }
        
        t1 = pfc->mult(tpk.tk0[j], la.w[i]);
        t2 = pfc->mult(tpk.tk1[j], la.w[i]);

        gt1 = pfc->pairing(tsk.dk0[k], t1);
        gt2 = pfc->pairing(tsk.dk1[k], t2);
        gt = gt1/gt2;
        if (i == 0)
        {
           gt3 = gt;
        }else{
            gt3 = gt3*gt;
        }
    }
   printf("e(g2, g)^{y}----\n");
    gt3.GT_Print();

}

void TVerifytest(PFC *pfc)
{
    int ul = 8;//number of attribute set, 0, 1,2,3,4,5,6,7
    int nl = 6;
    int S[VSIZE] = {0, 1, 4, 5, 6};
    int SL = 5;
    int M[DSIZE] = {0, 4, 5}; 
    int ML = 3;
    char mess[5]={1,2,3,4,5};
    int ml = 5;

    TMPK mpk;
    Big msk;
    TSK tsk;
    TPK tpk;
    LSSS la;
    TSign signature;
    TSetup(pfc, mpk, msk, ul);
    TKeyGen(pfc, tsk, tpk, la, mpk, msk, S, SL, M, ML, nl);
    TSignGen(pfc, signature, tsk, tpk, mpk, S, SL, M, ML, nl, mess, ml);
    TVerify(pfc, signature, tpk, la, mpk, M, ML, nl, mess, ml);

}


void AVerifytest(PFC *pfc)
{
    int ul = 8;//number of attribute set, 0, 1,2,3,4,5,6,7
    int nl = 6;
    int S[VSIZE] = {0, 1, 4, 5, 6};
    int SL = 5;
    int M[DSIZE] = {0, 4, 5}; 
    int ML = 3;
    char mess[5]={1,2,3,4,5};
    int ml = 5;

    AMPK mpk;
    Big msk;
    ASK ask;
    APK apk;
    LSSS la;
    ASign signature;

///////////////////////

ASetup(pfc, mpk, msk, ul);
AKeyGen(pfc, ask, apk, la, mpk, msk, S, SL, M, ML, nl);
ASignGen(pfc, signature, ask, apk, la, mpk, S, SL, M, ML, nl, mess, ml);
AVerify(pfc, signature, apk, la, mpk, M, ML, nl, mess, ml);


}

void ASUVerifytest(PFC *pfc)
{
    int ul = 8;//number of attribute set, 0, 1,2,3,4,5,6,7
    int nl = 6;
    int S[VSIZE] = {0, 1, 4, 5, 6};
    int SL = 5;
    int M[DSIZE] = {0, 4, 5}; 
    int ML = 3;
    char mess[5]={1,2,3,4,5};
    int ml = 5;

    AMPK mpk;
    Big msk;
    ASK ask;
    APK apk;
    LSSS la;
    ASign signature;
    Big vk;
    ASign newSign;
    GT Sigma;
///////////////////////
ASetup(pfc, mpk, msk, ul);
AKeyGen(pfc, ask, apk, la, mpk, msk, S, SL, M, ML, nl);
ASignGen(pfc, signature, ask, apk, la, mpk, S, SL, M, ML, nl, mess, ml);
ASTrans(pfc, vk, newSign, signature, nl);
ASVerify(pfc, Sigma, newSign, apk, la, mpk, M, ML, nl);
AUVerify(pfc, vk, Sigma, newSign, mpk, mess, ml);
}


void DKeyGentest(PFC *pfc)
{
    int ul = 8;//number of attribute set, 0, 1,2,3,4,5,6,7
    int nl = 7;
    int S[VSIZE] = {0, 1, 4, 5, 6};
    int SL = 5;
    int M[DSIZE] = {0, 4, 5}; 
    int ML = 3;
    char mess[5]={1,2,7,4,4};
    int ml = 5;

    DMPK mpk;
    DMSK msk;
    LSSS la;
    DUSK usk;
    DSign newSign, signature;
////////////////////////
    int i, j, k;
    Big bt;
    G1 t1, t2;
    G1 tmp1, tmp2;
    GT gt1, gt2, gt3, gt;

    DSetup(pfc, mpk, msk, ul);
    D2KeyGen(pfc, usk, la, mpk, msk, S, SL, M, ML);

    for ( i = 0; i < ML; i++)
    {
        j = M[i];
        for (k = 0; k < SL; k++)
        {
            if (j == S[k])
            {
                break;
            }
            
        }
        t1 = pfc->mult(usk.dk0[k], la.w[i]);
        tmp1 = pfc->mult(usk.dk1[k], la.w[i]);
        gt2 = pfc->pairing(tmp1, mpk.U[j]); 
        if (i == 0)
        {
            t2 = t1;
            gt3 = gt2;
        }else{
            t2 = t2 +t1;
            gt3 = gt3*gt2;
        }
    }

    gt1 = pfc->pairing(t2, mpk.g1);
    gt1 = gt1/gt3;
    gt = pfc->pairing(usk.D, mpk.g1);
    gt = gt*gt1;
    if (gt == mpk.Z)
    {
        printf("keygen is success!\n");
    }else{
        printf("keygen is error!\n");
    }

}

void DVerifytest(PFC *pfc)
{
    int ul = 8;//number of attribute set, 0, 1,2,3,4,5,6,7
    int nl = 7;
    int S[VSIZE] = {0, 1, 4, 5, 6};
    int SL = 5;
    int M[DSIZE] = {0, 4, 5}; 
    int ML = 3;
    char mess[5]={1,2,7,4,4};
    int ml = 5;

    DMPK mpk;
    DMSK msk;
    LSSS la;
    DUSK usk;
    G1 D;
    DSign Sigma, signature;
    DTSign ts;
    GT Sigma2;
    Big vk;

    DSetup(pfc, mpk, msk, ul);
    DKeyGen(pfc, usk, D, la, mpk, msk, S, SL, M, ML);
    DSSignGen(pfc, Sigma, la, usk, mpk, S, SL, M, ML, nl, mess, ml);
    DUSignGen(pfc, signature, D, Sigma, mpk, nl, mess, ml);
    DTrans(pfc, vk, ts, signature, nl);
    DSVerify(pfc, Sigma2, ts, mpk, nl);
    DUVerify(pfc, vk, Sigma2, signature, mpk, mess, ml);
}

void Timetest(PFC *pfc)
{
    LARGE_INTEGER freq;  
	LARGE_INTEGER start_t, stop_t;  
	double exe_time=0;  
	int counter = 1000;//1000
	QueryPerformanceFrequency(&freq); 
	exe_time = 0;

    int i;

    Big a1, a2;
    G1 g1, g2, tmp;
    GT gt1, gt2, gtmp;


    exe_time = 0;
    pfc->random(a1);
    pfc->random(g1);
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        pfc->mult(g1, a1);
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of E_1= " << exe_time/counter<< " ms" << endl;

    exe_time = 0;
    pfc->random(a1);
    pfc->random(g1);
    pfc->random(g2);
    gt1 = pfc->pairing(g1, g2);
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        pfc->power(gt1, a1);
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of E_2= " << exe_time/counter<< " ms" << endl;


    exe_time = 0;
    pfc->random(g1);
    pfc->random(g2);
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        gt1 = pfc->pairing(g1, g2);
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of P= " << exe_time/counter<< " ms" << endl;

    exe_time = 0;
    pfc->random(g1);
    pfc->random(g2);
    gt1 = pfc->pairing(g1, g2);
    pfc->random(g1);
    pfc->random(g2);
    gt2 = pfc->pairing(g1, g2);
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        gtmp = gt1/gt2;
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of GT / = " << exe_time/counter<< " ms" << endl; 

    exe_time = 0;
    pfc->random(g1);
    pfc->random(g2);
    gt1 = pfc->pairing(g1, g2);
    pfc->random(g1);
    pfc->random(g2);
    gt2 = pfc->pairing(g1, g2);
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        gtmp = gt1*gt2;
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of GT * = " << exe_time/counter<< " ms" << endl; 

    exe_time = 0;
    pfc->random(a1);
    pfc->random(g1);
    pfc->random(g2); 
 	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        gtmp = pfc->pairing(g1, g2);
        gt1 = pfc->power(gtmp, a1);
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of e(g, g)^t = " << exe_time/counter<< " ms" << endl;    
    exe_time = 0;
   	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        tmp = pfc->mult(g1, a1);
        gt1 = pfc->pairing(tmp, g2);
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of e(g^t, g) = " << exe_time/counter<< " ms" << endl; 

    exe_time = 0;
    pfc->random(a1);
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        inverse(a1, pfc->order());
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of 1/vk = " << exe_time/counter<< " ms" << endl;     
}

void Sizetest(PFC *pfc)
{
    G1 a1, a2;
    GT gt1;

    pfc->random(a1);
    pfc->random(a2);
    gt1 = pfc->pairing(a1, a2);

    printf("the size of G1:\n");
    a1.G1_Print();

    printf("the size of G2£º\n");
    gt1.GT_Print();
    
}

void KeyGenTimetest(PFC *pfc, int choose)
{
    int counter = 10;
    int i;
    ///int choose = 30;
    char mess[5] = {1, 2, 3, 4, 5};
    int ml = 5;

    int ul;// size of attribute universe
    int l; // size of access policy

    int M[DSIZE];
    int ML;
    int S[VSIZE];
    int SL;
    
    int MEL;
    int SEL;
    /////////////////////////////////////////


    switch(choose){
        case 1:
            ul = 8;
            l = 7;//6
            SL = 6;//4
            ML = 5;//2
            break;
        case 2:
            ul = 10;
            l = 9;//6
            SL = 8;//4
            ML = 7;//2
            break;
        case 3:
            ul = 15;
            l = 14;//6
            SL = 13;//4
            ML= 10;
            break;
        case 4:
            ul = 16;
            l = 15;//6
            SL = 14;//4
            ML= 13;
            break;
        case 5:
            ul = 18;
            l = 17;//6
            SL = 16;//4
            ML = 15;
            break;
        case 6:
            ul = 20;
            l = 19;//6
            SL = 18;//4
            ML= 17;
            break;
        case 7:
            ul = 23;
            l = 22;//6
            SL = 21;//4
            ML = 20;
            break;
        case 8:
            ul = 26;
            l = 25;//6
            SL = 24;//4
            ML = 23;
            break;
        case 9:
            ul = 28;
            l = 27;//6
            SL = 26;//4
            ML = 25;
            break;
        case 10:
            ul = 30;
            l = 29;//6
            SL = 28;//4
            ML = 27;
            break;
        case 11:
            ul = 33;
            l = 32;//6
            SL = 31;//4
            ML = 30;
            break;
    }

    for ( i = 0; i < ML; i++)
    {
        M[i] = i+1;
    }
    for ( i = 0; i < SL; i++)
    {
        if (i < ML)
        {
            S[i] = M[i];
        }else{
            S[i] = i;
        }  
    } 
    //MeTime(pfc, ul, M, ML, S, SL, mess, ml, counter);
    //SA2Time(pfc, ul, M, ML, S, SL, l, mess, ml, counter);
    TramsTime(pfc, ul, M,  ML, S, SL, l, mess, ml, counter);
   // AVSTime(pfc, ul, M, ML, S, SL, l, mess, ml, counter);
   // DABSTime(pfc, ul, S, SL, M, ML, l, mess, ml, counter);

}

void MeTime(PFC *pfc, int ul, int *M, int ML, int *S, int SL, char *mess, int ml, int counter)
{
    LARGE_INTEGER freq;  
	LARGE_INTEGER start_t, stop_t;  
	double exe_time=0;  
	//int counter = 1;//1000
	QueryPerformanceFrequency(&freq); 
	exe_time = 0; 

    int i;

    char hash[HASHLEN];
    MPK mpk;
    MSK msk;
    SK sk;
    Sigma signature;
    EI ei;
    Big vk;
    LSSS la;
    GT ai;

    Big result = 0;
    BOOL re;

    ABS_Setup(pfc, mpk, msk, ul);
    exe_time = 0;
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        ABS_KeyGen(pfc, sk, mpk, msk, S, SL); 
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of KeyGen of me = " << exe_time/counter<< " ms" << endl;   

    exe_time = 0;
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        ABS_Sign(pfc, signature, mpk, sk, S, SL, M, ML, mess, ml);
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of Sign of me = " << exe_time/counter<< " ms" << endl;   
        
    
    ABS_Trans(pfc, ei, vk, la, signature, mpk, S, SL, M, ML);
    ABS_SV(pfc, ai, ei, signature, mpk, la, ML);
    SignHash(pfc, hash, signature, ML);

    exe_time = 0;
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        re = ABS_UV(pfc, ai, vk, signature, mpk, ML, mess, ml, hash);
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
        if(re !=true)
        {
            printf("%d-th fail in our scheme!\n", i);
            break;
        }
	}
	cout << "The performance of Verify of me = " << exe_time/counter<< " ms" << endl;   
           
   
}

void SA2Time(PFC *pfc, int ul, int *M, int ML, int *S, int SL, int row, char *mess, int ml, int counter)
{
    LARGE_INTEGER freq;  
	LARGE_INTEGER start_t, stop_t;  
	double exe_time=0;  
	//int counter = 1;//1000
	QueryPerformanceFrequency(&freq); 
	exe_time = 0; 

    int i;

    Big vk;
    G1 t1, t2;
    GT tt1, tt2, tt3;
    GT result;

    SAMPK mpk;
    SAMSK msk;
    SAK sk;
    SAKU usk;
    LSSS la;
    SSign sigma;
    SST st;
    SSignature signature;
    BOOL re;


    SASetup(pfc, mpk, msk, ul);
    exe_time = 0;
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        SAKeyGenS(pfc, sk, la, mpk, msk, row, M, ML);
        SAKeyGenU(pfc, usk, mpk, msk);
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of KeyGen of SA = " << exe_time/counter<< " ms" << endl;   

    exe_time = 0;
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        SASSign(pfc, sigma, sk, la, mpk, M, ML, mess, ml); 
        SAUSign(pfc, signature, usk, sigma, mpk, mess, ml);
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of Sign of SA = " << exe_time/counter<< " ms" << endl;   


    SATrans(pfc, vk, st, signature, mpk);
    SASVeri(pfc, result,st, mpk, M, ML);

        exe_time = 0;
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        re = SAUVeri(pfc, result, signature, vk, mpk, mess, ml);
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
        if(re !=true)
        {
            printf("%d-th fail in the SA!\n", i);
            break;
        }
	}
	cout << "The performance of Verify of SA = " << exe_time/counter<< " ms" << endl;   
}

void TramsTime(PFC *pfc, int ul, int *M, int ML, int *S, int SL, int nl, char *mess, int ml, int counter)
{
    LARGE_INTEGER freq;  
	LARGE_INTEGER start_t, stop_t;  
	double exe_time=0;  
	//int counter = 1;//1000
	QueryPerformanceFrequency(&freq); 
	exe_time = 0; 

    int i;

    TMPK mpk;
    Big msk;
    TSK tsk;
    TPK tpk;
    LSSS la;
    TSign signature;
    BOOL re;

    TSetup(pfc, mpk, msk, ul);

    exe_time = 0;
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        TKeyGen(pfc, tsk, tpk, la, mpk, msk, S, SL, M, ML, nl);
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of KeyGen of trams = " << exe_time/counter<< " ms" << endl;   

    exe_time = 0;
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        TSignGen(pfc, signature, tsk, tpk, mpk, S, SL, M, ML, nl, mess, ml);
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of Sign of trams = " << exe_time/counter<< " ms" << endl;   

    exe_time = 0;
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        re = TVerify(pfc, signature, tpk, la, mpk, M, ML, nl, mess, ml);
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
        if(re !=true)
        {
            printf("%d-th fail in trams!\n", i);
            break;
        }
	}
	cout << "The performance of Verify of trams = " << exe_time/counter<< " ms" << endl;   
  
}

void AVSTime(PFC *pfc, int ul, int *M, int ML, int *S, int SL, int nl, char *mess, int ml, int counter)
{
    LARGE_INTEGER freq;  
	LARGE_INTEGER start_t, stop_t;  
	double exe_time=0;  
	//int counter = 1;//1000
	QueryPerformanceFrequency(&freq); 
	exe_time = 0; 

    int i;

    AMPK mpk;
    Big msk;
    ASK ask;
    APK apk;
    LSSS la;
    ASign signature;
    Big vk;
    ASign newSign;
    GT Sigma;
    BOOL re;
///////////////////////
    ASetup(pfc, mpk, msk, ul);

    exe_time = 0;
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        AKeyGen(pfc, ask, apk, la, mpk, msk, S, SL, M, ML, nl);
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of KeyGen of AVS = " << exe_time/counter<< " ms" << endl;   

    exe_time = 0;
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        ASignGen(pfc, signature, ask, apk, la, mpk, S, SL, M, ML, nl, mess, ml);
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of Sign of AVS = " << exe_time/counter<< " ms" << endl;  

    ASTrans(pfc, vk, newSign, signature, nl);
    ASVerify(pfc, Sigma, newSign, apk, la, mpk, M, ML, nl);

    exe_time = 0;
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        re = AUVerify(pfc, vk, Sigma, newSign, mpk, mess, ml); 
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
        if(re !=true)
        {
            printf("%d-th fail in the AVS!\n", i);
            break;
        }
	}
	cout << "The performance of Verify of AVS = " << exe_time/counter<< " ms" << endl;  

}

void DABSTime(PFC *pfc, int ul, int *S, int SL, int *M, int ML, int nl, char *mess, int ml, int counter)
{
    LARGE_INTEGER freq;  
	LARGE_INTEGER start_t, stop_t;  
	double exe_time=0;  
	//int counter = 1;//1000
	QueryPerformanceFrequency(&freq); 
	exe_time = 0; 

    int i;

    DMPK mpk;
    DMSK msk;
    LSSS la;
    DUSK usk;
    G1 D;
    DSign Sigma, signature;
    DTSign ts;
    GT Sigma2;
    Big vk;
    BOOL re;


    DSetup(pfc, mpk, msk, ul);
    exe_time = 0;
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        DKeyGen(pfc, usk, D, la, mpk, msk, S, SL, M, ML);
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of KeyGen of Dabs = " << exe_time/counter<< " ms" << endl;   

    exe_time = 0;
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        DSSignGen(pfc, Sigma, la, usk, mpk, S, SL, M, ML, nl, mess, ml);
        DUSignGen(pfc, signature, D, Sigma, mpk, nl, mess, ml);
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart;  
	}
	cout << "The performance of Sign of Dabs = " << exe_time/counter<< " ms" << endl;   
   

    DTrans(pfc, vk, ts, signature, nl);
    DSVerify(pfc, Sigma2, ts, mpk, nl);

    exe_time = 0;
	for(i = 0; i < counter; i++)
	{
		QueryPerformanceCounter(&start_t); 
        re = DUVerify(pfc, vk, Sigma2, signature, mpk, mess, ml);   
		QueryPerformanceCounter(&stop_t);  
		exe_time += 1e3*(stop_t.QuadPart-start_t.QuadPart)/freq.QuadPart; 
        if(re !=true)
        {
            printf("%d-th fail in the Dabs!\n", i);
            break;
        } 
	}
	cout << "The performance of Verify of Dabs = " << exe_time/counter<< " ms" << endl;  
    
}