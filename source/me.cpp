#include "me.h"

void ABS_Setup(PFC *pfc, MPK& mpk, MSK& msk, int Ul)
{
	int i = 0;
	pfc->random(mpk.P);
	for ( i = 0; i < Ul; i++)
	{
		pfc->random(msk.t[i]);
		mpk.T[i] = pfc->mult(mpk.P, msk.t[i]);
	}
	pfc->random(msk.alpha);
	pfc->random(msk.beta);
	mpk.g1 = pfc->mult(mpk.P, msk.alpha);
	mpk.Y = pfc->pairing(mpk.P, mpk.P);
	mpk.Y = pfc->power(mpk.Y, msk.beta);
}

void ABS_KeyGen(PFC *pfc, SK& sk, MPK mpk, MSK msk, int *S, int SL)
{
	int i, j;
	Big s;
	Big bt1;
	if(VSIZE < SL)
	{
		printf("VSIZE < SL \n");
		return;
	}
	pfc->random(s);
	sk.K2 = pfc->mult(mpk.P, s);
	bt1 = msk.beta + msk.alpha*s;
	sk.K1 = pfc->mult(mpk.P, bt1);
	for(i = 0; i < SL; i++)
	{
		j = S[i];
		sk.K3[i] = pfc->mult(mpk.T[j], s);
	}
}
///M-->S
void ABS_Sign(PFC *pfc, Sigma& signature, MPK mpk, SK sk, int *S, int SL,  int *M, int ML, char *mess, int ml)
{
	int i, j, k;
	char hash[HASHLEN];
	char t[HASHLEN];

	Big r1, r2;
	G1 E1, tmp;

	if (SL < ML)
	{
		printf("SL < ML \n");
		return;
	}
	pfc->random(r1);
	pfc->random(r2);
	signature.sigma0 = pfc->mult(mpk.P, r1);//g^r1
	tmp = pfc->mult(mpk.P, r2);//g^r2
	signature.sigma1 = sk.K2 + tmp;

	for (i = 0; i < ML; i++)
	{
		j = M[i];//index of S
		k = S[j];
		tmp = pfc->mult(mpk.T[k], r2);
		signature.sigma2[i] = sk.K3[j] + tmp;
	}
	tmp = pfc->mult(mpk.g1, r2);
	E1 = sk.K1 + tmp;

	SignHash(pfc, t, signature, ML);
	pfc->start_hash();
	pfc->add_to_hash(t, HASHLEN);
	pfc->add_to_hash(mess, ml);//add m
	copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(tmp, hash, HASHLEN);
	tmp = pfc->mult(tmp, r1);
	signature.sigma3 = E1 + tmp;
}
void ABS_Trans(PFC *pfc, EI& ei, Big& vk, LSSS& la, Sigma signature, MPK mpk, int *S, int SL, int *M, int ML)
{
	int i, j, k;
	Big u, nu;
	G1 tmp1, tmp2;
	GT t1;
	pfc->random(vk);
	ei.sigma3 = pfc->mult(signature.sigma3, vk);
	genLambda(pfc, la, ML, vk);

	for ( i = 0; i < ML; i++)
	{
		j = M[i];
		k = S[j];
		pfc->random(u);
	    nu =pfc->order() - u;//-u
		ei.EI2[i] = pfc->mult(mpk.P, u);//g^{u}
		tmp1 = pfc->mult(mpk.T[k], nu);
		tmp2 = pfc->mult(mpk.g1, la.l[i]);//g^{a\lambda}
		ei.EI1[i] = tmp2 + tmp1;
	}
}

void ABS_SV(PFC *pfc, GT& ai, EI ei, Sigma signature, MPK mpk, LSSS la, int ML)
{
	int i;
	GT t1, t2, tmpt, result, test;
	GT tt;

	t1 = pfc->pairing(ei.EI1[0], signature.sigma1);
	t2 = pfc->pairing(ei.EI2[0], signature.sigma2[0]);
	tmpt = t1*t2;
	result = pfc->power(tmpt, la.w[0]);
	for ( i = 1; i < ML; i++)
	{
		t1 = pfc->pairing(ei.EI1[i], signature.sigma1);
		t2 = pfc->pairing(ei.EI2[i], signature.sigma2[i]);
		tmpt = t1*t2;
		tmpt = pfc->power(tmpt, la.w[i]);	
		result = result*tmpt;
	}
	test = pfc->pairing(ei.sigma3, mpk.P);
	ai = test/result; 
}
BOOL ABS_UV(PFC *pfc, GT ai, Big vk, Sigma signature, MPK mpk, int ML, char *mess, int ml, char *hash)
{
	char t[HASHLEN];
	G1 tmp1, hm;
	GT t1, t2, t3;
	Big bt;
	bt = inverse(vk, pfc->order());
	t3 = pfc->power(ai, bt);
	pfc->start_hash();
	pfc->add_to_hash(hash, HASHLEN);
	pfc->add_to_hash(mess, ml);//add m
	copyChar(pfc->finish_hash_to_char(), t, HASHLEN);
	pfc->hash_and_map(hm, t, HASHLEN);

	t1 = pfc->pairing(hm, signature.sigma0); //e(H(m), g^r)
	t2 = mpk.Y;
	if(t3 == t1*t2)
	{
		//printf("uv-success!\n");
		return true;
	}
	///printf("uv-error!\n");
	return false;

}

BOOL ABS_UV2(PFC *pfc, GT ai, Big vk, Sigma signature, MPK mpk, int ML, char *mess, int ml)
{
	char hash[HASHLEN];
	char t[HASHLEN];
	G1 tmp1, hm;
	GT t1, t2, t3;
	Big bt;
	bt = inverse(vk, pfc->order());
	t3 = pfc->power(ai, bt);

	SignHash(pfc, t, signature, ML);
	pfc->start_hash();
	pfc->add_to_hash(t, HASHLEN);
	pfc->add_to_hash(mess, ml);//add m
	copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(hm, hash, HASHLEN);

	t1 = pfc->pairing(hm, signature.sigma0); //e(H(m), g^r)
	t2 = mpk.Y;
	if(t3 == t1*t2)
	{
		//printf("uv-success!\n");
		return true;
	}
	//printf("uv-error!\n");
	return false;

}
void SignHash(PFC *pfc, char *hash, Sigma signature, int ML)
{
	int i;
	pfc->start_hash();
	pfc->add_to_hash(signature.sigma0);
	pfc->add_to_hash(signature.sigma1);
	for ( i = 0; i < ML; i++)
	{
		pfc->add_to_hash(signature.sigma2[i]);
	}
	copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
}

BOOL ABS_Verify(PFC *pfc, Sigma signature, MPK mpk, int *S, int SL, int *M, int ML, char *mess, int ml)
{
	int i, j, k;
	char hash[HASHLEN];
	char t[HASHLEN];

	Big u, nu, iml;
	EI ei;
	G1 tmp1, tmp2;
	GT t1, t2, result, tmpt;
	GT test;
	for ( i = 0; i < ML; i++)//verify 1 attribute
	{
		j = M[i];
		k = S[j];
		pfc->random(u);
	    nu =pfc->order() - u;//-u
		ei.EI2[i] = pfc->mult(mpk.P, u);//g^{u}
		tmp1 = pfc->mult(mpk.T[k], nu);
		ei.EI1[i] = mpk.g1 + tmp1;

		t1 = pfc->pairing(ei.EI1[i], signature.sigma1);
		t2 = pfc->pairing(ei.EI2[i], signature.sigma2[i]);
		tmpt = t1*t2;
		if (i == 0)
		{
			result = tmpt;
		}else{
			
			result = result*tmpt;
		}
	}
	iml = inverse(ML, pfc->order());
	result = pfc->power(result, iml);

	SignHash(pfc, t, signature, ML);
	pfc->start_hash();
	pfc->add_to_hash(t, HASHLEN);
	pfc->add_to_hash(mess, ml);//add m
	copyChar(pfc->finish_hash_to_char(), hash, HASHLEN);
	pfc->hash_and_map(tmp1, hash, HASHLEN);
	t1 = pfc->pairing(tmp1, signature.sigma0); //e(H(m), g^r)

	test = pfc->pairing(signature.sigma3, mpk.P);
	if (test==result*t1*mpk.Y)
	{
		printf("success!\n");
		return true;
	}
	printf("error!\n");
	return false;
}

void genLambda(PFC *pfc, LSSS& la, int ML, Big s)
{
	int i;
	Big tmp = 0;
	Big tmp1;

	for ( i = 0; i < ML-1; i++)
	{
		pfc->random(la.l[i]);
		pfc->random(la.w[i]);
		tmp = (tmp+la.l[i]*la.w[i])% pfc->order();	
	}
	if (s < tmp)
	{
		tmp1 = s + pfc->order() - tmp;
	}else{
		tmp1 = s - tmp;
	}
	pfc->random(la.l[ML-1]);
	la.w[ML-1] = inverse(la.l[ML-1], pfc->order());
	la.w[ML-1] = la.w[ML-1]*tmp1%pfc->order();
}



