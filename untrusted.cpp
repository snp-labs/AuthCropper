#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pbc.h>
#include <openssl/sha.h>
#include <time.h>
#include "untrusted.h"
time_t startTime;
time_t endTime;

double keygenTime = 0;
double updateTime = 0;
double signTime = 0;
double verifyTime = 0;

//const int kBase = 8;
const int kBase = 8;
const int kL = 64;
const int kM = 256;

void create_timePeriod(timePeriod_t _id, int _bit)
{
	int i;
	int length = (_bit/kBase) + ( (_bit % kBase > 0) ? (1) : (0) );

	_id->bit = _bit;
	_id->data = (uchar_t*) malloc (length * sizeof(uchar_t));

	for(i=0; i<length; i++)
	{
		_id->data[i] = 0x00;
	}
}

int compare_timePeriod(timePeriod_t _a, timePeriod_t _b)
{
	int i;
	for(i=0; i<_a->bit; i++)
	{
		if(0 == CHECK_BIT(_a->data, i, kBase))
		{
			if(0 == CHECK_BIT(_b->data, i, kBase))
			{
				continue;
			}
			return 1;
		}
		else
		{
			if(0 != CHECK_BIT(_b->data, i, kBase))
			{
				continue;
			}
			return -1;
		}
	}
	return 0;
/*
	for(i=_a->bit-1; i>=0; i--)
	{
		if(0 == CHECK_BIT(_a->data, i, kBase))
		{
			if(0 == CHECK_BIT(_b->data, i, kBase))
			{
				continue;
			}
			return 1;		// a < b
		}
		else
		{
			if(0 == CHECK_BIT(_b->data, i, kBase))
			{
				return -1;	// a > b
			}
			continue;
		}
	}
	return 0;	// a == b
*/
}

void print_timePeriod(timePeriod_t _id)
{
	int i;
	char ch;

	for(i=0; i<_id->bit; i++)
	{
		ch = (0 == CHECK_BIT(_id->data, i, kBase)) ? ('0') : ('1');
		printf("%c", ch);
	}
	printf(", %d bit\n", _id->bit);
}

void clear_timePeriod(timePeriod_t _id)
{
	free(_id->data);
}

/*
 * sibling
 */
void sibling(timePeriod_t _k, timePeriod_t _id, int _bit)
{
	int i, j;
	int index = _bit-1;
	int length;

	if(_id->bit == index)
	{
		length = (_id->bit/kBase) + ( (_id->bit % kBase > 0) ? (1) : (0) );
		create_timePeriod(_k, _id->bit);
		for(i=0; i<length; i++)
		{
			_k->data[i] = _id->data[i];
		}
		return;
	}

	if(0 != CHECK_BIT(_id->data, index, kBase))
	{
		_k->bit = -1;
		_k->data = NULL;
		return;
	}

	length = (_bit/kBase) + ( (_bit % kBase > 0) ? (1) : (0) );

	create_timePeriod(_k, _bit);
	for(i=0; i<_k->bit-1; i++)
	{
		if(0 != CHECK_BIT(_id->data, i, kBase))
		{
			SET_BIT(_k->data, i, kBase);
			continue;
		}
		CLEAR_BIT(_k->data, i, kBase);
	}
	SET_BIT(_k->data, i, kBase);
}

/*
 * untrusted update scheme
 * - setup
 * - keyGen
 * - checkKey
 * - update
 * - sign
 * - verifiy
 */
void setup(pairing_t _pairing)
{
	FILE *fp;
	char param[1024];
	size_t count;

	printf("\n## setup...");
	startTime = clock();


	//fp = (NULL == (fp = fopen("./a.param", "r"))) ? (stdin) : (fp);
	//fp = (NULL == (fp = fopen("param", "r"))) ? (stdin) : (fp);
	fp = (NULL == (fp = fopen("a1.param", "r"))) ? (stdin) : (fp);
	count = fread(param, 1, 1024, fp);
	if(!count) pbc_die("input error");

	pairing_init_set_buf(_pairing, param, count);


	endTime = clock();
	printf("complete\n");
	printf("Elapsed time: %g\n\n", ELAPSEDTIME(startTime, endTime));
}

void keyGen(int _l, int _m, vk_t _vk, encsk_t _encsk, pairing_t _pairing)
{
	int index, i, j, length;

	element_t v, r;			// Zp
	element_t gv, temp, temp1;		// G1

	printf("\n## key gen...");
	startTime = clock();


	/*
	 *  ===========
	 * |generate vk|
	 *  ===========
	 */
	_vk->hLength = _l + 1;
	_vk->fLength = _m + 1;
	_vk->h = (element_t *) malloc ((_vk->hLength) * sizeof(element_t));
	_vk->f = (element_t *) malloc ((_vk->fLength) * sizeof(element_t));

	element_init_Zr(v, _pairing);
	//element_init_Zr(w, _pairing);

	element_init_G1(temp, _pairing);
	element_init_G1(temp1, _pairing);
	element_init_G1(_vk->g, _pairing);
	element_init_G1(gv,_pairing);
	element_init_GT(_vk->V, _pairing);
	//element_init_GT(_vk->W, _pairing);

	// g <- random
	element_random(_vk->g);

	// h[i] <- random
	for(i=0; i<_vk->hLength; i++)
	{
		element_init_G1(_vk->h[i], _pairing);
		element_random(_vk->h[i]);
	}

	// f[i] = random
	for(i=0; i<_vk->fLength; i++)
	{
		element_init_G1(_vk->f[i], _pairing);
		element_random(_vk->f[i]);
	}

	// V = e(g,g)^v
	element_random(v);
	element_pow_zn(gv, _vk->g, v);
	pairing_apply(_vk->V, _vk->g, gv, _pairing);

	/* W = e(g,g)^w
	element_random(w);
	element_pow_zn(temp, _vk->g, w);
	pairing_apply(_vk->W, _vk->g, temp, _pairing);
	*/

	/*
	 *  =============
	 * |generate encsk|
	 *  ==============
	 */
	_encsk->kLength = _l + 1;
	_encsk->K = (struct k_s *) malloc ((_encsk->kLength) * sizeof(struct k_s));
	
	element_init_Zr(r, _pairing);
	//element_init_Zr(vw, _pairing);

	//element_init_G1(gvw, _pairing);

	// ID = 0...01
	create_timePeriod(_encsk->ID, _l);
	i = _encsk->ID->bit - 1;
	SET_BIT(_encsk->ID->data, i, kBase);

	// K = [ g^(v+w) * (h[0] * TT h[i]^bit(i,k[i]))^r, g^r, h[i+1]^r, ... , h[l]^r ]
	// g^(v+w)
	//element_add(vw, v, w);
	//element_pow_zn(gvw, _vk->g, vw);
#ifdef DEBUG
printf("\n");
#endif
	for(i=1; i<_encsk->kLength-1; i++)		// i = 1 to l-1
	{
		index = i-1;
#ifdef DEBUG
printf("==== %d ====\n", index);
#endif
		_encsk->K[index].bLength = _encsk->kLength - 1 - i;
		_encsk->K[index].b = (element_t *) malloc ((_encsk->K[index].bLength) * sizeof(element_t));

		element_init_G1(_encsk->K[index].a0, _pairing);
		element_init_G1(_encsk->K[index].a1, _pairing);

		// a[0] = g^(v+w) * (h[0] * TT h[i]^bit(i,k[i]))^r
		// h[0] * TT h[i]^bit(i,k[i]) = h[0] * h[i]
		element_random(r);
		element_mul(temp, _vk->h[0], _vk->h[i]);		// temp = h[0] * h[i]
		element_pow_zn(temp1, temp, r);					// temp1 = (h[0] * h[i])^r
		element_mul(_encsk->K[index].a0, gv, temp1);	// a0 = g^(v) * (h[0] * h[i])^r
#ifdef DEBUG
printf("a0 = g^(v) * (h[0] * h[%d])^r\n", i);
#endif

		// a[1]	= g^r
		element_pow_zn(_encsk->K[index].a1, _vk->g, r);
#ifdef DEBUG
printf("a1 = a1^r\n");
#endif

		// b[j] = h[j]^r
		for(j=0; j<_encsk->K[index].bLength; j++)		// j = 0 to l - 1 - i
		{
			length = _encsk->kLength - _encsk->K[index].bLength + j;
			element_init_G1(_encsk->K[index].b[j], _pairing);
			element_pow_zn(_encsk->K[index].b[j], _vk->h[length], r);
#ifdef DEBUG
printf("b[%d] = h[%d]^r\n", j, length);
#endif
		}
	}
	// K[l]
	index = i-1;
	_encsk->K[index].bLength = -1;		// k[l] = NULL;
#ifdef DEBUG
printf("==== %d ====\n", index);
#endif

	// k[l+1]
	index = i;
#ifdef DEBUG
printf("==== %d ====\n", index);
#endif
	element_init_G1(_encsk->K[index].a0, _pairing);
	element_init_G1(_encsk->K[index].a1, _pairing);

	// a[0] = g^(v+w) * (h[0] * h[l])^r
	_encsk->K[index].bLength = 0;
	element_random(r);
	element_mul(temp, _vk->h[0], _vk->h[index]);	// temp = h[0] * h[l]
	element_pow_zn(temp1, temp, r);					// temp1 = (h[0] * h[l])^r
	element_mul(_encsk->K[index].a0, gv, temp1);		// a0 = g^(v+w) * (h[0] * h[i])^r
#ifdef DEBUG
printf("a0 = g^(v) * (h[0] * h[%d])^r\n", index);
#endif

	// a[1]	= g^r
	element_pow_zn(_encsk->K[index].a1, _vk->g, r);
#ifdef DEBUG
printf("a1 = a1^r\n");
#endif


	/*
	 *  =============
	 * |generate deck|
	 *  ==============
	 */
/*	element_init_G1(_deck->key, _pairing);

	// deck = g^(-w)
	element_pow_zn(temp, _vk->g, w);
	element_invert(_deck->key, temp);
*/	

	element_clear(r);
	element_clear(v);
	//element_clear(w);
	//element_clear(vw);
	//element_clear(gvw);
	element_clear(temp);
	element_clear(temp1);


	endTime = clock();
	printf("complete\n");
	printf("Elapsed time: %g\n\n", ELAPSEDTIME(startTime, endTime));
    keygenTime += ELAPSEDTIME(startTime, endTime);
}

void checkKey(encsk_t _encsk, vk_t _vk, pairing_t _pairing)
{
	int i, j, index;

	element_t mul, temp;						// G1
	element_t VW, temp1, temp2, temp3, temp4;	// GT

	timePeriod_t k;


	printf("\n## check key...");
//	startTime = clock();


	/*
	 *  =========
	 * |check key|
	 *  =========
	 */
	element_init_G1(mul, _pairing);
	element_init_G1(temp, _pairing);

	//element_init_GT(VW, _pairing);
	element_init_GT(temp1, _pairing);
	element_init_GT(temp2, _pairing);
	element_init_GT(temp3, _pairing);
	element_init_GT(temp4, _pairing);

	// V * W * e(a0, g^(-1)) * e(a1, h[0] * TT h[i]^bit(i,k[j]))
	// V * W
#ifdef DEBUG
printf("\n");
#endif
	//element_mul(VW, _vk->V, _vk->W);
	for(i=1; i<=_encsk->ID->bit+1; i++)
	{
		index = i-1;
		sibling(k, _encsk->ID, i);	
#ifdef DEBUG
printf("==== %d ====\n", index);
print_timePeriod(k);
#endif
		if(-1 == k->bit)
		{
			if(-1 != _encsk->K[index].bLength)
			{
#ifdef DEBUG
printf("%d\n", _encsk->K[index].bLength);
#endif
				printf("invalid key1\n");
				exit(0);
			}
			continue;
		}

		// temp1 = e(a0, g^(-1)
		element_invert(temp, _vk->g);
		pairing_apply(temp1, _encsk->K[index].a0, temp, _pairing);
#ifdef DEBUG
printf("e(a0, g^(-1)) ");
#endif

		// temp2 = e(a1, h[0] * TT h[i]^bit(i,k[j]))
		element_set(temp, _vk->h[0]);
#ifdef DEBUG
printf("* e(a1, h[0] ");
#endif
		for(j=0; j<k->bit; j++)
		{
			if(0 == CHECK_BIT(k->data, j, kBase))
			{
				continue;
			}
			element_set(mul, temp);
			element_mul(temp, mul, _vk->h[j+1]);
#ifdef DEBUG
printf("* h[%d]", j+1);
#endif
		}
		pairing_apply(temp2, _encsk->K[index].a1, temp, _pairing);
#ifdef DEBUG
printf(") ");
#endif

		// check key.
		element_mul(temp3, _vk->V, temp1);		// V * W * e(a0, g^(-1))
		element_mul(temp4, temp3, temp2);	// V * W * e(a0, g^(-1)) * e(a1, h[0] * TT h[i]^bit(i,k[j]))
#ifdef DEBUG
printf("* V * W\n");
#endif

		if(0 == element_is1(temp4))
		{
			printf("\ninvalid key2\n\n");
			exit(0);
		}

		free(k->data);
	}

	element_clear(temp4);
	element_clear(temp3);
	element_clear(temp2);
	element_clear(temp1);
	element_clear(temp);
	element_clear(mul);
	//element_clear(VW);


//	endTime = clock();
	printf("complete\n");
//	printf("Elapsed time: %g\n\n", ELAPSEDTIME(startTime, endTime));
}

void update(encsk_t _encsk, timePeriod_t _next, vk_t _vk, pairing_t _pairing)
{
	int i, j, index, suffixIndex, length;
	struct k_s suffix;

	element_t r;					// Zr
	element_t temp, temp1, mul;		// G1

	timePeriod_t k, a, b;
	timePeriod_t next;


	printf("\n## update...");
	startTime = clock();

	/*
	 *  ==========
	 * |check next|
	 *  ==========
	 */
	// next's bit == l
	if(_next->bit != _encsk->ID->bit)
	{
		printf("invalid id to update1\n");
		exit(0);
	}

	// id < next
	if(1 != compare_timePeriod(_encsk->ID, _next))
	{
		printf("invalid id to update2");
		exit(0);
	}

	
	/*
	 *  ======
	 * |update|
	 *  ======
	 */
	element_init_Zr(r, _pairing);

	element_init_G1(mul, _pairing);
	element_init_G1(temp, _pairing);
	element_init_G1(temp1, _pairing);
	element_init_G1(suffix.a0, _pairing);
	element_init_G1(suffix.a1, _pairing);

#ifdef DEBUG
printf("current\n");
print_timePeriod(_encsk->ID);
printf("next\n");
print_timePeriod(_next);
#endif
	// find suffix string s
	for(i=1; i<=_encsk->ID->bit; i++)
	{
		index = i-1;
#ifdef DEBUG
printf("%d, ", index);
#endif
		if(0 == CHECK_BIT(_encsk->ID->data, index, kBase))
		{
			if(0 != CHECK_BIT(_next->data, index, kBase))
			{
				break;
			}
		}
	}
#ifdef DEBUG
printf("\nsave index: %d\n", index);
#endif

	// copy suffix.
	suffixIndex = index;
	element_set(suffix.a0, _encsk->K[suffixIndex].a0);
	element_set(suffix.a1, _encsk->K[suffixIndex].a1);
	suffix.bLength = _encsk->K[suffixIndex].bLength;
	suffix.b = (element_t *) malloc (suffix.bLength * sizeof(element_t));
	for(j=0; j<suffix.bLength; j++)
	{
		element_init_G1(suffix.b[j], _pairing);
		element_set(suffix.b[j], _encsk->K[suffixIndex].b[j]);
	}

	// K[j] = (a0 * b[j+1]^bit(j+1,k'[j]) ... * b[j']^bit(j',k'[j]) * (h[0] * TT h[i]^bit(i,k'[i]))^r, a1 * g^r, b[j'+1] * h[j'+1]^r, ..., b[l] * h[l]^r)
	for( ; i<=_encsk->ID->bit+1; i++)
	{
		index = i-1;
#ifdef DEBUG
printf("==== %d ====\n", index);
#endif
		sibling(k, _next, i);
		
		// rewrite K about sibling.
		if(-1 == k->bit)		// if k = NULL
		{
			if(-1 == _encsk->K[index].bLength)		// if K == NULL
			{
				continue;
			}

			element_clear(_encsk->K[index].a0);
			element_clear(_encsk->K[index].a1);
			if(0 < _encsk->K[index].bLength)
			{
				for(j=0; j<_encsk->K[index].bLength; j++)
				{
					element_clear(_encsk->K[index].b[j]);
				}
			}
			_encsk->K[index].bLength = -1;
			continue;
		}

		// if sibling exist && original NULL, alloc
		if(-1 == _encsk->K[index].bLength)
		{
			_encsk->K[index].bLength = _encsk->kLength - 1 - k->bit;
			element_init_G1(_encsk->K[index].a0, _pairing);
			element_init_G1(_encsk->K[index].a1, _pairing);
			if(0 != _encsk->K[index].bLength)
			{
				_encsk->K[index].b = (element_t *) malloc (_encsk->K[index].bLength * sizeof(element_t));
			}
		}

		// a0 = a0 * b[j+1]^bit(j+1,k'[j]) * (h[0] * TT h[i]^bit(i,k'[i]))^r
		// temp = a0 * b[j+1]^bit(j+1,k'[j]) * ... * b[j']^bit(j',k'[j])
#ifdef DEBUG
print_timePeriod(k);
printf("a0 = a0");
#endif
		element_set(temp, suffix.a0);
		for(j=suffixIndex+1; j<k->bit; j++)
		{
			if(0 == CHECK_BIT(k->data, j, kBase))
			{
				continue;
			}
			element_set(mul, temp);
			element_mul(temp, mul, suffix.b[j-suffixIndex-1]);
#ifdef DEBUG
printf(" * b[%d]", j-suffixIndex-1);
#endif
		}

		// temp1 = (h[0] * TT h[i]^bit(i,k'[i]))^r
		element_random(r);
		element_set(mul, _vk->h[0]);
#ifdef DEBUG
printf(" * (h[0]");
#endif
		for(j=0; j<k->bit; j++)
		{
			if(0 == CHECK_BIT(k->data, j, kBase))
			{
				continue;
			}
			element_set(temp1, mul);
			element_mul(mul, temp1, _vk->h[j+1]);
#ifdef DEBUG
printf(" * h[%d]", j+1);
#endif
		}
		element_pow_zn(temp1, mul, r);
#ifdef DEBUG
printf(") ^ r\n");
#endif

		// a0 = temp * temp1
		element_mul(_encsk->K[index].a0, temp, temp1);


		// a1 = a1 * g^r
		element_pow_zn(temp, _vk->g, r);
		element_mul(_encsk->K[index].a1, suffix.a1, temp);
#ifdef DEBUG
printf("a1 = a1 * g^r\n");
#endif


		// b[i] = b[i] * h[j]^r
		for(j=0; j<_encsk->K[index].bLength; j++)
		{
#ifdef DEBUG
printf("b[%d] = ", j);
#endif
			element_pow_zn(temp, _vk->h[j+k->bit+1], r);
#ifdef DEBUG
printf("h[%d]^r ", j+k->bit+1);
#endif
			element_mul(_encsk->K[index].b[j], suffix.b[j], temp);
#ifdef DEBUG
printf("* b[%d]\n", j);
#endif
//			element_init_G1(_encsk->K[index].b[j], _pairing);
//			element_pow_zn(temp, , r);
//			element_mul(_encsk->K[index].b[j], suffix.a1, 
		}
		
		free(k->data);
	}

	// update ID.
	length = (_next->bit/kBase) + ( (_next->bit % kBase > 0) ? (1) : (0) );
	for(i=0; i<length; i++)
	{
		_encsk->ID->data[i] = _next->data[i];
	}
#ifdef DEBUG
printf("update ID: ");
print_timePeriod(_encsk->ID);
#endif


	for(i=0; i<suffix.bLength; i++)
	{
		element_clear(suffix.b[i]);
	}
	element_clear(suffix.a0);
	element_clear(suffix.a1);
	element_clear(temp1);
	element_clear(temp);
	element_clear(mul);
	element_clear(r);


	endTime = clock();
	printf("complete\n");
	printf("Elapsed time: %g\n\n", ELAPSEDTIME(startTime, endTime));
    updateTime += ELAPSEDTIME(startTime, endTime);
}

void sign(sigma_t _sigma, message_t _msg, encsk_t _encsk, vk_t _vk, pairing_t _pairing)
{
	int i, index, length;

		index = i-1;
	uchar_t hash[SHA_DIGEST_LENGTH];


	element_t r, s;								// Zr
	element_t mul, temp, temp1, temp2, temp3;	// G1
	element_t VW, check1, check2, check3;		// GT


	printf("\n## sign...");
	startTime = clock();


	/*
	 *  =========
	 * |check key|
	 *  =========
	 */
	// check key 1
	index = _encsk->kLength-1;
	if(-1 == _encsk->K[index].bLength)
	{
		printf("invalid key1\n");
		exit(0);
	}

	element_init_Zr(r, _pairing);
	element_init_Zr(s, _pairing);

	element_init_G1(mul, _pairing);
	element_init_G1(temp, _pairing);
	element_init_G1(temp1, _pairing);
	element_init_G1(temp2, _pairing);
	element_init_G1(temp3, _pairing);

	element_init_GT(VW, _pairing);
	element_init_GT(check1, _pairing);
	element_init_GT(check2, _pairing);
	element_init_GT(check3, _pairing);

	// check key 2
	// 1 == V * W * e(a0,g^(-1)) * e(a1, h[0] * TT h[i]^bit(i,ID))^r
	// VW = V * W
	
	/*element_mul(VW, _vk->V, _vk->W);
	*/
#ifdef DEBUG
printf("V");
#endif

	// check1 = e(a0,g^(-1))
	element_invert(temp, _vk->g);
	pairing_apply(check1, _encsk->K[index].a0, temp, _pairing);
#ifdef DEBUG
printf(" * e(a0, g^(-1))");
#endif

	// check2 = e(a1, h[0] * TT h[i]^bit(i,ID))^r
	element_set(temp, _vk->h[0]);
#ifdef DEBUG
printf(" * e(h[0]");
#endif
	for(i=0; i<_encsk->ID->bit; i++)
	{
		if(0 == CHECK_BIT(_encsk->ID->data, i, kBase))
		{
			continue;
		}
		element_set(mul, temp);
		element_mul(temp, mul, _vk->h[i+1]);
#ifdef DEBUG
printf(" * h[%d]", i+1);
#endif
	}
	pairing_apply(check2, _encsk->K[index].a1, temp, _pairing);
#ifdef DEBUG
printf(", a1)\n");
#endif

	// check3 = V * W * e(a0,g&(-1))
	element_mul(check3, _vk->V, check1);
	element_mul(check1, check2, check3);
	if(0 == element_is1(check1))
	{
		printf("invalid key2\n");
		exit(0);
	}


	/*
	 *  ====
	 * |sign|
	 *  ====
	 */
	// copy ID   
	create_timePeriod(_sigma->ID, _encsk->ID->bit);
	length = (_sigma->ID->bit/kBase) + ( (_sigma->ID->bit % kBase > 0) ? (1) : (0) );
	for(i=0; i<length; i++)
	{
		_sigma->ID->data[i] = _encsk->ID->data[i];
	}
#ifdef DEBUG
printf("ID: ");
print_timePeriod(_sigma->ID);
#endif

	// message to hash
#ifdef DEBUG
printf("hasing...\n");
#endif
	SHA1(_msg->data, _msg->length, hash);

	element_init_G1(_sigma->s0, _pairing);
	element_init_G1(_sigma->s1, _pairing);
	element_init_G1(_sigma->s2, _pairing);

	// s0 = DecK * a0 * (h[0] * TT h[i]^bit(i,ID))^r * (f[0] * TT f[j]^bit(j,M))^s
	element_random(r);
	element_random(s);

	// temp1 = Deck * a0
	element_set(temp1, _encsk->K[index].a0);
#ifdef DEBUG
printf("s0 = DecK * a1 ");
#endif

	// temp2 = (h[0] * TT h[i]^bit(i,ID))^r
	element_set(temp, _vk->h[0]);
#ifdef DEBUG
printf("* (h[0] ");
#endif
	for(i=0; i<_sigma->ID->bit; i++)
	{
		if(0 == CHECK_BIT(_sigma->ID->data, i, kBase))
		{
			continue;
		}
		element_set(mul, temp);
		element_mul(temp, mul, _vk->h[i+1]);
#ifdef DEBUG
printf("* h[%d] ", i+1);
#endif
	}
	element_pow_zn(temp2, temp, r);
#ifdef DEBUG
printf(")^r ");
#endif

	// temp3 = (f[0] * TT f[j]^bit(j,M))^s
	element_set(temp, _vk->f[0]);
#ifdef DEBUG
printf("* (f[0] ");
#endif
	for(i=0; i<SHA_DIGEST_LENGTH*kBase; i++)
	{
		if(0 == CHECK_BIT(hash, i, kBase))
		{
			continue;
		}
		element_set(mul, temp);
		element_mul(temp, mul, _vk->f[i+1]);
#ifdef DEBUG
printf("* f[%d] ", i+1);
#endif
	}
	element_pow_zn(temp3, temp, s);
#ifdef DEBUG
printf(")^s\n");
#endif

	// s0 = temp1 * temp2 * temp3
	element_mul(temp, temp1, temp2);
	element_mul(_sigma->s0, temp, temp3);

	// s1 = a1 * g^r
	element_pow_zn(temp, _vk->g, r);
	element_mul(_sigma->s1, _encsk->K[index].a1, temp);
#ifdef DEBUG
printf("s1= a1 * g^r\n");
#endif

	// s2 = g^s	
	element_pow_zn(_sigma->s2, _vk->g, s);
#ifdef DEBUG
printf("s2= g^s\n");
#endif


	element_clear(check3);
	element_clear(check2);
	element_clear(check1);
	element_clear(temp3);
	element_clear(temp2);
	element_clear(temp1);
	element_clear(temp);
	element_clear(mul);
	//element_clear(VW);
	element_clear(s);
	element_clear(r);


	endTime = clock();
	printf("complete\n");
	printf("Elapsed time: %g\n\n", ELAPSEDTIME(startTime, endTime));
	signTime += ELAPSEDTIME(startTime, endTime);
}

int verify(sigma_t _sigma, message_t _msg, vk_t _vk, pairing_t _pairing)
{
	int i, isVerify;

	uchar_t hash[SHA_DIGEST_LENGTH];

	element_t mul, temp;							// G1
	element_t temp1, temp2, temp3, temp4, temp5;	// GT


	printf("\n## verify...");
	startTime = clock();


	/*
	 *  =========
	 * |verify|
	 *  =========
	 */
	element_init_G1(mul, _pairing);
	element_init_G1(temp, _pairing);

	element_init_GT(temp1, _pairing);
	element_init_GT(temp2, _pairing);
	element_init_GT(temp3, _pairing);
	element_init_GT(temp4, _pairing);
	element_init_GT(temp5, _pairing);

	// message to hash
#ifdef DEBUG
printf("hasing...\n");
#endif
	SHA1(_msg->data, _msg->length, hash);

	// 1 == V * e(s0,g^(-1)) * e(s1,h[0] * TT h[i]^bit(i,ID)) * e(s2,f[0] * TT f[i]^bit(M))
	// temp1 = e(s0,g(-1))
	element_invert(temp, _vk->g);
	pairing_apply(temp1, _sigma->s0, temp, _pairing);
#ifdef DEBUG
printf("e(s0, g^(-1)) ");
#endif

	// temp2 = e(s1,h[0] * TT h[i]^bit(i,ID))
#ifdef DEBUG
printf("* e(h[0] ");
#endif
	element_set(temp, _vk->h[0]);
	for(i=0; i<_sigma->ID->bit; i++)
	{
		if(0 == CHECK_BIT(_sigma->ID->data, i, kBase))
		{
			continue;
		}
		element_set(mul, temp);
		element_mul(temp, mul, _vk->h[i+1]);
#ifdef DEBUG
printf("* h[%d] ", i+1);
#endif
	}
	pairing_apply(temp2, _sigma->s1, temp, _pairing);
#ifdef DEBUG
printf(", s1) ");
#endif

	// temp3 = e(s2,f[0] * TT f[j]^bit(j,M))
#ifdef DEBUG
printf("* e(f[0] ");
#endif
	element_set(temp, _vk->f[0]);
	for(i=0; i<SHA_DIGEST_LENGTH*kBase; i++)
	{
		if(0 == CHECK_BIT(hash, i, kBase))
		{
			continue;
		}
		element_set(mul, temp);
		element_mul(temp, mul, _vk->f[i+1]);
#ifdef DEBUG
printf("* f[%d] ", i+1);
#endif
	}
	pairing_apply(temp3, _sigma->s2, temp, _pairing);
#ifdef DEBUG
printf(", s2) * V\n");
#endif

	// 1 == V * temp1 * temp2 * temp3
	element_mul(temp4, _vk->V, temp1);
	element_mul(temp5, temp4, temp2);
	element_mul(temp4, temp5, temp3);
	isVerify =  element_is1(temp4);


	element_clear(temp5);
	element_clear(temp4);
	element_clear(temp3);
	element_clear(temp2);
	element_clear(temp1);
	element_clear(temp);
	element_clear(mul);

	endTime = clock();
	printf("complete\n");
	printf("Elapsed time: %g\n\n", ELAPSEDTIME(startTime, endTime));
	verifyTime += ELAPSEDTIME(startTime, endTime);

	return isVerify;
}

void memory_clean(vk_t _vk, encsk_t _encsk, sigma_t _sigma, pairing_t _pairing)
{
	int i, j;

	//pairing
	pairing_clear(_pairing);
	
	// vk
	element_clear(_vk->g);
	element_clear(_vk->V);
	//element_clear(_vk->W);
	for(i=0; i<_vk->hLength; i++)
	{
		element_clear(_vk->h[i]);
	}
	free(_vk->h);
	for(i=0; i<_vk->fLength; i++)
	{
		element_clear(_vk->f[i]);
	}
	free(_vk->f);

	// encsk
	clear_timePeriod(_encsk->ID);
	for(i=0; i<_encsk->kLength; i++)
	{
		for(j=0; j<_encsk->K[i].bLength; j++)
		{
			element_clear(_encsk->K[i].b[j]);
		}

		if(_encsk->K[i].bLength < 0)
		{
			continue;
		}

		element_clear(_encsk->K[i].a0);
		element_clear(_encsk->K[i].a1);
	}
	free(_encsk->K);

	// deck
	//element_clear(_deck->key);

	// sigma
	clear_timePeriod(_sigma->ID);
	element_clear(_sigma->s0);
	element_clear(_sigma->s1);
	element_clear(_sigma->s2);
}

void nextTimePeriod(timePeriod_t _next, timePeriod_t _current)
{
	int i, carry, length;

	// ID = 0...10
	length = (_current->bit/kBase) + ( (_current->bit % kBase > 0) ? (1) : (0) );
	for(i=0; i<length; i++)
	{
		_next->data[i] = _current->data[i];
	}

	carry = 0;
	for(i=_next->bit-1; i>=0; i--)
	{
		if(0 == CHECK_BIT(_next->data, i, kBase))
		{
			SET_BIT(_next->data, i, kBase);
			break;
		}
		else
		{
			if(0 == carry)
			{
				CLEAR_BIT(_next->data, i, kBase);
			}
			else
			{
				SET_BIT(_next->data, i, kBase);
			}
			carry = 1;
		}
	}
//	i = _next->bit - 2;
//	SET_BIT(_next->data, i, kBase);
//	i = _next->bit - 4;
//	SET_BIT(_next->data, i, kBase);
//	i = _next->bit - 5;
//	SET_BIT(_next->data, i, kBase);
//	i = _next->bit - 8;
//	SET_BIT(_next->data, i, kBase);
//	i = _next->bit - 11;
//	SET_BIT(_next->data, i, kBase);
#ifdef DEBUG
printf("\n========\n");
printf("current: ");
print_timePeriod(_current);
printf("next: ");
print_timePeriod(_next);
printf("========\n");
#endif
}
