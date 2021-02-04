#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pbc.h>
#include <openssl/sha.h>
#include <time.h>
//using namespace std;
#define ELAPSEDTIME(x, y) ((float)(y-x)/CLOCKS_PER_SEC)
#define SET_BIT(data, index, base) ( (*(data+(index/base))) |= (1 << index%base) )
#define CLEAR_BIT(data, index, base) ( (*(data+(index/base))) &= ~(1 << index%base) )
#define CHECK_BIT(data, index, base) ( (*(data+(index/base))) & (1 << index%base) )
#pragma pack(1)
//time_t startTime;
//time_t endTime;
extern const int kBase;
extern const int kL;
extern const int kM;

extern double keygenTime;
extern double updateTime;
extern double signTime;
extern double verifyTime;

typedef unsigned char uchar_t;

typedef struct timePeriod_s
{       
        int bit;
        uchar_t *data;
} timePeriod_t[1];

typedef struct message_s
{       
        int length;
	//uchar_t length;
        uchar_t *data;
	//string *data;
} message_t[1];

struct vk_s
{
        int hLength;
        int fLength;
        element_t g;
        element_t V; //W;
        element_t *h;
        element_t *f;
};

struct k_s
{
        int bLength;
        element_t a0;
        element_t a1;
        element_t *b;
};

struct encsk_s
{
        int kLength;
        timePeriod_t ID;
        struct k_s *K;
};

/*struct deck_s
{
        element_t key;
};
*/
struct sigma_s
{
        timePeriod_t ID;
        element_t s0;
        element_t s1;
        element_t s2;
};

typedef struct vk_s vk_t[1];
typedef struct encsk_s encsk_t[1];
//typedef struct deck_s deck_t[1];
typedef struct sigma_s sigma_t[1];

void testvalue();

void create_timePeriod(timePeriod_t _id,int _bit);
int compare_timePeriod(timePeriod_t _a, timePeriod_t _b);
void print_timePeriod(timePeriod_t _id);
void clear_timePeriod(timePeriod_t _id);
void sibling(timePeriod_t _k, timePeriod_t _id,int _bit);
void setup(pairing_t _pairing);
void keyGen(int _l, int _m, vk_t _vk,encsk_t _encsk, pairing_t _pairing);
void checkKey(encsk_t _encsk, vk_t _vk, pairing_t _pairing);
void update(encsk_t _encsk, timePeriod_t _next, vk_t _vk, pairing_t _pairing);
void sign(sigma_t _sigma, message_t _msg,encsk_t _encsk ,vk_t _vk, pairing_t _pairing_);
int verify(sigma_t _sigma, message_t _msg, vk_t _vk, pairing_t _pairing);//,int *isVerify);
void signcall(uchar_t *paramsg,sigma_t sigma,int call,int *isVerify,int genesis);
//void verifycall(uchar_t *paramsg,sima_t sigma);
void nextTimePeriod(timePeriod_t _next, timePeriod_t _current);
