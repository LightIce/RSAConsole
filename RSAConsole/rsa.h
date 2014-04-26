#include <stdio.h>
#include <windows.h>
#include <time.h>

extern "C"
{
#include "miracl.h"
#include "mirdef.h"
};

#define MAXBIGSIZE 4096

typedef struct 
{
	UINT uKeySize;	//��Կ��С
	big p, q;		//������p��q
	big n;			//n = p *����
	big e;			//��Կ
	big d;			//˽Կ
}_RSA_CONTEXT;
typedef _RSA_CONTEXT  RSA_CONTEXT;
typedef _RSA_CONTEXT* RSA_PCONTEXT;

//initialize the RSA data
static void RSA_InitContext(RSA_PCONTEXT rsa_pcontext);

// set rsa key length
static void RSA_SetKeyLength(RSA_PCONTEXT rsa_pcontext, UINT uKeyLen);

//make big prime number and set it to rsa_context
static void RSA_GenerateBigPrime(RSA_CONTEXT rsa_pcontext);

// Generate Publickey n
static void RSA_GenerateN(RSA_PCONTEXT rsa_pcontext);

// Generate D
static void RSA_GenerateD(RSA_PCONTEXT rsa_pcontext);

// Generate E
static void RSA_GenerateE(RSA_PCONTEXT rsa_pcontext);

static void RSA_Encrypto(RSA_PCONTEXT rsa_pcontext);

static void RSA_Decrypto(RSA_PCONTEXT rsa_pcontext);

