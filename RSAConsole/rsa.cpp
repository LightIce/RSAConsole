#ifndef _RSA_H
#define _RSA_H
#include "rsa.h"
#endif
static void RSA_InitContext(RSA_PCONTEXT rsa_pcontext)
{
	rsa_pcontext->uKeySize = 4096;
	rsa_pcontext->p = mirvar(0);
	rsa_pcontext->q = mirvar(0);

	rsa_pcontext->e = mirvar(19);
	rsa_pcontext->n = mirvar(0);
	rsa_pcontext->d = mirvar(0);
}

static void RSA_SetKeyLength(RSA_PCONTEXT rsa_pcontext, UINT uKeyLen = MAXBIGSIZE)
{
#ifdef _DEBUG
	printf("[DEBUG] uKeyLen = %u\n", uKeyLen);
#endif
	if (uKeyLen > MAXBIGSIZE )
	{
		printf("[Error] The key length is toooo long!\n");
		exit(0);
	}
	else if (uKeyLen < 32)
	{
		printf("[Error] The key length is toooo short! Maybe it is not safe enough!\n");
		exit(0);
	}
	if (uKeyLen < 1024)
	{
		printf("[Warning] Maybe the length is not safe!\n");
	}
	rsa_pcontext->uKeySize = uKeyLen;
}

static void RSA_GenerateBigPrime(RSA_PCONTEXT rsa_pcontext)
{
	// init the random key
	irand(time((time_t)(NULL)));

	//set p and q
	printf("[INFO] Finding the big prime for p...\n");
	while (true)
	{
		bigbits(rsa_pcontext->uKeySize, rsa_pcontext->p);
		if (isprime(rsa_pcontext->p))
		{
			printf("[INFO] Find p:");
			cotnum(rsa_pcontext->p, stdout);
			printf("\n");
			break;
		}
		else
		{
			bigbits(rsa_pcontext->uKeySize, rsa_pcontext->p);
		}
	}
	printf("[INFO] Done. Now find q...\n");
	while (true)
	{
		bigbits(rsa_pcontext->uKeySize, rsa_pcontext->q);
		if (isprime(rsa_pcontext->q))
		{
			printf("[INFO] Find q:");
			cotnum(rsa_pcontext->q, stdout);
			printf("\n");
			break;
		}
		else
		{
			bigbits(rsa_pcontext->uKeySize, rsa_pcontext->q);
		}
	}

	printf("Generate done. Good Luck!\n");
}

static void RSA_GenerateN(RSA_PCONTEXT rsa_pcontext)
{
	multiply(rsa_pcontext->p, rsa_pcontext->q, rsa_pcontext->n);
	printf("[INFO] n = p * q = ");
	cotnum(rsa_pcontext->n, stdout);
	printf("\n");
}

static void RSA_GenerateD(RSA_PCONTEXT rsa_pcontext)
{
	// f(n) = (p-1) * (q-1)
	big fain = mirvar(0);
	big tempP = mirvar(1);
	big tempQ = mirvar(1);

	subtract(rsa_pcontext->p, tempP, tempP);	//tempP = p - 1
	subtract(rsa_pcontext->q, tempQ, tempQ);	//tempQ = q - 1
	multiply(tempP, tempQ, fain);

#ifdef _DEBUG
	printf("[DEBUG] p-1 = ");
	cotnum(tempP, stdout);
	printf("\n");

	printf("[DEBUG] q-1 = ");
	cotnum(tempQ, stdout);
	printf("\n");

	printf("[DEBUG] f(n) = ");
	cotnum(fain, stdout);
	printf("\n");
#endif

	big TempBigD = mirvar(0), TempBigZ = mirvar(0);

	multi_inverse(1, &rsa_pcontext->e, fain, &rsa_pcontext->d);

	printf("[INFO] e = ");
	cotnum(rsa_pcontext->e, stdout);
	printf("\n");

	printf("[INFO] d = ");
	cotnum(rsa_pcontext->d, stdout);
	printf("\n");

	mirkill(fain);
	mirkill(tempP);
	mirkill(tempQ);
	mirkill(TempBigD);
	mirkill(TempBigZ);
}

static void RSA_GenerateE(RSA_PCONTEXT rsa_pcontext)
{
	// f(n) = (p-1) * (q-1)
	big fain = mirvar(0);
	big tempP = mirvar(1);
	big tempQ = mirvar(1);

	subtract(rsa_pcontext->p, tempP, tempP);	//tempP = p - 1
	subtract(rsa_pcontext->q, tempQ, tempQ);	//tempQ = q - 1
	multiply(tempP, tempQ, fain);

	// TempZ = gcd(e, TempBig);
	big TempBigZ = mirvar(0), TempBigStd = mirvar(1);
	egcd(rsa_pcontext->e, fain, TempBigZ);

	

	return ;
}

static void RSA_Encrypto(RSA_PCONTEXT rsa_pcontext)
{
	FILE *fileMessage;
	fileMessage = fopen("msg.txt", "r");
	if (fileMessage == NULL)
	{
		printf("No msg.txt found!\n");
		exit(0);
	}

	FILE *fileEncMessage;
	fileEncMessage = fopen("enc.txt", "w");

	char messageBuf[4096];
	ZeroMemory(messageBuf, 4096);

	while ((fgets(messageBuf, 4096, fileMessage)) != NULL)
	{
		//printf("%s", messageBuf);
		int len = strlen(messageBuf);
		big tempX = mirvar(0);
		bytes_to_big(len, messageBuf, tempX);
#ifdef _DEBUG
		printf("[DEBUG] msg %s -> ", messageBuf);
		cotnum(tempX, stdout);
		printf("\n");
#endif

		big enc = mirvar(0);
		powmod(tempX, rsa_pcontext->e, rsa_pcontext->n, enc);
#ifdef _DEBUG
		printf("[DEBUG] %s -> ", messageBuf);
		cotnum(enc, stdout);
		printf("\n");
#endif
		cotnum(enc, fileEncMessage);
		enc = mirvar(0);
		mirkill(tempX);
	}
	
	fclose(fileMessage);
	fclose(fileEncMessage);
	
}

static void RSA_Decrypto(RSA_PCONTEXT rsa_pcontext)
{
	FILE *fileEncMessage;
	fileEncMessage = fopen("enc.txt", "r");
	if (fileEncMessage == NULL)
	{
		printf("[Error] enc.txt not found!");
		exit(0);
	}

	FILE *fileCheckMessage;
	fileCheckMessage = fopen("check.txt", "w");

	char encMessageBuf[4096];
	ZeroMemory(encMessageBuf, 4096);
	char messageBuf[4096];
	ZeroMemory(messageBuf, 4096);

	while ((fgets(encMessageBuf, 4096, fileEncMessage)) != NULL)
	{
		big temp = mirvar(0);
		cinstr(temp, encMessageBuf);

		big check = mirvar(0);
		powmod(temp, rsa_pcontext->d, rsa_pcontext->n, check);
		big_to_bytes(4096, check, messageBuf, FALSE);
#ifdef _DEBUG
		printf("========================\n");
		cotnum(temp, stdout);
		printf(" -> ");		
		puts(messageBuf);
#endif
		fputs(messageBuf, fileCheckMessage);
		mirkill(check);
		mirkill(temp);
		ZeroMemory(messageBuf, 4096);
		ZeroMemory(encMessageBuf, 4096);
	}


	fclose(fileEncMessage);
	fclose(fileCheckMessage);
}