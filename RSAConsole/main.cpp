#ifndef _RSA_H
#define _RSA_H
#include "rsa.h"
#endif
#include "rsa.cpp"

FILE *fileLog;


int main(_In_ int _Argc, _In_reads_(_Argc) _Pre_z_ char ** _Argv, _In_z_ char ** _Env)
{
	printf("===============================================================================\n");
	printf("| Please put your message in the msg.txt.\n");
	printf("| And we will generate a log file which named log.txt\n");
	printf("| The encryption message is in the enc.txt.\n");
	printf("| If we finished the encryption, we will decrypt the enc.txt\n");
	printf("| And put the decryption int the check.txt.\n");
	printf("| if you found the msg.txt is not the same with the check.txt.\n");
	printf("| You should encrypt the message again \n");
	printf("|until the msg.txt is same to the check.txt\n");
	printf("================================================================================\n");

	fileLog = fopen("log.txt", "w");

	static miracl *mip = mirsys(MAXBIGSIZE, 0);
	mip->IOBASE = 16;

	// init rsa 
	RSA_PCONTEXT rsaContext = new RSA_CONTEXT;
	RSA_InitContext(rsaContext);
	printf("[INFO] RSA_InitContext success!\n");
	fprintf(fileLog, "[INFO] RSA_InitContext success!\n");
#ifdef _DEBUG
	printf("[DEBUG] e = ");
	fprintf(fileLog, "[DEBUG] e = ");
	cotnum(rsaContext->e, stdout);
	cotnum(rsaContext->e, fileLog);
	printf("\n");
	fprintf(fileLog, "\n");
#endif

	// select key length
	int keyLen = 0;
#ifdef _DEBUG
	printf("[DEBUG] If you want to test the function, 512 is the best choice.\n");
#endif

	fprintf(fileLog, "[DEBUG] If you want to test the function, 512 is the best choice.\n");
	printf("Please input the key length (Max:4096 RECOMMAND FOR 2048):");

	scanf("%d", &keyLen);
	RSA_SetKeyLength(rsaContext, keyLen);
	printf("[INFO] Key length is set! Length is: %d\n", keyLen);
	fprintf(fileLog, "[INFO] Key length is set! Length is: %d\n", keyLen);

	// Generate big prime number
	RSA_GenerateBigPrime(rsaContext);

	// Generate N
	RSA_GenerateN(rsaContext);

	// Generate E
	getchar();		// Get the last enter \n
	printf("Please input a public key E(RECOMMAND FOR 11/13/17..etc): ");
	fprintf(fileLog, "Please input a public key E(RECOMMAND FOR 11/13/17..etc): ");
	big E = mirvar(0);
	cinnum(E, stdin);
	rsaContext->e = E;

	// Generate D
	RSA_GenerateD(rsaContext);

#ifdef _DEBUG
	printf("[DEBUG] Show all the var in RSA_CONTEXT\n");
	printf("[DEBUG] RSA_CONTEXT->p: ");
	cotnum(rsaContext->p,stdout);
	printf("\n[DEBUG] RSA_CONTEXT->q: ");
	cotnum(rsaContext->q, stdout);
	printf("\n[DEBUG] RSA_CONTEXT->d: ");
	cotnum(rsaContext->d, stdout);
	printf("\n[DEBUG] RSA_CONTEXT->e: ");
	cotnum(rsaContext->e, stdout);
	printf("\n[DEBUG] RSA_CONTEXT->n: ");
	cotnum(rsaContext->n, stdout);
	printf("\n");
#endif
	fprintf(fileLog, "[DEBUG] Show all the var in RSA_CONTEXT\n");
	fprintf(fileLog, "[DEBUG] RSA_CONTEXT->p: ");
	cotnum(rsaContext->p,fileLog);
	fprintf(fileLog, "\n[DEBUG] RSA_CONTEXT->q: ");
	cotnum(rsaContext->q, fileLog);
	fprintf(fileLog, "\n[DEBUG] RSA_CONTEXT->d: ");
	cotnum(rsaContext->d, fileLog);
	fprintf(fileLog, "\n[DEBUG] RSA_CONTEXT->e: ");
	cotnum(rsaContext->e, fileLog);
	fprintf(fileLog, "\n[DEBUG] RSA_CONTEXT->n: ");
	cotnum(rsaContext->n, fileLog);
	fprintf(fileLog, "\n");

	//Encryption
	RSA_Encrypto(rsaContext);

	//Decryption
	RSA_Decrypto(rsaContext);

	printf("[INFO] Now write some information to the key.txt\n");
	fprintf(fileLog, "[INFO] Now write some information to the key.txt\n");
	FILE *fileKey;
	fileKey = fopen("key.txt", "w");

	fprintf(fileKey, "public key:\n");
	fprintf(fileKey, "{e, n} = \n");
	fprintf(fileKey, "{");
	cotnum(rsaContext->e, fileKey);
	fprintf(fileKey, ",");
	cotnum(rsaContext->n, fileKey);
	fprintf(fileKey,"}\n\n\n");

	fprintf(fileKey, "private key:\n");
	fprintf(fileKey, "{d, n} = \n");
	fprintf(fileKey, "{");
	cotnum(rsaContext->d, fileKey);
	fprintf(fileKey, ",");
	cotnum(rsaContext->n, fileKey);
	fprintf(fileKey,"}");

	printf("[INFO] All thing has done. Good Luck!\n");
	fprintf(fileLog, "[INFO] All thing has done. Good Luck!\n");

	fclose(fileKey);
	fclose(fileLog);
	return 0;
}

