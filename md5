#include "stdafx.h"


#include <cstdio>
#include <cstring>
#include <Windows.h>
#include <Wincrypt.h>

int main()
{
	HCRYPTPROV hCryptProv;
	HCRYPTHASH hHash;
	if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0))
	{
		printf("Cryptographic provider initialized.\n");
	}
	else
	{
		printf("Acquisition of context failed.\n");
		exit(1);
	}
	if (CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash))
	{
		printf("An empty hash object has been created. \n");
	}
	else
	{
		printf("Error during CryptBeginHash!\n");
		exit(1);
	}
	char data[] = "Boka";
	if (CryptHashData(hHash, (BYTE*)data, strlen(data), 0))
	{
		printf("Hash data loaded. \n");
	}
	else
	{
		printf("Error during CryptHashData!\n");
		exit(1);
	}
	DWORD count = 0;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, NULL, &count, 0))
	{
		printf("Error during CryptGetHashParam!\n");
		exit(1);
	}
	unsigned char* hash_value = static_cast<unsigned char*>(malloc(count + 1));
	ZeroMemory(hash_value, count + 1);

	if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)hash_value, &count, 0))
	{
		printf("Error during CryptGetHashParam!\n");
		exit(1);
	}
	puts("Hash value is received");
	// Вывод на экран полученного хеш-значения
	puts("Hash value:");
	for (unsigned char const* p = hash_value; *p; ++p)
	{
		printf("%x", unsigned(*p), '\n');
	}
	if (hHash)
		CryptDestroyHash(hHash);
	if (hCryptProv)
		CryptReleaseContext(hCryptProv, 0);
	return 0;
}
