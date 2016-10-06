/*
 * dukpt.c
 *
 *  Created on: 28 Jul 2016
 *      Author: steve
 */
/**
 * FEIG ELECTRONIC Contactless Demo
 *
 * Copyright (C) 2016 FEIG ELECTRONIC GmbH
 *
 * This software is the confidential and proprietary information of
 * FEIG ELECTRONIC GmbH ("Confidential Information"). You shall not
 * disclose such Confidential Information and shall use it only in
 * accordance with the terms of the license agreement you entered
 * into with FEIG ELECTRONIC GmbH.
 */

/*
 * This demo program looks up the DUKPT initial key with id 0xCC01 and label
 * "DUKPT_IK" in application 0's Cryptographic Token and executes three
 * transaction key derivations and data encryption operations.
 *
 * Build as follows:
 *
 * arm-linux-gcc -Wall -Werror dukpt-demo.c -o dukpt-demo -lfepkcs11 -lcrypto
 * fesign --module opensc-pkcs11.so --pin 648219 --slotid 1 --keyid 00a0 \
 *	  --infile dukpt-demo
 **/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <feig/fepkcs11.h>
#include "macros.h"

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(*(x)))

char *bin2hex(char *out, const void *in, size_t len)
{
	const char *p = (const char *)in;
	size_t i;

	for (i = 0; i < len; i++) {
		char digit;

		digit = p[i] >> 4;
		digit = digit < 0xA ? digit + '0' : digit - 10 + 'A';
		out[2 * i] = digit;

		digit = p[i] & 0xF;
		digit = digit < 0xA ? digit + '0' : digit - 10 + 'A';
		out[2 * i + 1] = digit;
	}

	out[2 * len] = '\0';

	return out;
}

int hex2bin( const char *s )
{
    int ret=0;
    int i;
    for( i=0; i<2; i++ )
    {
        char c = *s++;
        int n=0;
        if( '0'<=c && c<='9' )
            n = c-'0';
        else if( 'a'<=c && c<='f' )
            n = 10 + c-'a';
        else if( 'A'<=c && c<='F' )
            n = 10 + c-'A';
        ret = n + ret*16;
    }
    return ret;
}

static CK_OBJECT_HANDLE get_dukpt_ikey(CK_SESSION_HANDLE hSession, char *label,
								    uint16_t id)
{
	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS dukptClass = CKO_DUKPT_IKEY;
	CK_KEY_TYPE dukptKeyType = CKK_DES2;
	CK_ATTRIBUTE attrs_dukpt_key[] = {
		{ CKA_CLASS, &dukptClass, sizeof(dukptClass) },
		{ CKA_KEY_TYPE, &dukptKeyType, sizeof(dukptKeyType) },
		{ CKA_LABEL, label, strlen(label) },
		{ CKA_ID, &id, sizeof(id) }
	};
	CK_ULONG ulObjectCount = 0;
	CK_RV rv = CKR_OK;

	rv = C_FindObjectsInit(hSession, attrs_dukpt_key,
						   ARRAY_SIZE(attrs_dukpt_key));
	assert(rv == CKR_OK);

	rv = C_FindObjects(hSession, &hKey, 1, &ulObjectCount);
	assert(rv == CKR_OK);

	rv = C_FindObjectsFinal(hSession);
	assert(rv == CKR_OK);

	return hKey;
}

static unsigned char *get_key_serial_number(CK_SESSION_HANDLE hSession,
				  CK_OBJECT_HANDLE hIKey, unsigned char ksn[10])
{
	CK_ATTRIBUTE ksn_template[] = {
		{ CKA_DUKPT_KEY_SERIAL_NUMBER, ksn, 10 }
	};
	CK_RV rv = CKR_OK;

	rv = C_GetAttributeValue(hSession, hIKey, ksn_template,
						      ARRAY_SIZE(ksn_template));

	assert(rv == CKR_OK);

	return ksn;
}

static CK_OBJECT_HANDLE get_transaction_key(CK_SESSION_HANDLE hSession,
							 CK_OBJECT_HANDLE hIKey)
{
	CK_RV rv = CKR_OK;
	CK_OBJECT_HANDLE hTxnKey = CK_INVALID_HANDLE;
	CK_MECHANISM mechanism = {
		CKM_KEY_DERIVATION_DUKPT_TRANSACTION_KEY, NULL_PTR, 0
	};
	CK_BBOOL ckTrue = CK_TRUE;
	CK_ATTRIBUTE template[] = {
		{ CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
		{ CKA_DERIVE, &ckTrue, sizeof(ckTrue) }
	};

	rv = C_DeriveKey(hSession, &mechanism, hIKey, template,
						ARRAY_SIZE(template), &hTxnKey);
	assert(rv == CKR_OK);

	return hTxnKey;
}

static CK_OBJECT_HANDLE get_data_key(CK_SESSION_HANDLE hSession,
						       CK_OBJECT_HANDLE hTxnKey)
{
	CK_RV rv = CKR_OK;
	CK_OBJECT_HANDLE hDataKey = CK_INVALID_HANDLE;
	CK_MECHANISM mechanism = {
		CKM_KEY_DERIVATION_DUKPT_DATA_ENCRYPTION_REQUEST, NULL_PTR, 0
	};
	CK_BBOOL ckTrue = CK_TRUE;
	CK_BBOOL ckFalse = CK_FALSE;
	CK_ATTRIBUTE template[] = {
		{ CKA_TOKEN, &ckFalse, sizeof(ckFalse) },
		{ CKA_ENCRYPT, &ckTrue, sizeof(ckTrue) }
	};

	rv = C_DeriveKey(hSession, &mechanism, hTxnKey, template,
					       ARRAY_SIZE(template), &hDataKey);
	assert(rv == CKR_OK);

	return hDataKey;
}

void dukpt_encrypt(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hIKey,
			    void *in, size_t in_len, void *out, size_t *out_len)
{
	CK_OBJECT_HANDLE hTxnKey = get_transaction_key(hSession, hIKey);
	CK_OBJECT_HANDLE hDataKey = get_data_key(hSession, hTxnKey);
	CK_BYTE iv[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	CK_MECHANISM mech_des3_cbc = { CKM_DES3_CBC, &iv, sizeof(iv) };
	CK_ULONG ulOutLen = (CK_ULONG)(*out_len);
	CK_RV rv = CKR_OK;
	size_t padded_len = (in_len + 7) & ~0x7u;
	unsigned char padded_in[padded_len];

	assert(*out_len >= padded_len);

	memset(padded_in, 0, sizeof(padded_in));
	memcpy(padded_in, in, in_len);

	rv = C_EncryptInit(hSession, &mech_des3_cbc, hDataKey);
	assert(rv == CKR_OK);

	rv = C_Encrypt(hSession, padded_in, padded_len, out, &ulOutLen);
	assert(rv == CKR_OK);

	*out_len = (size_t)ulOutLen;

	C_DestroyObject(hSession, hDataKey);
	C_DestroyObject(hSession, hTxnKey);
}

int dukptEncrypt(CK_SESSION_HANDLE hSession, unsigned char *icc,int iccSizeIn, unsigned char *hexKsn, unsigned char *hexBuffer)
{
	CK_OBJECT_HANDLE hIKey = CK_INVALID_HANDLE;
	char label[] = "DUKPT_IKEY", hex[256];
	uint16_t id = 0xCC01;
	int sizeIcc;
	unsigned char buffer[128];
	unsigned char inputBuffer[128];

	size_t len = sizeof(buffer);

	size_t lenHex = sizeof(hexBuffer);

	unsigned char ksn[10];


	//Convert HEX string into binary
    for( sizeIcc=0; sizeIcc<(iccSizeIn/2); sizeIcc++ )
    {
    	//NOTE icc is a pointer
    	inputBuffer[sizeIcc] = hex2bin( icc );
        icc += 2;
    }

	hIKey = get_dukpt_ikey(hSession, label, id);
	if (hIKey == CK_INVALID_HANDLE) {
		printf("No DUKPT Initial Key found (label '%s', id %02hX).\n",
								     label, id);
		goto done;
	}

	printf("Example 3: ICC (Contact and Contactless)\n");

	strcpy(hexKsn, bin2hex(hex, get_key_serial_number(
			   hSession, hIKey, ksn), sizeof(ksn)));

	printf("KSN       : %s\n", hexKsn);

	printf("Plaintext : %s\n", bin2hex(hex, inputBuffer, sizeIcc));


	dukpt_encrypt(hSession, hIKey, inputBuffer,sizeIcc, buffer, &len);

	//Set input buffer to zero
	for( sizeIcc=0; sizeIcc<(iccSizeIn/2); sizeIcc++ )
	{
		//NOTE icc is a pointer
		inputBuffer[sizeIcc] = 0x00;
	}

	strcpy(hexBuffer, bin2hex(hex, buffer, len));

	printf("CipherText: %s\n", hexBuffer);

done:

	return EXIT_SUCCESS;
}
