/*
 * emvPaymentApp.c
 *
 *  Created on: 26 Jul 2016
 *      Author: steve
 */

#define VERSION_MAJOR "1"
#define VERSION_MINOR "0"
#define VERSION_PATCH "0"

#ifdef DEBUG
#define BUILD_TYPE "DEBUG"
#else
#define BUILD_TYPE "RELEASE"
#endif

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <emv-l2/l2FeigHAL.h>
#include <emv-l2/l2manager.h>
#include <emv-l2/l2base.h>
#include <emv-l2/l2errors.h>
#include <emv-l2/l2entrypoint.h>
#include <emv-l2/l2expresspay.h>
#include <emv-l2/l2paywave.h>
#include <emv-l2/l2paypass.h>
#include <emv-l2/l2discover.h>
#include <feig/feclr.h>
#include "asn1.h"
#include "tlv.h"
#include "emvTagList.h"
#include "sslCall.h"

#include "macros.h"

#include "dukpt.h"

static char version[] = VERSION_MAJOR "." VERSION_MINOR "." VERSION_PATCH "." BUILD_TYPE;
static char timestamp[] = __DATE__ " " __TIME__;

static L2Outcome gL2Outcome;
static int gfeclr_fd = -1;
pthread_t inc_x_thread;
bool threadRunning = false;

UIRequest onRequestOutcome;
UIRequest onRestartOutcome;
L2ExternalTransactionParameters tp;

CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;

//Thread for sending data online
void *thread_doSslCall(void *body){

	printf("\n\n\nthread_doSslCall here...\n");

	doSslCall((char *)body);

	// free pointer to outputBuffer
	free(body);

	printf("\n\n\nthread_doSslCall here2...\n");

	return NULL;
}

int open_session_and_login()
{
	CK_RV rv = CKR_OK;

	rv = C_Initialize(NULL_PTR);
	if (CKR_OK != rv)
		return EXIT_FAILURE;

	rv = C_OpenSession(FEPKCS11_APP0_TOKEN_SLOT_ID,
			   CKF_RW_SESSION | CKF_SERIAL_SESSION,
			   NULL,
			   NULL,
			   &hSession);
	if (CKR_OK != rv) {
		C_Finalize(NULL_PTR);
		return EXIT_FAILURE;
	}

	rv = C_Login(hSession, CKU_USER, NULL_PTR, 0);
	if (CKR_OK != rv) {
		C_CloseSession(hSession);
		C_Finalize(NULL_PTR);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

void logout_and_close_session()
{
	C_Logout(hSession);
	C_CloseSession(hSession);
	C_Finalize(NULL_PTR);
	hSession = CK_INVALID_HANDLE;
}

void PrintEMVPaymentAppVersions(){
	printf("EMV Payment Application Version : %s\n",version);
	printf("EMV Payment Application Timestamp : %s\n",timestamp);
}

void ClearTransactionData()
{
	/* Init EMVCo L2 outcome structure */
	memset(&gL2Outcome, 0, sizeof(L2Outcome));

	/* Init EMVCo L2 transaction parameters */
	memset(&tp, 0, sizeof(L2ExternalTransactionParameters));
	memset(&onRequestOutcome, 0, sizeof(UIRequest));
	memset(&onRestartOutcome, 0, sizeof(UIRequest));
}

void SetTransactionData()
{
	/* Init EMVCo L2 transaction parameters */
	memset(&tp, 0, sizeof(L2ExternalTransactionParameters));
	memcpy(tp.m_9F02_AmountAuthorised, "\x06\x00\x00\x00\x00\x07\x77", 7);
	memcpy(tp.m_9F03_AmountOther, "\x06\x00\x00\x00\x00\x00\x00", 7);
	memcpy(tp.m_9C_TransactionType, "\x01\x00", 2);
	/* Transaction currency code EURO = 978 */
	/* Transaction currency code USD = 840 */
	/* Transaction currency code GBP = 826 */
	memcpy(tp.m_5F2A_TransactionCurrencyCode, "\x02\x08\x26", 3);
}

void WaitEmvThreadFinnish(){
	if (threadRunning){
		//wait for thread to finish
		printf("Wait for thread to finish\n");
		pthread_join(inc_x_thread,NULL);
		threadRunning = false;
	}
}

int check_2pay_sys(unsigned char *rsp, int lr)
{
	char *MC_RID = "\xA0\x00\x00\x00\x04";	      /* MasterCard RID */
	char *MC_UK_RID = "\xA0\x00\x00\x00\x05";     /* MasterCard UK RID */
	char *VISA_RID = "\xA0\x00\x00\x00\x03";      /* Visa RID */
	char *AMEX_RID = "\xA0\x00\x00\x00\x25";      /* AMEX RID */
	char *DISCOVER_RID = "\xA0\x00\x00\x03\x24";  /* AMEX RID */
	char *GIROGO_RID = "\xD2\x76\x00\x00\x25";    /* Geldkarte/GiroGo RID */
	unsigned char *fci_issuer_discret_data;
	int fci_issuer_discret_data_len = 0;
	unsigned char *aid = NULL;
	int aid_len;
	unsigned char *app_template = NULL;
	int app_template_len = 0;
	unsigned char *tmp_aid = NULL;
	int tmp_aid_len;
	unsigned char *app_label = NULL;
	int app_label_len = 0;
	int priority = 15;
	unsigned char *prio = NULL;
	int prio_len;
	unsigned char *d;

	fci_issuer_discret_data = asn1Find(rsp, "\x6F\xA5\xBF\x0C", 3);
	if (fci_issuer_discret_data == NULL)
		return -1;

	asn1Tag(&fci_issuer_discret_data);
	fci_issuer_discret_data_len = asn1Length(&fci_issuer_discret_data);

	while (fci_issuer_discret_data_len > 4) {
		app_template = asn1Find(fci_issuer_discret_data, "\x61", 1);
		if (app_template == NULL)
			break;

		asn1Tag(&app_template);
		app_template_len = asn1Length(&app_template);
		d = app_template;
		/* Decode the AID */
		tmp_aid = asn1Find(d, "\x4F", 1);
		if (tmp_aid == NULL)
			return -1;

		asn1Tag(&tmp_aid);
		tmp_aid_len = asn1Length(&tmp_aid);
		d = tmp_aid + tmp_aid_len;
		/* Decode the application label */
		app_label = asn1Find(d, "\x50", 1);
		if (app_label != NULL) {
			asn1Tag(&app_label);
			app_label_len = asn1Length(&app_label);
			d = app_label + app_label_len;
		}
		/* Decode the priority */
		prio = asn1Find(d, "\x87", 1);
		if (prio != NULL) {
			asn1Tag(&prio);
			prio_len = asn1Length(&prio);
			d = prio + prio_len;

			if (*prio < priority) {
				priority = *prio;
				aid = tmp_aid;
				aid_len = tmp_aid_len;
			}
		} else {
			aid = tmp_aid;
			aid_len = tmp_aid_len;
		}

		fci_issuer_discret_data_len -= app_template_len;
		fci_issuer_discret_data = d;
	}

	if (aid == NULL)
		return -1;

	/* We need at least the first five bytes of the AID (RID) */
	if (aid_len < 5)
		return -1;

	if ((memcmp(aid, MC_RID, 5) == 0) || (memcmp(aid, MC_UK_RID, 5) == 0))
		return 1;
	else if (memcmp(aid, VISA_RID, 5) == 0)
		return 2;
	else if (memcmp(aid, AMEX_RID, 5) == 0)
		return 3;
	else if (memcmp(aid, DISCOVER_RID, 5) == 0)
		return 4;
	else if (memcmp(aid, GIROGO_RID, 5) == 0)
		return 5;

	/* AID (RID) not supported */
	return -1;
}

void print_UIRequest(UIRequest *UIRequestData)
{
	int i = 0;

	printf("UIRequestData->m_bpresent:\t\t0x%02X\n", UIRequestData->m_bpresent);
	printf("UIRequestData->m_ucmsgid:\t\t0x%02X (%d)\n", UIRequestData->m_ucmsgid, UIRequestData->m_ucmsgid);
	printf("============================================\n");
	printf("============================================\n");
	printf("===== ");
	switch (UIRequestData->m_ucmsgid) {
	case UIMsg_Approved:
		printf("Approved ");
		break;
	case UIMsg_NotAuthorised:
		printf("NotAuthorised ");
		break;
	case UIMsg_PleaseEnterYourPIN:
		printf("Please Enter Your PIN ");
		break;
	case UIMsg_ProcessingError:
		printf("Processing Error ");
		break;
	case UIMsg_PleaseRemoveCard:
		printf("Please Remove Card ");
		break;
	case UIMsg_Welcome:
		printf("Welcome ");
		break;
	case UIMsg_PresentCard:
		printf("PresentCard ");
		break;
	case UIMsg_Processing:
		printf("Processing ");
		break;
	case UIMsg_CardReadOKPleaseRemoveCard:
		printf("Card Read OK Please Remove Card ");
		break;
	case UIMsg_PleaseInsertOrSwipeCard:
		printf("Please Insert Or Swipe Card ");
		break;
	case UIMsg_PleasePresentOneCardOnly:
		printf("Please Present One Card Only ");
		break;
	case UIMsg_ApprovedPleaseSign:
		printf("Approved Please Sign ");
		break;
	case UIMsg_AuthorisingPleaseWait:
		printf("Authorising Please Wait ");
		break;
	case UIMsg_InsertSwipeOrTryAnotherCard:
		printf("Insert Swipe Or Try Another Card ");
		break;
	case UIMsg_PleaseInsertCard:
		printf("Please Insert Card ");
		break;
	case UIMsg_NoMessageDisplayed:
		printf("No Message Displayed ");
		break;
	case UIMsg_SeePhoneForInstructions:
		printf("See Phone For Instructions ");
		break;
	case UIMsg_PresentCardAgain:
		printf("Present Card Again ");
		break;
	case UIMsg_NA:
		printf("N/A Not Applicable ");
		break;
	default:
		break;
	}
	printf("=====\n");
	printf("============================================\n");
	printf("============================================\n");
	printf("UIRequestData->m_uctranstatus:\t\t0x%02X - ", UIRequestData->m_uctranstatus);
	switch (UIRequestData->m_uctranstatus) {
	case ETransactionStatus_NotReady:
		printf("ETransactionStatus_NotReady\n");
		break;
	case ETransactionStatus_Idle:
		printf("ETransactionStatus_Idle\n");
		break;
	case ETransactionStatus_ReadytoRead:
		printf("ETransactionStatus_ReadytoRead\n");
		break;
	case ETransactionStatus_Processing:
		printf("ETransactionStatus_Processing\n");
		break;
	case ETransactionStatus_CardReadSuccessfully:
		printf("ETransactionStatus_CardReadSuccessfully\n");
		break;
	case ETransactionStatus_ProcessingError:
		printf("ETransactionStatus_ProcessingError\n");
		break;
	default:
		printf("<UNKOWN>\n");
		break;
	}
	printf("UIRequestData->m_ucholdtime:\t\t0x%02X%02X\n", UIRequestData->m_ucholdtime[0], UIRequestData->m_ucholdtime[1]);
	printf("UIRequestData->m_uclanguagepreference:\t");
	if (UIRequestData->m_uclanguagepreference[0] > 0) {
		for (i = 0; i < UIRequestData->m_uclanguagepreference[0]; i += 2)
			printf("%c%c (0x%02X%02X) ", UIRequestData->m_uclanguagepreference[i+1], UIRequestData->m_uclanguagepreference[i+2], UIRequestData->m_uclanguagepreference[i+1], UIRequestData->m_uclanguagepreference[i+2]);
		printf("\n");
	} else {
		printf("N/A\n");
	}
	printf("UIRequestData->m_valuequalifier:\t0x%02X - ", UIRequestData->m_valuequalifier);
	switch (UIRequestData->m_valuequalifier) {
	case EValueQualifierType_NA:
		printf("EValueQualifierType_NA\n");
		break;
	case EValueQualifierType_Amount:
		printf("EValueQualifierType_Amount\n");
		break;
	case EValueQualifierType_Balance:
		printf("EValueQualifierType_Balance\n");
		break;
	default:
		printf("\n");
		break;
	}

	printf("UIRequestData->m_ucvalue:\t\t");
	if (UIRequestData->m_ucvalue[0] > 0) {
		for (i = 0; i < UIRequestData->m_ucvalue[0]; i++)
			printf("0x%02X ", UIRequestData->m_ucvalue[i+1]);
		printf("\n");
	} else {
		printf("N/A\n");
	}
	printf("UIRequestData->m_ucCurrencyCode:\t");
	if (UIRequestData->m_ucCurrencyCode[0] > 0) {
		for (i = 0; i < UIRequestData->m_ucCurrencyCode[0]; i += 2)
			printf("0x%02X%02X ", UIRequestData->m_ucCurrencyCode[i+1], UIRequestData->m_ucCurrencyCode[i+2]);
		printf("\n");
	} else {
		printf("N/A\n");
	}
	printf("\n");
}

//************************ Callbacks START

void SendL2UIOutcomeImplFeig(L2Outcome *pL2Outcome)
{
	int i = 0;

	memcpy(&gL2Outcome, pL2Outcome, sizeof(L2Outcome));

	printf("-------------------------------------------\n");
	printf("%s\n", __func__);
	printf("-------------------------------------------\n");
	printf("OUTCOMES:\n");
	printf("pL2Outcome->m_l2errorCode: %d\n", pL2Outcome->m_l2errorCode);
	printf("pL2Outcome->m_outcomeType: ");
	switch (pL2Outcome->m_outcomeType) {
	case EOutcomeType_NA:
		printf("EOutcomeType_NA\n");
		break;
	case EOutcomeType_SelectNext:
		printf("EOutcomeType_SelectNext\n");
		break;
	case EOutcomeType_TryAgain:
		printf("EOutcomeType_TryAgain\n");
		break;
	case EOutcomeType_Approved:
		printf("EOutcomeType_Approved\n");
		break;
	case EOutcomeType_Declined:
		printf("EOutcomeType_Declined\n");
		break;
	case EOutcomeType_Online:
		printf("EOutcomeType_Online\n");
		break;
	case EOutcomeType_TryAnotherInterface:
		printf("EOutcomeType_TryAnotherInterface\n");
		break;
	case EOutcomeType_EndApplication:
		printf("EOutcomeType_EndApplication\n");
		break;
	default:
		printf("UNKNOWN\n");
		break;
	}

	/* Described in EMVCO 2.5 Book A:
	 * 8.1.1.19
	 * If the Outcome parameter Start has a value other than ‘N/A’,
	 * then the reader shall set the Restart flag.
	 *
	 * Restart flag:
	 * Internal reader flag that indicates whether a kernel is being
	 * started for a new transaction or continuing with an ongoing
	 * transaction (e.g. in order to complete online processing, to
	 * perform on-device CVM, to recover from a communication
	 * error, etc.).
	 */
	printf("pL2Outcome->m_outcomeParameters.m_bRestart: %d\n",
			       (int)pL2Outcome->m_outcomeParameters.m_bRestart);

	printf("pL2Outcome->m_outcomeParameters.m_start: ");
	switch (pL2Outcome->m_outcomeParameters.m_start) {
	case EStart_NA:
		printf("EStart_NA\n");
		break;
	case EStart_A:
		printf("EStart_A\n");
		break;
	case EStart_B:
		printf("EStart_B\n");
		break;
	case EStart_C:
		printf("EStart_C\n");
		break;
	case EStart_D:
		printf("EStart_D\n");
		break;
	default:
		break;
	}

	printf("pL2Outcome->m_outcomeParameters.m_onlineresponsetype: ");
	switch (pL2Outcome->m_outcomeParameters.m_onlineresponsetype) {
	case EOnlineResponseType_NA:
		printf("EOnlineResponseType_NA\n");
		break;
	case EOnlineResponseType_EMVData:
		printf("EOnlineResponseType_EMVData\n");
		break;
	case EOnlineResponseType_Any:
		printf("EOnlineResponseType_Any\n");
		break;
	case EOnlineResponseType_EMV7191Received:
		printf("EOnlineResponseType_EMV7191Received\n");
		break;
	case EOnlineResponseType_Any7191Received:
		printf("EOnlineResponseType_Any7191Received\n");
		break;
	case EOnlineResponseType_Only7191Received:
		printf("EOnlineResponseType_Only7191Received\n");
		break;
	default:
		break;
	}

	printf("pL2Outcome->m_outcomeParameters.m_ucOnlineResponse: ");
	if (pL2Outcome->m_outcomeParameters.m_usOnlineResponseLength == 0) {
		printf("N/A\n");
	} else {
		for (i = 0; i < pL2Outcome->m_outcomeParameters.m_usOnlineResponseLength; i++)
			printf("%02X", pL2Outcome->m_outcomeParameters.m_ucOnlineResponse[i]);
		printf("\n");
	}

	printf("pL2Outcome->m_outcomeParameters.m_cvm: ");
	switch (pL2Outcome->m_outcomeParameters.m_cvm) {
	case ECVM_ConfCode:
		printf("ECVM_ConfCode\n");
		break;
	case ECVM_NA:
		printf("ECVM_NA\n");
		break;
	case ECVM_NoCVM:
		printf("ECVM_NoCVM\n");
		break;
	case ECVM_OnlinePin:
		printf("ECVM_OnlinePin\n");
		break;
	case ECVM_Signature:
		printf("ECVM_Signature\n");
		break;
	default:
		break;
	}

	printf("pL2Outcome->m_outcomeParameters.m_UIRequestOnOutCome: ");
	if (pL2Outcome->m_outcomeParameters.m_UIRequestOnOutCome.m_bpresent) {
		printf("\n");
		print_UIRequest(&pL2Outcome->m_outcomeParameters.m_UIRequestOnOutCome);
	} else {
		printf("N/A\n");
	}
	printf("pL2Outcome->m_outcomeParameters.m_UIRequestOnRestart: ");
	if (pL2Outcome->m_outcomeParameters.m_UIRequestOnRestart.m_bpresent) {
		printf("\n");
		print_UIRequest(&pL2Outcome->m_outcomeParameters.m_UIRequestOnRestart);
	} else {
		printf("N/A\n");
	}

	printf("pL2Outcome->m_outcomeParameters.m_usDataRecord: ");
	if (pL2Outcome->m_outcomeParameters.m_usDataRecordLength == 0) {
		printf("N/A\n");
	} else {
		for (i = 0; i < pL2Outcome->m_outcomeParameters.m_usDataRecordLength; i++)
			printf("%02X", pL2Outcome->m_outcomeParameters.m_ucDataRecord[i]);
		printf("\n");
	}

	printf("pL2Outcome->m_outcomeParameters.m_ucDiscretionaryData: ");
	if (pL2Outcome->m_outcomeParameters.m_usDiscretionaryDataLength == 0) {
		printf("N/A\n");
	} else {
		for (i = 0; i < pL2Outcome->m_outcomeParameters.m_usDiscretionaryDataLength; i++)
			printf("%02X", pL2Outcome->m_outcomeParameters.m_ucDiscretionaryData[i]);
		printf("\n");
	}

	printf("pL2Outcome->m_outcomeParameters.m_interface: ");
	switch (pL2Outcome->m_outcomeParameters.m_interface) {
	case EInterface_NA:
		printf("EInterface_NA\n");
		break;
	case EInterfaceContact:
		printf("EInterfaceContact\n");
		break;
	case EInterfaceContactAndMagStripe:
		printf("EInterfaceContactAndMagStripe\n");
		break;
	case EInterfaceMagstripe:
		printf("EInterfaceMagstripe\n");
		break;
	default:
		break;
	}

	printf("pL2Outcome->m_outcomeParameters.m_receipt: %d\n",
				     pL2Outcome->m_outcomeParameters.m_receipt);

	printf("pL2Outcome->m_outcomeParameters.m_ucFieldOff: %02X%02X\n",
			       pL2Outcome->m_outcomeParameters.m_ucFieldOff[0],
			       pL2Outcome->m_outcomeParameters.m_ucFieldOff[1]);

	printf("pL2Outcome->m_outcomeParameters.m_usRemoval: %d\n",
				   pL2Outcome->m_outcomeParameters.m_usRemoval);
}


void SendTrack2DataImplFeig(uchar *uTrack2Data, int iLen)
{
	int i = 0;
	printf("-------------------------------------------\n");
	printf("%s\n", __func__);
	printf("-------------------------------------------\n");
	printf("Track2(or Track2 Equivalent Data):\n");
	for (i = 0; i < iLen; i++)
		printf("%02X", uTrack2Data[i]);
	printf("\n\n");
}

void UIRequestCallbackImplFeig(UIRequest *UIRequestData)
{
	printf("-------------------------------------------\n");
	printf("%s\n", __func__);
	printf("-------------------------------------------\n");

	print_UIRequest(UIRequestData);
}

void PrintEMVCoL2Versions(void)
{
	char cVerBNum[28 + 1] = {0};

	l2manager_GetVersBuildNum(cVerBNum);
	printf("L2Manager : %s\n", cVerBNum);

	memset(cVerBNum, 0, sizeof(cVerBNum));
	l2entry_GetVersBuildNum(cVerBNum);
	printf("L2Entrypoint : %s\n", cVerBNum);

	memset(cVerBNum, 0, sizeof(cVerBNum));
	l2base_GetVersBuildNum(cVerBNum);
	printf("L2Base : %s\n", cVerBNum);

	memset(cVerBNum, 0, sizeof(cVerBNum));
	l2pp_GetVersBuildNum(cVerBNum);
	printf("L2PayPass : %s\n", cVerBNum);

	memset(cVerBNum, 0, sizeof(cVerBNum));
	l2pw_GetVersBuildNum(cVerBNum);
	printf("L2Paywave : %s\n", cVerBNum);

	memset(cVerBNum, 0, sizeof(cVerBNum));
	l2ep_GetVersBuildNum(cVerBNum);
	printf("L2ExpressPay : %s\n", cVerBNum);

	memset(cVerBNum, 0, sizeof(cVerBNum));
	l2discover_GetVersBuildNum(cVerBNum);
	printf("L2Discover : %s\n", cVerBNum);

	memset(cVerBNum, 0, sizeof(cVerBNum));
	l2FeigHAL_GetVersBuildNum(cVerBNum);
	printf("L2FeigHAL : %s\n", cVerBNum);
	printf("\n");
}


#ifdef DEBUG
//This callback is used in debug mode only
int CardTransmitImplFeig(void *pl2, enum SSL2CommandTypes type,
				ushort nInputLength, uchar *pucInput,
				int *pnOutputLength, uchar *pucOutput,
				int nOutputBufferSize)
{
	int rc = 0;
	uint8_t rx_last_bits;
	uint64_t status;
	int idx = 0;

	printf("-------------------------------------------\n");
	printf("%s\n", __func__);
	printf("-------------------------------------------\n");

	printf("C-APDU: ");
	for (idx = 0; idx < nInputLength; idx++)
			printf("%02X ", pucInput[idx]);
	printf("\n");

	rc = feclr_transceive(gfeclr_fd,
			      0,
			      pucInput,
			      nInputLength,
			      0,
			      pucOutput,
			      nOutputBufferSize,
			      (size_t *)pnOutputLength,
			      &rx_last_bits,
			      0,
			      &status);
	if (rc < 0) {
		printf("APDU exchange failed with error: \"%s\"\n",
		strerror(rc));
		return SMARTCARD_FAIL;
	}
	if (status != FECLR_STS_OK) {
		printf("APDU exchange failed with status: 0x%08llX\n", status);
		return SMARTCARD_FAIL;
	}

	printf("R-APDU: ");
	for (idx = 0; idx < *pnOutputLength; idx++)
		printf("%02X ", pucOutput[idx]);
	printf("\n\n");

	return SMARTCARD_OK;
}

#endif

//************************** Callbacks END

int SetEmvCallbacks(int fd)
{
	int rc = 0;

	/* save contactless interface file descriptor for access in callback */
	gfeclr_fd = fd;

	printf("Register SendTrack2DataImplFeig\n");
	/* Register user-callbacks */
	/* Callback to receive the Track2 / Track2 equivalent data as soon as
	 * available.
	 */
	rc = l2FeigHAL_register_SendTrack2DataCallback(SendTrack2DataImplFeig);
	if (rc != L2TRUE) {
		printf("Register SendTrack2DataImplFeig failed\n");
		return 1;
	}

	printf("Register SendL2UIOutcomeImplFeig\n");
	/* Callback to receive the Outcome data as soon as available.
	 */
	rc = l2FeigHAL_register_SendL2OutcomeCallback(SendL2UIOutcomeImplFeig);
	if (rc != L2TRUE) {
		printf("Register SendL2UIOutcomeImplFeig failed\n");
		return 1;
	}

#ifdef DEBUG
	printf("Register CardTransmitImplFeig\n");
	/* APDU Trace Callback -> only needed for debug purpose */
	rc = l2FeigHAL_register_CardTransmitCallback(CardTransmitImplFeig);
	if (rc != L2TRUE) {
		printf("Register CardTransmitImplFeig failed\n");
		return 1;
	}

#endif

	printf("Register UIRequestCallbackImplFeig\n");
	/* UIRequest Callback */
	rc = l2FeigHAL_register_UIRequestCallback(UIRequestCallbackImplFeig);
	if (rc != L2TRUE) {
		printf("Register UIRequestCallbackImplFeig failed\n");
		return 1;
	}
	return 0;
}

int SetEmvL2Layers(int fd)
{
	l2bool result = L2FALSE;
	int rc;
	/* Init EMVCo L2 manager layer */
	result = l2manager_Init();
	if (result != L2TRUE) {
		printf("l2manager_Init failed\n");
		return 1;
	}

	/* Init EMVCo L2 HAL layer */
	rc = l2FeigHAL_Init(fd,
			    &hSession,
			    "config/");
	if (rc < 0) {
		printf("Init L2FeigHAL failed with error: %d\n", rc);
		return 1;
	}

	return 0;
}

int IsEMVCard(int fd,uint64_t *pStatus) {
	unsigned char cmd_buffer[261];
	unsigned char rsp_buffer[258];
	size_t rx_frame_size;
	uint8_t rx_last_bits;
	char *SELECT_2PAY_SYS = "\x00\xA4\x04\x00\x0E\x32\x50\x41\x59\x2E\x53\x59\x53\x2E\x44\x44\x46\x30\x31\x00";
	int rc;

	/* Select 2PAY.SYS.DDF01 */
	rc = feclr_transceive(fd, 0,
			      SELECT_2PAY_SYS, 20, 0,
			      rsp_buffer, sizeof(rsp_buffer),
			      &rx_frame_size, &rx_last_bits,
			      0,
			      pStatus);
	if (rc < 0) {
		return rc;
	}


	if (!verify_icc_response(rsp_buffer, rx_frame_size, 0x9000)) {
		if (asn1Validate(rsp_buffer, rx_frame_size - 2) == 0) {
			rc = check_2pay_sys(rsp_buffer, rx_frame_size);
			printf(" check_2pay_sys rc value = %d\n",rc);
			if (rc == 1) {
				/* MASTER Card detected */
				printf(" MASTER Card detected\n");
				return 1;
			} else if (rc == 2) {
				/* VISA Card detected */
				printf("VISA Card detected\n");
				return 1;
			} else if (rc == 3) {
				/* AMEX Card detected */
				printf("AMEX Card detected\n");
				return 1;
			} else if (rc == 4) {
				/* DISCOVER Card detected */
				printf("DISCOVER Card detected\n");
				return 1;
			} else if (rc == 5) {
				/* GIROGO Card detected */
				printf("GIROGO Card detected\n");
				visualization_girogo();
				return 0;
			}
		}
	}
	return 0;
}

void DoEmvTransaction(){
	unsigned char transaction_data[4096];
	unsigned int transaction_data_len = 0;
	unsigned char custom_data[1024];
	unsigned int custom_data_len = 0;
	char *outputBuffer;
	char *sesitiveTagBuffer;
	char *clearTagBuffer;
	int samSlot = 1;
	char pToken[32] = {0};
	l2bool result = L2FALSE;
	int rcTransaction = 0;
	int rcResponse = 0;
	int rc = 0;
	int i = 0;


	/* Perform EMVCo L2 transaction */
	rcTransaction = l2manager_PerformTransaction(&tp,
					  &onRequestOutcome,
					  &onRestartOutcome,
					  samSlot,
					  pToken);
	/* Evaluate return value */
	printf("\nl2manager_PerformTransaction() returns with %d\n\n", rcTransaction);

	switch (rcTransaction) {
	case EMV_OFFLINE_ACCEPT:
	case EMV_GO_ONLINE:
		if (onRequestOutcome.m_bpresent)
			printf("onRequestOutcome.m_ucmsgid:  %d\n",
						   (int)onRequestOutcome.m_ucmsgid);
		if (onRestartOutcome.m_bpresent)
			printf("onRestartOutcome.m_ucmsgid:  %d\n",
						   (int)onRestartOutcome.m_ucmsgid);

		/* Get transaction data.
		 * Please see description of
		 * rdol_<kernel_id>_emv.txt or rdol_<kernel_id>_ms.txt.
		 */
		result = l2manager_GetTransactionData(transaction_data,
							  sizeof(transaction_data),
							  &transaction_data_len);
		if (result == L2TRUE) {
			printf("TRANSACTION DATA:\n");
			for (i = 0; i < transaction_data_len; i++)
				printf("%02X", transaction_data[i]);
			printf("\n\n");

			//********** DO DUKPT Crypto


			unsigned char icc[] = {
					0x5A, 0x08, 0x54, 0x13, 0x33, 0x00, 0x90, 0x00, 0x02, 0x18, 0x5F, 0x24, 0x03, 0x17, 0x12, 0x31
			};

			unsigned char hexKsn[21];
			unsigned char hexBuffer[128];

			int i;
			printf("ICC DATA PRE:\n");
						for (i = 0; i < sizeof(icc); i++)
							printf("%02X", icc[i]);
						printf("\n\n");

			dukptEncrypt(hSession, icc, sizeof(icc), hexKsn, hexBuffer);

			printf("EMV - KSN       : %s\n", hexKsn);
			printf("EMV - CipherText: %s\n", hexBuffer);

			printf("Here -1");
#ifdef DEBUG
		fflush(stdout);
#endif


			// Output format for CULR call to Creditcall

			//unsigned short size = sizeof(transaction_data)/sizeof(transaction_data[0]);

			asprintf(&outputBuffer, "<Request type=\"CardEaseXML\" version=\"1.0.0\">\n");
			asprintf(&outputBuffer, "%s<TransactionDetails>\n",outputBuffer);
			asprintf(&outputBuffer, "%s<LocalDateTime format=\"yyyyMMddHHmmss\">20160624105000</LocalDateTime>\n",outputBuffer);
			if (rcTransaction == EMV_OFFLINE_ACCEPT) {
				asprintf(&outputBuffer, "%s<MessageType>Offline</MessageType>\n",outputBuffer);
			} else {
				asprintf(&outputBuffer, "%s<MessageType>Auth</MessageType>\n",outputBuffer);
			}
			asprintf(&outputBuffer, "%s<Amount>777</Amount>\n",outputBuffer);
			asprintf(&outputBuffer, "%s<Reference>CARD_TOKEN_HASH</Reference>\n",outputBuffer);
			asprintf(&outputBuffer, "%s<ExtendedPropertyList>\n",outputBuffer);
			asprintf(&outputBuffer, "%s<ExtendedProperty id=\"dukptksn\">FFFF9876543210E0000F</ExtendedProperty>\n",outputBuffer);
			asprintf(&outputBuffer, "%s<ExtendedProperty id=\"dukptiv\">0000000000000000</ExtendedProperty>\n",outputBuffer);
			asprintf(&outputBuffer, "%s<ExtendedProperty id=\"dukptproduct\">CC01</ExtendedProperty>\n",outputBuffer);
			asprintf(&outputBuffer, "%s</ExtendedPropertyList>\n",outputBuffer);
			asprintf(&outputBuffer, "%s</TransactionDetails>\n",outputBuffer);
			asprintf(&outputBuffer, "%s<TerminalDetails>\n",outputBuffer);
			asprintf(&outputBuffer, "%s<TerminalID>99962873</TerminalID>\n",outputBuffer);
			asprintf(&outputBuffer, "%s<TransactionKey>3uZwVaSDzfU4xqHH</TransactionKey>\n",outputBuffer);
			asprintf(&outputBuffer, "%s</TerminalDetails>\n",outputBuffer);
			asprintf(&outputBuffer, "%s<CardDetails>\n",outputBuffer);
			asprintf(&outputBuffer, "%s<ICC type=\"EMV\">\n",outputBuffer);

			tlvInfo_t *t=malloc(sizeof(tlvInfo_t)*transaction_data_len);
			memset(t,0,transaction_data_len);
			tlvInfo_init(t);

			int tindex = 0;

			asprintf(&clearTagBuffer, "");

			emvparse(transaction_data, transaction_data_len, t, &tindex, 0, &clearTagBuffer, &sesitiveTagBuffer);

			free(t);

			asprintf(&outputBuffer, "%s<ICCTag tagid=\"ENCRYPTEDCARDDETAILS\">4447F41D99D261DE1746EF1BB7E57612</ICCTag>\n",outputBuffer);

			//Clear out transaction_data buffer that contains sensitive data to zero
			memset(&transaction_data[0], 0, sizeof(transaction_data));

			//TODO Clear out sensitive data to zero
//			memset(&sesitiveTagBuffer[0], 0, sizeof(sesitiveTagBuffer));

			free(sesitiveTagBuffer);

//
			asprintf(&outputBuffer, "%s%s",outputBuffer,clearTagBuffer);

			free(clearTagBuffer);

			asprintf(&outputBuffer, "%s</ICC>\n",outputBuffer);
			asprintf(&outputBuffer, "%s</CardDetails>\n",outputBuffer);
			asprintf(&outputBuffer, "%s</Request>\n",outputBuffer);

			printf("%s",outputBuffer);

		}

		/* Get custom data.
		 * Please see description of rdol_clear.txt.
		 */
		result = l2manager_GetCustomData(custom_data,
						 sizeof(custom_data),
						 &custom_data_len);
		if (result == L2TRUE) {
			printf("RDOL:\n");
			for (i = 0; i < custom_data_len; i++)
				printf("%02X", custom_data[i]);
			printf("\n\n");
		}

		/** If the return value is EMV_GO_ONLINE you must call the
		* function l2manager_ProcessOnlineResponse().
		**/
		if (rcTransaction == EMV_GO_ONLINE) {
			/** ATTENTION
			 * It is absolutely necessary to call the function
			 * l2manager_ProcessOnlineResponse() if the code
			 * EMV_GO_ONLINE is returned from function
			 * l2manager_PerformTransaction() !
			 * If you want to abort the transaction, or the backend
			 * is not reachable or something else, you should set
			 * the ucOnlineRespData and OnlineRespDataLen to zero.
			 * In such a case the return code will be
			 * EMV_ONLINE_DECLINE.
			**/

			//NEED to get return buffer
			//doSslCall(outputBuffer);

			unsigned char OnlineRespData[1024] = {0};
			unsigned int OnlineRespDataLen = 0;
#ifdef EMV_ONLINE_SUCCESS
			/* Successfull Online Verification = 0x30 0x30 */
			OnlineRespDataLen = 16;
			memcpy(OnlineRespData,
				   "\x8A\x02\x30\x30\x91\x0A\x60\x6D\x6C\x6C\x37\xD4\xAC\x51\x30\x30",
				   OnlineRespDataLen);
#endif
			memset(&onRequestOutcome, 0, sizeof(UIRequest));
			memset(&onRestartOutcome, 0, sizeof(UIRequest));
			rcResponse = l2manager_ProcessOnlineResponse(OnlineRespData,
								 OnlineRespDataLen,
								 &onRequestOutcome,
								 &onRestartOutcome);
			switch (rcResponse) {
			case EMV_ONLINE_ACCEPT:
				printf("%s returns with EMV_ONLINE_ACCEPT\n",
					   "l2manager_ProcessOnlineResponse()");
				emvSuccessVisualization(1, 1);
				disable_bar();
				enable_running_led();
				break;
			case EMV_ONLINE_DECLINE:
				printf("%s returns with EMV_ONLINE_DECLINE\n",
					 "\nl2manager_ProcessOnlineResponse()");
				/* EMVCo alert tone.
				 * Buzzer Beep @ 750Hz for 200ms
				 * [On -> Off -> On]
				 */
				emvAlertTone();
				break;
			default:
				printf("%s returns with undefined code (%d)\n",
					   "\nl2manager_ProcessOnlineResponse()",
					   rcTransaction);
				/* EMVCo alert tone.
				 * Buzzer Beep @ 750Hz for 200ms
				 * [On -> Off -> On]
				 */
				emvAlertTone();
				break;
			}
		} else {
			/* EMVCo success tone.
			 * Buzzer Beep @ 1500Hz for 500ms
			 */
			if (rcTransaction == EMV_OFFLINE_ACCEPT) {

				if (threadRunning){
				//wait for thread to finish
					WaitEmvThreadFinnish();
				}

				//Create thread for sending data
				int err;
				err = pthread_create(&inc_x_thread,NULL,&thread_doSslCall,(void *)outputBuffer);

				if (err != 0){
					printf("\n\n\nCan't create thread...\n");
					threadRunning = false;
				} else {
					printf("\n\n\nThread created...\n");
					threadRunning = true;
				}

				emvSuccessVisualization();

				disable_bar();
				enable_running_led();
				ClearTransactionData();
				SetTransactionData();
			}
		}
		break;

	case EMV_PPSE_NOT_SUPPORTED_BY_CARD:
	case EMV_NO_MATCHING_APP:
		/** At this point you could do some "closed loop" processing,
		 * because the EMVCo kernel refuse the card.
		 * Maybe it is no credit card, or the application is not
		 * supported.
		 * The card is still activated and remains in ISO 14443-4 state.
		 */
		/* EMVCo alert tone.
		 * Buzzer Beep @ 750Hz for 200ms [On -> Off -> On]
		 */
		emvAlertTone();
		break;
	/* case ...:
	 *	break;
	 */
	default:
		/* The other codes should be treated as error. */
		/* EMVCo alert tone.
		 * Buzzer Beep @ 750Hz for 200ms [On -> Off -> On]
		 */
		emvAlertTone();
		break;
	}


	/* Check TransactionMode */
	rc = l2manager_GetTransactionMode();
	switch (rc) {
	case 1:
		printf("Transaction mode = Magstripe\n");
		break;
	case 2:
		printf("Transaction mode = Magstripe [CVN_17]\n");
		break;
	case 3:
		printf("Transaction mode = EMV\n");
		break;
	default:
		printf("Transaction mode = (%d) - UNKNOWN\n", rc);
		break;
	}

	/* Needed for Mastercard processing */
	/* This function is used to clear TORN for paypass transactions */
	result = l2manager_ClearTorn();
	if (result != L2TRUE)
		printf("Error in function l2manager_ClearTorn()\n");

}


