/*
 * emvTransaction.c
 *
 *  Created on: 26 Jul 2016
 *      Author: steve
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
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

static L2Outcome gL2Outcome;
static int gfeclr_fd = -1;

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

void ResetTransactionData(L2ExternalTransactionParameters *tp, UIRequest *onRequestOutcome, UIRequest *onRestartOutcome)
{
	/* Init EMVCo L2 outcome structure */
		memset(&gL2Outcome, 0, sizeof(L2Outcome));

		/* Init EMVCo L2 transaction parameters */
		memset(tp, 0, sizeof(L2ExternalTransactionParameters));
		memset(onRequestOutcome, 0, sizeof(UIRequest));
		memset(onRestartOutcome, 0, sizeof(UIRequest));
		memcpy(tp->m_9F02_AmountAuthorised, "\x06\x00\x00\x00\x00\x07\x77", 7);
		memcpy(tp->m_9F03_AmountOther, "\x06\x00\x00\x00\x00\x00\x00", 7);
		memcpy(tp->m_9C_TransactionType, "\x01\x00", 2);
		/* Transaction currency code EURO = 978 */
		/* Transaction currency code USD = 840 */
		/* Transaction currency code GBP = 826 */
		memcpy(tp->m_5F2A_TransactionCurrencyCode, "\x02\x08\x26", 3);
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

	/* Register user-callbacks */
	/* Callback to receive the Track2 / Track2 equivalent data as soon as
	 * available.
	 */
	rc = l2FeigHAL_register_SendTrack2DataCallback(SendTrack2DataImplFeig);
	if (rc != L2TRUE) {
		printf("Register SendTrack2DataCallback failed\n");
		return 1;
	}

	/* Callback to receive the Outcome data as soon as available.
	 */
	rc = l2FeigHAL_register_SendL2OutcomeCallback(SendL2UIOutcomeImplFeig);
	if (rc != L2TRUE) {
		printf("Register SendL2OutcomeCallback failed\n");
		return 1;
	}

#ifdef DEBUG
	/* APDU Trace Callback -> only needed for debug purpose */
	rc = l2FeigHAL_register_CardTransmitCallback(CardTransmitImplFeig);
	if (rc != L2TRUE) {
		printf("Register SendL2OutcomeCallback failed\n");
		return 1;
	}

#endif

	/* UIRequest Callback */
	rc = l2FeigHAL_register_UIRequestCallback(UIRequestCallbackImplFeig);
	if (rc != L2TRUE) {
		printf("Register UIRequestCallbackImplFeig failed\n");
		return 1;
	}
	return 0;
}


