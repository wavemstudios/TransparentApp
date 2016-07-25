/*
 * PaymentSample - FEIG Payment sample application for EMV L2 Kernel
 *
 * Copyright (C) 2015-2016 FEIG ELECTRONIC GmbH
 *
 * This software is the confidential and proprietary information of
 * FEIG ELECTRONIC GmbH ("Confidential Information"). You shall not
 * disclose such Confidential Information and shall use it only in
 * accordance with the terms of the license agreement you entered
 * into with FEIG ELECTRONIC GmbH.
 */

/* This payment sample is only a demo, howto simply perform a transaction.
 * To get the best performance, the visualization (buzzer & leds) should be done
 * within separate threads.
 */

/* You could compile this sample with
 *
 * arm-linux-gcc PaymentSample.c -o PaymentSample -lfeclr \
 * -lfepkcs11 -lleds -lbuzzer -lL2Manager -lL2Base -lL2PayPass -lL2Paywave \
 * -lL2Entrypoint -lL2ExpressPay -lL2Discover -lL2FeigHAL
 *
 * !!! Don´t forget to sign it before transfer & execution on the target !!!
 */

#include <stdio.h>
#include <string.h>
#include <execinfo.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
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
#include <feig/leds.h>
#include <feig/buzzer.h>
#include <feig/fememcard.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

#include "macros.h"

#include "tlv.h"
#include "emvTagList.h"
#include "sslCall.h"
#include "asn1.h"

#define WAIT_FOR_CARD_INSERTION_TIMEOUT	200000LL /* 2 seconds in us*/
#define WAIT_FOR_CARD_REMOVAL_TIMEOUT	30000000LL /* 30 seconds in us*/

#define PAYMENT_SAMPLE_VERSION	"01.04.00"

#define EMV_ONLINE_SUCCESS	1    /* !< Force Valid Online Response */

#define FECLR_DEVICE		"/dev/feclr0"

static int gfeclr_fd = -1;
static L2Outcome gL2Outcome;

//Thread for sending data online
void *thread_doSslCall(void *body){

	printf("\n\n\nthread_doSslCall here...\n");

	doSslCall((char *)body);

	free(body);

	printf("\n\n\nthread_doSslCall here2...\n");

	return NULL;
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

void disable_bar()
{
	leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
		 LEDS_YELLOW | LEDS_RED);
}

static void enable_running_led(void)
{
	leds_on(LEDS_GREEN0);
}

static void startup_visualization(void)
{
	leds_on(LEDS_GREEN1);

	usleep(100000);

	leds_on(LEDS_YELLOW);

	usleep(100000);

	leds_on(LEDS_RED);

	usleep(100000);

	leds_off(LEDS_GREEN1 | LEDS_YELLOW | LEDS_RED);

	buzzer_beep(659, 150);
	buzzer_beep(740, 150);
	buzzer_beep(830, 150);
	buzzer_beep(987, 300);
}

int verify_icc_response(unsigned char *rsp, int lr, unsigned short sw)
{
	unsigned short sw_rsp;

	if (lr < 2)
		return -1;

	sw_rsp = (rsp[lr - 2] << 8) | rsp[lr - 1];

	return sw_rsp == sw ? 0 : -1;
}

static void visualization_mifare_classic(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		usleep(100000);
		usleep(100000);
		leds_on(LEDS_RED);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}

static void visualization_mifare_plus(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		usleep(100000);
		leds_on(LEDS_GREEN2);
		usleep(100000);
		leds_on(LEDS_RED);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}

static void visualization_mifare_ultralight(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		usleep(100000);
		leds_on(LEDS_GREEN1);
		usleep(100000);
		leds_on(LEDS_RED);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}

static void visualization_mifare_desfire(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		leds_on(LEDS_GREEN1);
		usleep(100000);
		leds_on(LEDS_GREEN2);
		usleep(100000);
		leds_on(LEDS_RED);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}



static void visualization_credit(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		leds_on(LEDS_GREEN1);
		usleep(100000);
		leds_on(LEDS_GREEN2);
		usleep(100000);
		leds_on(LEDS_GREEN3);
		buzzer_off();
		usleep(300000);
		*new_tag = 0;
		*tag = 0;
	}
}

static void visualization_girogo(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		usleep(100000);
		leds_on(LEDS_GREEN2);
		usleep(100000);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}



static void visualization_cipurse(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		usleep(100000);
		leds_on(LEDS_YELLOW | LEDS_RED);
		usleep(100000);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}

static void visualization_iso14443a(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		leds_on(LEDS_GREEN1);
		usleep(100000);
		leds_on(LEDS_YELLOW);
		usleep(100000);
		leds_on(LEDS_RED);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}

static void visualization_iso14443b(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		leds_on(LEDS_GREEN1);
		usleep(100000);
		leds_on(LEDS_YELLOW);
		usleep(100000);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}

static void visualization_jewel(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		usleep(100000);
		usleep(100000);
		leds_on(LEDS_GREEN3);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}

static void visualization_felica(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		usleep(100000);
		leds_on(LEDS_YELLOW);
		usleep(100000);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}

static void ResetTransactionData(L2ExternalTransactionParameters *tp, UIRequest *onRequestOutcome, UIRequest *onRestartOutcome)
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

static int open_session_and_login(CK_SESSION_HANDLE_PTR phSession,
							      CK_SLOT_ID slotID)
{
	CK_RV rv = CKR_OK;

	rv = C_Initialize(NULL_PTR);
	if (CKR_OK != rv)
		return EXIT_FAILURE;

	rv = C_OpenSession(slotID,
			   CKF_RW_SESSION | CKF_SERIAL_SESSION,
			   NULL,
			   NULL,
			   phSession);
	if (CKR_OK != rv) {
		C_Finalize(NULL_PTR);
		return EXIT_FAILURE;
	}

	rv = C_Login(*phSession, CKU_USER, NULL_PTR, 0);
	if (CKR_OK != rv) {
		C_CloseSession(*phSession);
		C_Finalize(NULL_PTR);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static void logout_and_close_session(CK_SESSION_HANDLE_PTR phSession)
{
	C_Logout(*phSession);
	C_CloseSession(*phSession);
	C_Finalize(NULL_PTR);
	*phSession = CK_INVALID_HANDLE;
}

static void print_UIRequest(UIRequest *UIRequestData)
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

static void SendTrack2DataImplFeig(uchar *uTrack2Data, int iLen)
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

static void SendL2UIOutcomeImplFeig(L2Outcome *pL2Outcome)
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

static int CardTransmitImplFeig(void *pl2, enum SSL2CommandTypes type,
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

static void UIRequestCallbackImplFeig(UIRequest *UIRequestData)
{
	printf("-------------------------------------------\n");
	printf("%s\n", __func__);
	printf("-------------------------------------------\n");

	print_UIRequest(UIRequestData);
}

static void PrintEMVCoL2Versions(void)
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

int main(int argc, char *argv[])
{
	struct timeval firstResp;
	union tech_data tech_data;
	uint64_t status, tech;

	int fd = 0;
	int rc = 0;
	int i = 0;
	int isEMV =0;
	/************************/
	l2bool result = L2FALSE;
	UIRequest onRequestOutcome;
	UIRequest onRestartOutcome;
	int samSlot = 1;
	char pToken[32] = {0};
	unsigned char transaction_data[4096];
	unsigned int transaction_data_len = 0;
	unsigned char custom_data[1024];
	unsigned int custom_data_len = 0;
	//****** Steve Added
	char *outputBuffer;
	int rcTransaction = 0;
	int rcResponse = 0;
	pthread_t inc_x_thread;

	unsigned char cmd_buffer[261];
	unsigned char rsp_buffer[258];
	size_t rx_frame_size;
	uint8_t rx_last_bits;
	char *SELECT_2PAY_SYS = "\x00\xA4\x04\x00\x0E\x32\x50\x41\x59\x2E\x53\x59\x53\x2E\x44\x44\x46\x30\x31\x00";
	char *SELECT_EF_ID_INFO = "\x00\xA4\x00\x00\x02\x2F\xF7";
	char *SELECT_EF_ACCESS = "\x00\xA4\x02\x0C\x02\x01\x1C";
	int new_tag = 0, tag = 0;
	uint16_t tag_typ = FEMEMCARD_TAG_TYPE_UNKNOWN;

	//******************

	L2ExternalTransactionParameters tp;
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;

	printf("Payment sample version %s started\n\n", PAYMENT_SAMPLE_VERSION);
	/* Print EMVCo Kernel versions */
	PrintEMVCoL2Versions();

	/* Login to PKCS11 interface */
	rc = open_session_and_login(&hSession, FEPKCS11_APP0_TOKEN_SLOT_ID);
	if (rc != EXIT_SUCCESS)
		return -1;

	/* Initialize buzzer interface */
	rc = buzzer_init();
	if (rc < 0) {
		printf("buzzer_init failed with error: \"%s\"\n", strerror(rc));
		goto err1;
	}

	/* Initialize led interface */
	rc = leds_init();
	if (rc < 0) {
		printf("led_init failed with error: \"%s\"\n", strerror(rc));
		goto err2;
	}

	/* Enable logo leds */
	leds_on(LEDS_LOGO0 | LEDS_LOGO1);
	startup_visualization();

	/* Acquire exclusive access to the FEIG ContactLess Reader device 0 */
	fd = open(FECLR_DEVICE, O_RDWR);
	if (fd < 0) {
		printf("Open device failed with error: \"%s\"\n",
							       strerror(errno));
		goto err3;
	}

	/* Init EMVCo L2 manager layer */
	result = l2manager_Init();
	if (result != L2TRUE) {
		printf("l2manager_Init failed\n");
		goto err4;
	}

	/* Init EMVCo L2 HAL layer */
	rc = l2FeigHAL_Init(fd,
			    &hSession,
			    "config/");
	if (rc < 0) {
		printf("Init L2FeigHAL failed with error: %d\n", rc);
		goto err5;
	}

	/* Register user-callbacks */
	/* Callback to receive the Track2 / Track2 equivalent data as soon as
	 * available.
	 */
	rc = l2FeigHAL_register_SendTrack2DataCallback(SendTrack2DataImplFeig);
	if (rc != L2TRUE) {
		printf("Register SendTrack2DataCallback failed\n");
		goto err5;
	}

	/* Callback to receive the Outcome data as soon as available.
	 */
	rc = l2FeigHAL_register_SendL2OutcomeCallback(SendL2UIOutcomeImplFeig);
	if (rc != L2TRUE) {
		printf("Register SendL2OutcomeCallback failed\n");
		goto err5;
	}

	/* APDU Trace Callback -> only needed for debug purpose */
	rc = l2FeigHAL_register_CardTransmitCallback(CardTransmitImplFeig);
	if (rc != L2TRUE) {
		printf("Register SendL2OutcomeCallback failed\n");
		goto err5;
	}
	/* save contactless interface file descriptor for access in callback */
	gfeclr_fd = fd;

	/* UIRequest Callback */
	rc = l2FeigHAL_register_UIRequestCallback(UIRequestCallbackImplFeig);
	if (rc != L2TRUE) {
		printf("Register UIRequestCallbackImplFeig failed\n");
		goto err5;
	}

reset:


	ResetTransactionData(&tp,&onRequestOutcome,&onRestartOutcome);

	/* Init EMVCo L2 outcome structure */
//	memset(&gL2Outcome, 0, sizeof(L2Outcome));

	/* Init EMVCo L2 transaction parameters */
//	memset(&tp, 0, sizeof(L2ExternalTransactionParameters));
//	memset(&onRequestOutcome, 0, sizeof(UIRequest));
//	memset(&onRestartOutcome, 0, sizeof(UIRequest));
//	memcpy(tp.m_9F02_AmountAuthorised, "\x06\x00\x00\x00\x00\x07\x77", 7);
//	memcpy(tp.m_9F03_AmountOther, "\x06\x00\x00\x00\x00\x00\x00", 7);
//	memcpy(tp.m_9C_TransactionType, "\x01\x00", 2);
	/* Transaction currency code EURO = 978 */
	/* Transaction currency code USD = 840 */
	/* Transaction currency code GBP = 826 */
//	memcpy(tp.m_5F2A_TransactionCurrencyCode, "\x02\x08\x26", 3);


start:

	disable_bar();
	enable_running_led();

	new_tag = 1;
	tag = 0;
	isEMV = 0;
	/* Start the EMVCo compliant polling loop and poll for ISO/IEC 14443-A
	 * and ISO/IEC 14443-B compatible RFID cards.
	 */
	rc = feclr_start_polling(fd,
				 FECLR_LOOP_EMVCO,
				 FECLR_TECH_ISO14443A | FECLR_TECH_ISO14443B |
				 FECLR_TECH_FELICA | FECLR_TECH_ST |
				 FECLR_TECH_INNOVATRON,
				 FECLR_FLAG_DISABLE_LPCD,
				 &status);
	if (rc < 0) {
		printf("Start polling failed with error: \"%s\"\n",
		strerror(rc));
		feclr_stop_polling(fd);
		goto start;
	} else if (status != FECLR_STS_OK) {
		printf("Start polling failed with status: 0x%08llX\n", status);
		goto err6;
	}

	/* Wait for x seconds for an RFID card to be presented. */
	printf("Please present card...\n");
	while (1) {

#ifdef DEBUG
		fflush(stdout);
#endif

		isEMV = 0;
		rc = feclr_wait_for_card(fd,
					 WAIT_FOR_CARD_INSERTION_TIMEOUT,
					 &tech,
					 &tech_data,
					 &firstResp,
					 &status);
		if (rc < 0) {
			printf("Wait for card failed with error: \"%s\"\n",
			strerror(rc));
			feclr_stop_polling(fd);
			goto start;
		} else if (status != FECLR_STS_OK) {
			new_tag = 1;
			tag = 0;
//			if (status != FECLR_STS_TIMEOUT){
//				printf("Wait for card failed with status: 0x%08llX\n", status);
//			}
			continue;
		}

		//TODO Detect all cards

		/* Evaluate transponder data */
		/** At this point you could evaluate the card data (tech and tech_data).
		 * You could evaluate the card type and maybe do some "closed loop"
		 * processing.
		 * (E.g.: NXP Mifare DESFire)
		 * (For tag type identification please see NXP application note
		 * AN10833 MIFARE Type Identification Procedure - NXP.com
		 **/

		if (tech & FECLR_TECH_FELICA) {
			/* felica detected */
			if (new_tag) {
				printf("felica detected\n");
			}
			tag = 1;
			visualization_felica(&tag, &new_tag);
			continue;
		}

		if ((tech & FECLR_TECH_ISO14443A) &&
		    (tech_data.iso14443a_jewel.type == FECLR_TECH_JEWEL)) {
			/* jewel detected */
			if (new_tag) {
				printf("jewel detected\n");
			}
			tag = 1;
			visualization_jewel(&tag, &new_tag);
			continue;
		}

		if (tech & (FECLR_TECH_ISO14443A | FECLR_TECH_ISO14443B)) {
			/* Evaluate tag */
			rc = fememc_tag_evaluator(tech_data, tech, &tag_typ);
			if (rc < 0) {
				printf("Eval tag failed with error: \"%s\"\n",
								  strerror(rc));
				feclr_stop_polling(fd);
				goto start;
			}

			switch (tag_typ) {
			case FEMEMCARD_TAG_TYPE_MIFARE_CL_1K:
			case FEMEMCARD_TAG_TYPE_MIFARE_CL_4K:
			case FEMEMCARD_TAG_TYPE_MIFARE_MINI:
			case FEMEMCARD_TAG_TYPE_MIFARE_PL_SL1_2K:
			case FEMEMCARD_TAG_TYPE_MIFARE_PL_SL1_4K:
				/* mifare classic detected */
				if (new_tag) {
					printf("mifare classic 1k 2k 4k mini detected\n");
				}
				tag = 1;
				visualization_mifare_classic(&tag, &new_tag);
				continue;

			case FEMEMCARD_TAG_TYPE_MIFARE_PL_SL2_2K:
			case FEMEMCARD_TAG_TYPE_MIFARE_PL_SL2_4K:
				/* mifare plus detected */
				if (new_tag) {
					printf("mifare plus 2k or 4k detected\n");
				}
				tag = 1;
				visualization_mifare_plus(&tag, &new_tag);
				continue;

			case FEMEMCARD_TAG_TYPE_NFC_TAG_TYP_2:
				/* nfc tag type 2 detected */
				if (new_tag) {
					printf("nfc tag type 2 detected\n");
				}
				tag = 1;
				visualization_mifare_ultralight(&tag, &new_tag);
				continue;

			case FEMEMCARD_TAG_TYPE_UNKNOWN:
			case FEMEMCARD_TAG_TYPE_SLE55R_XXXX:
				if (tech & FECLR_TECH_ISO14443A) {
					/* No ISO 14443-4 tag */
					/* ISO14443A detected */
					if (new_tag) {
						printf("No ISO 14443-4 tag - ISO14443A detected\n");
					}
					tag = 1;
					visualization_iso14443a(&tag, &new_tag);
					continue;
				} else if (tech & FECLR_TECH_ISO14443B) {
					/* No ISO 14443-4 tag */
					/* ISO14443B detected */
					if (new_tag) {
						printf("No ISO 14443-4 tag - ISO14443B detected\n");
					}
					tag = 1;
					visualization_iso14443b(&tag, &new_tag);
					continue;
				}
				break;
			}
		}

		/* Final check if transponder is ISO/IEC 14443-4 compatible */
		if (((tech == FECLR_TECH_ISO14443A) &&
			 ((tech_data.iso14443a_jewel.iso14443a.sak & 0x20) == 0x00))
			||
			((tech == FECLR_TECH_ISO14443B) &&
			 ((tech_data.iso14443b.atqb[10] & 0x01) == 0x00))) {
			printf("Transponder is not ISO/IEC 14443-4 compatible !\n");
			continue;
		}

		/* Select the ISO/IEC 14443-4 protocol to communicate with the RFID
		 * card.
		 */
		rc = feclr_select_protocol(fd, FECLR_PROTO_ISO14443_4, &status);
		if (rc < 0) {
			printf("Select ISO14443-4 protocol failed with error: \"%s\"\n",
			strerror(rc));
			continue;
		} else if (status != FECLR_STS_OK) {
			printf("Select ISO14443-4 protocol failed. Status: 0x%08llX\n",
			status);
			continue;
		}

		if (status != FECLR_STS_OK) {
			if (tech & FECLR_TECH_ISO14443A) {
				/* ISO14443A detected */
				if (new_tag) {
					printf("ISO14443A detected\n");
				}
				tag = 1;
				visualization_iso14443a(&tag, &new_tag);
				continue;
			}
			if (tech & FECLR_TECH_ISO14443B) {
				/* ISO14443B detected */
				if (new_tag) {
					printf("ISO14443B detected\n");
				}
				tag = 1;
				visualization_iso14443b(&tag, &new_tag);
				continue;
			}
			continue;
		}

//*********TEST IF EMV CARD

		/* Select 2PAY.SYS.DDF01 */
		rc = feclr_transceive(fd, 0,
				      SELECT_2PAY_SYS, 20, 0,
				      rsp_buffer, sizeof(rsp_buffer),
				      &rx_frame_size, &rx_last_bits,
				      0,
				      &status);
		if (rc < 0) {
			printf("Transceive failed with error: \"%s\"\n",
								  strerror(rc));
			feclr_stop_polling(fd);
			goto start;
		}

		if (status != FECLR_STS_OK) {
			printf("Transceive status: 0x%08llX\n", status);
			continue;
		}

		if (!verify_icc_response(rsp_buffer, rx_frame_size, 0x9000)) {
			if (asn1Validate(rsp_buffer, rx_frame_size - 2) == 0) {
				rc = check_2pay_sys(rsp_buffer, rx_frame_size);
				printf(" check_2pay_sys rc value = %d\n",rc);
				if (rc == 1) {
					/* MASTER Card detected */
					printf(" MASTER Card detected\n");
					tag = 1;
					isEMV = 1;
				} else if (rc == 2) {
					/* VISA Card detected */
					printf("VISA Card detected\n");
					tag = 1;
					isEMV = 1;
				} else if (rc == 3) {
					/* AMEX Card detected */
					printf("AMEX Card detected\n");
					tag = 1;
					isEMV = 1;
				} else if (rc == 4) {
					/* DISCOVER Card detected */
					printf("DISCOVER Card detected\n");
					tag = 1;
					isEMV = 1;
				} else if (rc == 5) {
					/* GIROGO Card detected */
					printf("GIROGO Card detected\n");
					tag = 1;
					visualization_girogo(&tag, &new_tag);
					tag = 1;
					continue;
				}
			}
		}

//*********END TEST EMV CARD

//********* Do this if NOT EMV

		if (!isEMV){
			/* Select EF.ID_INFO of CIPURSE */
			rc = feclr_transceive(fd, 0,
						  SELECT_EF_ID_INFO, 7, 0,
						  rsp_buffer, sizeof(rsp_buffer),
						  &rx_frame_size, &rx_last_bits,
						  0,
						  &status);
			if (rc < 0) {
				printf("Transceive failed with error: \"%s\"\n",
									  strerror(rc));
				feclr_stop_polling(fd);
				goto start;
			}

			if (status != FECLR_STS_OK) {
				/* printf("Transceive status: 0x%08llX\n", status); */
				continue;
			}

			if (!verify_icc_response(rsp_buffer, rx_frame_size, 0x9000)) {
				/* ISO14443-4 detected */
				if (new_tag) {
					printf("cipurse.bmp\n");
				}
				tag = 1;
				visualization_cipurse(&tag, &new_tag);
				continue;
			}

			/* Select EF.CardAccess */
			rc = feclr_transceive(fd, 0,
						  SELECT_EF_ACCESS, 7, 0,
						  rsp_buffer, sizeof(rsp_buffer),
						  &rx_frame_size, &rx_last_bits,
						  0,
						  &status);
			if (rc < 0) {
				printf("Transceive failed with error: \"%s\"\n",
									  strerror(rc));
				feclr_stop_polling(fd);
				goto start;
			}

			if (status != FECLR_STS_OK) {
				/* printf("Transceive status: 0x%08llX\n", status); */
				continue;
			}

			if (!verify_icc_response(rsp_buffer, rx_frame_size, 0x9000)) {
				/* ISO14443-4 detected */
				tag = 1;
				if (tech == FECLR_TECH_ISO14443A){
					if (new_tag) {
						printf("Jewel RFID iso144434A Card\n");
					}
					visualization_iso14443a(&tag, &new_tag);
				} else if (tech == FECLR_TECH_ISO14443B){
					if (new_tag) {
						printf("RFID iso144434B Card\n");
					}
					visualization_iso14443b(&tag, &new_tag);
				}
				continue;
			}

			if (tech & (FECLR_TECH_ISO14443A | FECLR_TECH_ISO14443B)) {
				switch (tag_typ) {
				case FEMEMCARD_TAG_TYPE_MIFARE_DESFIRE:
					/* mifare desfire detected */
					if (new_tag) {
						printf("mifare_desfire.bmp\n");
					}
					tag = 1;
					visualization_mifare_desfire(&tag, &new_tag);
					continue;

				case FEMEMCARD_TAG_TYPE_MIFARE_PL_SL3:
					/* mifare plus detected */
					if (new_tag) {
						printf("mifare_plus.bmp\n");
					}
					tag = 1;
					visualization_mifare_plus(&tag, &new_tag);
					continue;

				case FEMEMCARD_TAG_TYPE_MIFARE_EMULATION:
					/* mifare classic detected */
					if (new_tag) {
						printf("mifare_classic emulation.bmp\n");
					}
					tag = 1;
					visualization_mifare_classic(&tag, &new_tag);
					continue;
				}
			}

			/* ISO14443-4 detected */
			tag = 1;
			if (tech == FECLR_TECH_ISO14443A){
				if (new_tag) {
					printf("Jewel RFID iso144434A Card\n");
				}
				visualization_iso14443a(&tag, &new_tag);
			} else if (tech == FECLR_TECH_ISO14443B){
				if (new_tag) {
					printf("RFID iso144434B Card\n");
				}
				visualization_iso14443b(&tag, &new_tag);
			}

			//Catch all - continue without EMV
			continue;
		}

		//If we are here we must have a valid EMV card

		/* Perform EMVCo L2 transaction */
		rcTransaction = l2manager_PerformTransaction(&tp,
						  &onRequestOutcome,
						  &onRestartOutcome,
						  samSlot,
						  pToken);
		/* Evaluate return value */
		printf("\nl2manager_PerformTransaction() returns with %d\n\n", rc);
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

	//***************** STEVE ADDED
	// create output format for CULR call to Creditcall

				//unsigned short size = sizeof(transaction_data)/sizeof(transaction_data[0]);

				tlvInfo_t *t=malloc(sizeof(tlvInfo_t)*transaction_data_len);
				memset(t,0,transaction_data_len);
				tlvInfo_init(t);

				int tindex =0;

				asprintf(&outputBuffer, "<Request type=\"CardEaseXML\" version=\"1.0.0\">\n",outputBuffer);
				asprintf(&outputBuffer, "%s<TransactionDetails>\n",outputBuffer);
				asprintf(&outputBuffer, "%s<LocalDateTime format=\"yyyyMMddHHmmss\">20160624105000</LocalDateTime>\n",outputBuffer);
				if (rcTransaction == EMV_OFFLINE_ACCEPT) {
					asprintf(&outputBuffer, "%s<MessageType>Offline</MessageType>\n",outputBuffer);
				} else {
					asprintf(&outputBuffer, "%s<MessageType>Auth</MessageType>\n",outputBuffer);
				}
				asprintf(&outputBuffer, "%s<Amount>777</Amount>\n",outputBuffer);
				asprintf(&outputBuffer, "%s<Reference>CARD_TOKEN_HASH</Reference>\n",outputBuffer);
				asprintf(&outputBuffer, "%s</TransactionDetails>\n",outputBuffer);
				asprintf(&outputBuffer, "%s<TerminalDetails>\n",outputBuffer);
				asprintf(&outputBuffer, "%s<TerminalID>99962873</TerminalID>\n",outputBuffer);
				asprintf(&outputBuffer, "%s<TransactionKey>3uZwVaSDzfU4xqHH</TransactionKey>\n",outputBuffer);
				asprintf(&outputBuffer, "%s</TerminalDetails>\n",outputBuffer);
				asprintf(&outputBuffer, "%s<CardDetails>\n",outputBuffer);
				asprintf(&outputBuffer, "%s<ICC type=\"EMV\">\n",outputBuffer);
				emvparse(transaction_data, transaction_data_len, t, &tindex, 0, &outputBuffer);
				asprintf(&outputBuffer, "%s</ICC>\n",outputBuffer);
				asprintf(&outputBuffer, "%s</CardDetails>\n",outputBuffer);
				asprintf(&outputBuffer, "%s</Request>\n",outputBuffer);

				free(t);

				printf("%s",outputBuffer);

	//***************** STEVE ADDED END

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
		root
		cvend
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
					/* EMVCo success tone.
					 * Buzzer Beep @ 1500Hz for 500ms
					 */
					buzzer_beep(1500, 500);
					break;
				case EMV_ONLINE_DECLINE:
					printf("%s returns with EMV_ONLINE_DECLINE\n",
						 "\nl2manager_ProcessOnlineResponse()");
					/* EMVCo alert tone.
					 * Buzzer Beep @ 750Hz for 200ms
					 * [On -> Off -> On]
					 */
					buzzer_beep(750, 200);
					usleep(200000);
					buzzer_beep(750, 200);
					break;
				default:
					printf("%s returns with undefined code (%d)\n",
						   "\nl2manager_ProcessOnlineResponse()",
						   rc);
					/* EMVCo alert tone.
					 * Buzzer Beep @ 750Hz for 200ms
					 * [On -> Off -> On]
					 */
					buzzer_beep(750, 200);
					usleep(200000);
					buzzer_beep(750, 200);
					break;
				}
			} else {
				/* EMVCo success tone.
				 * Buzzer Beep @ 1500Hz for 500ms
				 */
				if (rcTransaction == EMV_OFFLINE_ACCEPT) {


					//Create thread for sending data
					int err;
					err = pthread_create(&inc_x_thread,NULL,&thread_doSslCall,(void *)outputBuffer);

					if (err != 0){
						printf("\n\n\nCan't create thread...\n");
					} else {
						printf("\n\n\nThread created...\n");
					}

					tag=1;
					visualization_credit(&tag, &new_tag);
					ResetTransactionData(&tp,&onRequestOutcome,&onRestartOutcome);
					/* enable green LED 0 */
					leds_set(LEDS_GREEN0);

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
			buzzer_beep(750, 200);
			usleep(200000);
			buzzer_beep(750, 200);
			break;
		/* case ...:
		 *	break;
		 */
		default:
			/* The other codes should be treated as error. */
			/* EMVCo alert tone.
			 * Buzzer Beep @ 750Hz for 200ms [On -> Off -> On]
			 */
			buzzer_beep(750, 200);
			usleep(200000);
			buzzer_beep(750, 200);
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

		/* Wait x seconds for RFID card to be removed from the terminal. */
		printf("Please remove card...\n");
		rc = feclr_wait_for_card_removal(fd,
						 WAIT_FOR_CARD_REMOVAL_TIMEOUT,
						 &status);
		if (rc < 0) {
			printf("Wait for card removal failed with error: \"%s\"\n",
									  strerror(rc));
			goto err6;
		} else if (status != FECLR_STS_OK) {
			printf("Wait for card removal failed with status: 0x%08llX\n",
										status);
			goto err6;
		}
		printf("Card removed...\n");
	}

err6:

	/* Stop the polling loop */
	rc = feclr_stop_polling(fd);
	if (rc < 0) {
		printf("Stop polling failed with error: \"%s\"\n",
								  strerror(rc));
		goto err3;
	}

err5:
	/* Release EMVCo L2 manager layer */
	l2manager_Release();

err4:
	/* Release exclusive access to the FEIG ContactLess Reader device 0 */
	rc = close(fd);
	if (rc < 0) {
		printf("close device failed with error: \"%s\"\n",
							       strerror(errno));
	}
err3:
	/* switch all leds off */
	leds_set(0);
	/* Release LEDs */
	leds_term();
err2:
	/* Release buzzer */
	buzzer_term();

err1:
	/* Release PKCS11 interface */
	logout_and_close_session(&hSession);

	//Send all offline accepted transactions to CC
//	if (rcTransaction == EMV_OFFLINE_ACCEPT) {
//		doSslCall(outputBuffer);
//	}

	//wait for thread to finish
	pthread_join(inc_x_thread,NULL);


	return rc;
}
