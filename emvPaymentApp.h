/*
 * emvTransaction.h
 *
 *  Created on: 26 Jul 2016
 *      Author: steve
 */

#ifndef EMVPAYMENTAPP_H_
#define EMVPAYMENTAPP_H_
#include <emv-l2/l2base.h>

//Internal
int check_2pay_sys(unsigned char *rsp, int lr);
void print_UIRequest(UIRequest *UIRequestData);

//Callbacks
void SendL2UIOutcomeImplFeig(L2Outcome *pL2Outcome);
void SendTrack2DataImplFeig(uchar *uTrack2Data, int iLen);

int CardTransmitImplFeig(void *pl2, enum SSL2CommandTypes type,
				ushort nInputLength, uchar *pucInput,
				int *pnOutputLength, uchar *pucOutput,
				int nOutputBufferSize);

void UIRequestCallbackImplFeig(UIRequest *UIRequestData);
void PrintEMVCoL2Versions(void);

//Called From External
int SetEmvCallbacks(int fd);
int SetEmvL2Layers(int fd, CK_SESSION_HANDLE_PTR phSession);
int IsEMVCard(int fd, uint64_t *pStatus);
void DoEmvTransaction();
void ClearTransactionData();
void SetTransactionData();
void WaitEmvThreadFinnish();
void PrintEMVPaymentAppVersions();

#endif /* EMVPAYMENTAPP_H_ */
