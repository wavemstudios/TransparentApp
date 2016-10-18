/*
 * dukpt.h
 *
 *  Created on: 9 Aug 2016
 *      Author: steve
 */

#ifndef DUKPT_H_
#define DUKPT_H_

int runDukptTest(void);
int dukptEncrypt(CK_SESSION_HANDLE hSession, unsigned char *icc, int iccSizeIn, unsigned char *hexKsn, unsigned char *hexBuffer);

#endif /* DUKPT_H_ */
