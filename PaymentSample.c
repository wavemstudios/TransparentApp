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
 *
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <execinfo.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <feig/feclr.h>
#include <feig/fememcard.h>

#include "macros.h"

#include "ledBuzzerController.h"
#include "emvPaymentApp.h"
#include "apduListener.h"

#define WAIT_FOR_CARD_INSERTION_TIMEOUT	20000LL /* 0.2 seconds in us*/
#define WAIT_FOR_CARD_REMOVAL_TIMEOUT	30000000LL /* 30 seconds in us*/

#define PAYMENT_APP_VERSION	"01.00.00"

#define EMV_ONLINE_SUCCESS	1    /* !< Force Valid Online Response */

#define FECLR_DEVICE		"/dev/feclr0" /* Card reader */

int verify_icc_response(unsigned char *rsp, int lr, unsigned short sw)
{
	unsigned short sw_rsp;

	if (lr < 2)
		return -1;

	sw_rsp = (rsp[lr - 2] << 8) | rsp[lr - 1];

	return sw_rsp == sw ? 0 : -1;
}

int main(int argc, char *argv[])
{
	struct timeval firstResp;
	union tech_data tech_data;
	uint64_t status, tech;

	int fd = 0;
	int rc = 0;

	bool isEMV = false;

	//****** Steve Added

	unsigned char cmd_buffer[261];
	unsigned char rsp_buffer[258];
	size_t rx_frame_size;
	uint8_t rx_last_bits;
	char *SELECT_EF_ID_INFO = "\x00\xA4\x00\x00\x02\x2F\xF7";
	char *SELECT_EF_ACCESS = "\x00\xA4\x02\x0C\x02\x01\x1C";

	int new_tag = 0, tag = 0;
	uint16_t tag_typ = FEMEMCARD_TAG_TYPE_UNKNOWN;

	//******************

	printf("Card reader version %s started\n\n", PAYMENT_APP_VERSION);

	PrintEMVPaymentAppVersions();

	/* Print EMVCo Kernel versions */
	PrintEMVCoL2Versions();

reset:
	/* Login to PKCS11 interface */
	rc = open_session_and_login();
	if (rc != EXIT_SUCCESS)
		return -1;

	/* Initialize buzzer interface */
	rc = initialise_buzzer();
	if (rc < 0) {
		printf("buzzer_init failed with error: \"%s\"\n", strerror(rc));
		goto err1;
	}

	/* Initialize led interface */
	rc = initialise_leds();
	if (rc < 0) {
		printf("led_init failed with error: \"%s\"\n", strerror(rc));
		goto err2;
	}

	startup_visualization();

	/* Acquire exclusive access to the FEIG ContactLess Reader device 0 */
	fd = open(FECLR_DEVICE, O_RDWR);
	if (fd < 0) {
		printf("Open device failed with error: \"%s\"\n",
							       strerror(errno));
		goto err3;
	}

	if (SetEmvL2Layers(fd)){
			goto err5;
	}

#ifdef DEBUG
	if (SetEmvCallbacks(fd)){
			goto err5;
	}
#endif

	//EMV SET START TRANSACTION
	ClearTransactionData();
	SetTransactionData();

start:

	socketInitialise();
	setStatus(FECLR_STS_TIMEOUT);

	disable_bar();
	enable_running_led();

	new_tag = 1;
	tag = 0;
	isEMV = false;
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

		if (socketListen()){
			int RestVal = socketRead(fd, &tech_data);
		}

		isEMV = false;
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
			if (status != FECLR_STS_TIMEOUT){
				printf("Wait for card failed with status: 0x%08llX\n", status);
			}
			continue;
		}

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

		int idx;

		if (tech & FECLR_TECH_ISO14443A){
			setStatus(FECLR_STS_OK);
			printf("ATQ: ");
				for (idx = 0; idx < sizeof(tech_data.iso14443a_jewel.iso14443a.atqa); idx++) {
					printf("0x%02X ", tech_data.iso14443a_jewel.iso14443a.atqa[idx]);
				}
			printf("\n");

			printf("UID: ");
				for (idx = 0; idx < tech_data.iso14443a_jewel.iso14443a.uid_size; idx++) {
					printf("0x%02X ", tech_data.iso14443a_jewel.iso14443a.uid[idx]);
				}
			printf("\n");

		} else if (tech & FECLR_TECH_ISO14443B){
			setStatus(FECLR_STS_OK);
			printf("TYPE B: ");
			printf("\n");
		} else {
			//NO Card
			setStatus(FECLR_STS_TIMEOUT);
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

		rc = IsEMVCard(fd,&status);

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

		if (rc == 1) {
			tag = 1;
			isEMV = true;
		} else {
			isEMV = false;
		}

//*********END TEST EMV CARD

//********* Test for other card types if NOT EMV

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
				printf("Transceive status: 0x%08llX\n", status);
				continue;
			}

			if (!verify_icc_response(rsp_buffer, rx_frame_size, 0x9000)) {
				/* ISO14443-4 detected */
				if (new_tag) {
					printf("ISO14443-4 cipurse detected\n");
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
				 printf("Transceive status: 0x%08llX\n", status);
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
						printf("mifare desfire detected\n");
					}

					//******* TEST APDU EXTRA COMMANDS

					int RestVal = socketRead(fd, &tech_data);

					//******************************

					tag = 1;
					visualization_mifare_desfire(&tag, &new_tag);
					continue;

				case FEMEMCARD_TAG_TYPE_MIFARE_PL_SL3:
					/* mifare plus detected */
					if (new_tag) {
						printf("mifare plus detected\n");
					}
					tag = 1;
					visualization_mifare_plus(&tag, &new_tag);
					continue;

				case FEMEMCARD_TAG_TYPE_MIFARE_EMULATION:
					/* mifare classic detected */
					if (new_tag) {
						printf("mifare classic emulation detected\n");
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
		DoEmvTransaction();

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
	logout_and_close_session();

	//Send all offline accepted transactions to CC
//	if (rcTransaction == EMV_OFFLINE_ACCEPT) {
//		doSslCall(outputBuffer);
//	}

	WaitEmvThreadFinnish();

	return rc;
}
