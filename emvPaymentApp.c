/*
 * emvTransaction.c
 *
 *  Created on: 26 Jul 2016
 *      Author: steve
 */

#include <stdio.h>
#include "asn1.h"

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


