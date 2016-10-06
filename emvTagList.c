#include "emvTagList.h"
#include <stdlib.h>
#include <stdio.h>
#include <emv-l2/l2errors.h>

#include "macros.h"

#define CONSTRUCTED 1
#define PRIMITIVE 0
#define ISSUER 2
#define ICC 1
#define TERMINAL 0

void emvparse(unsigned char arr[], unsigned short size, tlvInfo_t * t, int * tindex, int index, char **clearTagBuffer, char **sesitiveTagBuffer){
		int j;
		t[*tindex].tlv =  *tlv_parse(arr, &index);

		if (0x5A == t[*tindex].tlv.Tag || 0x5F24 == t[*tindex].tlv.Tag || 0x57 == t[*tindex].tlv.Tag){
			if (0x57 != t[*tindex].tlv.Tag){

				asprintf(&*sesitiveTagBuffer, "%s%02X%02X", *sesitiveTagBuffer, t[*tindex].tlv.Tag,t[*tindex].tlv.Len);
				for(j=0; j< t[*tindex].tlv.Len; j++){
					asprintf(&*sesitiveTagBuffer, "%s%02X", *sesitiveTagBuffer, t[*tindex].tlv.Val[j]);
				}

			}
		} else {
			asprintf(&*clearTagBuffer, "%s<ICCTag tagid=\"0x%02X\">", *clearTagBuffer, t[*tindex].tlv.Tag);

			//printf("Len: %X\n", t[*tindex].tlv.Len);


			for(j=0; j< t[*tindex].tlv.Len; j++){
					//		printf("%X", t[*tindex].tlv.Val[j]);
							asprintf(&*clearTagBuffer, "%s%02X", *clearTagBuffer, t[*tindex].tlv.Val[j]);
						}

			asprintf(&*clearTagBuffer, "%s</ICCTag>\n", *clearTagBuffer);
		}

		*tindex +=1;

		if(t[*tindex-1].PC == CONSTRUCTED){
		 	emvparse(t[*tindex-1].tlv.Val, \
				t[*tindex-1].tlv.Len, t, tindex, 0, &*clearTagBuffer, &*sesitiveTagBuffer);
		}

		if(index >= size){
			return;
		}
		{ //several consecutive primite tlv's
			return emvparse(&arr[index], size-index , t, tindex, 0, &*clearTagBuffer, &*sesitiveTagBuffer);
		}
}

void formatOutputBuffer(char **outputBuffer, unsigned char *hexKsn, char **clearTagBuffer, unsigned char *encryptedHexBuffer, int rcTransaction, unsigned char *hexToken){

			asprintf(&*outputBuffer, "<Request type=\"CardEaseXML\" version=\"1.0.0\">\n");
			asprintf(&*outputBuffer, "%s<TransactionDetails>\n",*outputBuffer);
			asprintf(&*outputBuffer, "%s<LocalDateTime format=\"yyyyMMddHHmmss\">20160624105000</LocalDateTime>\n",*outputBuffer);
			if (rcTransaction == EMV_OFFLINE_ACCEPT) {
				asprintf(&*outputBuffer, "%s<MessageType>Offline</MessageType>\n",*outputBuffer);
			} else {
				asprintf(&*outputBuffer, "%s<MessageType>Auth</MessageType>\n",*outputBuffer);
			}
			asprintf(&*outputBuffer, "%s<Amount>777</Amount>\n",*outputBuffer);
			asprintf(&*outputBuffer, "%s<Reference>%s</Reference>\n",*outputBuffer,hexToken);
			asprintf(&*outputBuffer, "%s<ExtendedPropertyList>\n",*outputBuffer);
			asprintf(&*outputBuffer, "%s<ExtendedProperty id=\"dukptksn\">%s</ExtendedProperty>\n",*outputBuffer,hexKsn);
			asprintf(&*outputBuffer, "%s<ExtendedProperty id=\"dukptiv\">0000000000000000</ExtendedProperty>\n",*outputBuffer);
			asprintf(&*outputBuffer, "%s<ExtendedProperty id=\"dukptproduct\">CC01</ExtendedProperty>\n",*outputBuffer);
			asprintf(&*outputBuffer, "%s</ExtendedPropertyList>\n",*outputBuffer);
			asprintf(&*outputBuffer, "%s</TransactionDetails>\n",*outputBuffer);
			asprintf(&*outputBuffer, "%s<TerminalDetails>\n",*outputBuffer);
			asprintf(&*outputBuffer, "%s<TerminalID>99962873</TerminalID>\n",*outputBuffer);
			asprintf(&*outputBuffer, "%s<TransactionKey>3uZwVaSDzfU4xqHH</TransactionKey>\n",*outputBuffer);
			asprintf(&*outputBuffer, "%s</TerminalDetails>\n",*outputBuffer);
			asprintf(&*outputBuffer, "%s<CardDetails>\n",*outputBuffer);
			asprintf(&*outputBuffer, "%s<ICC type=\"EMV\">\n",*outputBuffer);
			asprintf(&*outputBuffer, "%s<ICCTag tagid=\"ENCRYPTEDCARDDETAILS\">%s</ICCTag>\n",*outputBuffer,encryptedHexBuffer);
			asprintf(&*outputBuffer, "%s%s",*outputBuffer,*clearTagBuffer);
			asprintf(&*outputBuffer, "%s</ICC>\n",*outputBuffer);
			asprintf(&*outputBuffer, "%s</CardDetails>\n",*outputBuffer);
			asprintf(&*outputBuffer, "%s</Request>\n",*outputBuffer);
}

