#include "emvTagList.h"
#include <stdlib.h>
#include <stdio.h>

#include "macros.h"

#define CONSTRUCTED 1
#define PRIMITIVE 0
#define ISSUER 2
#define ICC 1
#define TERMINAL 0

void emvparse(unsigned char arr[], unsigned short size, tlvInfo_t * t, int * tindex, int index, char **outputBuffer, char **secureOutputBuffer){
		int j;
		t[*tindex].tlv =  *tlv_parse(arr, &index);

		asprintf(&*outputBuffer, "%s<ICCTag tagid=\"0x%02X\">", *outputBuffer, t[*tindex].tlv.Tag);

		//printf("Len: %X\n", t[*tindex].tlv.Len);


		for(j=0; j< t[*tindex].tlv.Len; j++){
				//		printf("%X", t[*tindex].tlv.Val[j]);
						asprintf(&*outputBuffer, "%s%02X", *outputBuffer, t[*tindex].tlv.Val[j]);
					}

		asprintf(&*outputBuffer, "%s</ICCTag>\n", *outputBuffer);

		*tindex +=1;

		if(t[*tindex-1].PC == CONSTRUCTED){
		 	emvparse(t[*tindex-1].tlv.Val, \
				t[*tindex-1].tlv.Len, t, tindex, 0, &*outputBuffer, &*secureOutputBuffer);
		}

		if(index >= size){
			return;
		}
		{ //several consecutive primite tlv's
			return emvparse(&arr[index], size-index , t, tindex, 0, &*outputBuffer, &*secureOutputBuffer);
		}
}
