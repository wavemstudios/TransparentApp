#ifndef EMVTAGLIST_H
#define EMVTAGLIST_H

#include "tlv.h"

void emvparse(unsigned char arr[], unsigned short size, tlvInfo_t * t, int * tindex, int index, char **clearTagBuffer, char **sesitiveTagBuffer);

void formatOutputBuffer(char **outputBuffer, unsigned char *hexKsn, char **clearTagBuffer, unsigned char *encryptedHexBuffer, int rcTransaction, unsigned char *panToken);

#endif //EMVTAGLIST_H
