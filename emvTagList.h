#ifndef EMVTAGLIST_H
#define EMVTAGLIST_H

#include "tlv.h"

void  emvparse(unsigned char arr[], unsigned short size, tlvInfo_t * t, int * tindex, int index, char **outputBuffer, char **secureOutputBuffer);

#endif //EMVTAGLIST_H
