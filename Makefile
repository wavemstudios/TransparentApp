CC=arm-linux-gcc

all:executable

debug: CC += -g -DDEBUG
debug: executable

executable: PaymentSample.c
	$(CC) PaymentSample.c tlv.c emvTagList.c sslCall.c asn1.c -o PaymentSample -lfeclr -lfepkcs11 -lleds -lbuzzer -lL2Manager -lL2Base -lL2PayPass -lL2Paywave -lL2Entrypoint -lL2ExpressPay -lL2Discover -lL2FeigHAL -lfememcard -lpthread -lssl -lcrypto
	
.PHONY: clean
clean:
	rm PaymentSample PaymentSample.backup