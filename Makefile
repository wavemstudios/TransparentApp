CC=arm-linux-gcc

all:executable

debug: CC += -g -DDEBUG
debug: executable

executable: PaymentSample.c
	rm -f PaymentSample emvPaymentApp.o sslCall.o emvTagList.o asn1.o tlv.o emvPaymentLib.a
	$(CC) -c emvPaymentApp.c -o emvPaymentApp.o
	$(CC) -c sslCall.c -o sslCall.o
	$(CC) -c emvTagList.c -o emvTagList.o
	$(CC) -c asn1.c -o asn1.o
	$(CC) -c tlv.c -o tlv.o
	$(CC) -c dukpt.c -o dukpt.o
	$(CC) -c sha256.c -o sha256.o
	$(CC) -c conversions.c -o conversions.o
	ar -cvq emvPaymentLib.a emvPaymentApp.o sslCall.o emvTagList.o asn1.o tlv.o dukpt.o sha256.o conversions.o
	$(CC) PaymentSample.c emvTagList.c ledBuzzerController.c apduListener.c emvPaymentLib.a -o TransparentSample -lfeclr -lleds -lbuzzer -lL2Manager -lL2Base -lL2PayPass -lL2Paywave -lL2Entrypoint -lL2ExpressPay -lL2Discover -lL2FeigHAL -lfememcard -lpthread -lssl -lfepkcs11 -lcrypto
	fesign --module opensc-pkcs11.so --pin 648219 --slotid 1 --keyid 00a0 --infile TransparentSample
	
.PHONY: clean
clean:
	rm -f TransparentSample TransparentSample.backup emvPaymentApp.o sslCall.o emvTagList.o asn1.o tlv.o dukpt.o sha256.o emvPaymentLib.a
