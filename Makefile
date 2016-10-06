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
	ar -cvq emvPaymentLib.a emvPaymentApp.o sslCall.o emvTagList.o asn1.o tlv.o dukpt.o sha256.o
	$(CC) PaymentSample.c emvTagList.c ledBuzzerController.c emvPaymentLib.a -o PaymentSample -lfeclr -lleds -lbuzzer -lL2Manager -lL2Base -lL2PayPass -lL2Paywave -lL2Entrypoint -lL2ExpressPay -lL2Discover -lL2FeigHAL -lfememcard -lpthread -lssl -lfepkcs11 -lcrypto
	fesign --module opensc-pkcs11.so --pin 648219 --slotid 1 --keyid 00a0 --infile PaymentSample
	
.PHONY: clean
clean:
	rm -f PaymentSample PaymentSample.backup emvPaymentApp.o sslCall.o emvTagList.o asn1.o tlv.o dukpt.o sha256.o emvPaymentLib.a
