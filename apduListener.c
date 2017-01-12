/*
 * apduListener.c
 *
 *  Created on: 10 Oct 2016
 *      Author: steve
 */

#include<stdio.h>
#include<string.h>    //strlen
#include<stdint.h>
#include<sys/socket.h>
#include<arpa/inet.h> //inet_addr
#include<unistd.h>    //write
#include<feig/feclr.h>

#include "macros.h"

#include "conversions.h"

int client_sock, socket_desc, idx;
unsigned char rsp_buffer[258];
unsigned char out_buffer[258];
size_t rx_frame_size;
uint8_t rx_last_bits;
uint64_t status;
char *outputBuffer;

char *SELECT_EF_ID_INFO = "\x00\xA4\x00\x00\x02\x2F\xF7";
char *SELECT_EF_ACCESS = "\x00\xA4\x02\x0C\x02\x01\x1C";

#define WAIT_FOR_CARD_INSERTION_TIMEOUT	20000LL /* 0.2 seconds in us*/
#define WAIT_FOR_CARD_TIMEOUT	20000LL /* 0.2 seconds in us*/

fd_set read_flags,write_flags; // the flag sets to be used
struct timeval waitd = {0, 1};          // the max wait time for an event
int sel;                      // holds return value for select();

int setStatus(uint64_t newStatus)
{
	status = newStatus;
}

int socketListen()
{
	FD_ZERO(&read_flags);
	FD_ZERO(&write_flags);
	FD_SET(client_sock, &read_flags);
	FD_SET(client_sock, &write_flags);
	FD_SET(STDIN_FILENO, &read_flags);
	FD_SET(STDIN_FILENO, &write_flags);

	sel = select(client_sock+1, &read_flags, &write_flags, (fd_set*)0, &waitd);

	//if an error with select
	if(sel < 0)
		return 0;

	//socket ready for reading
	if(FD_ISSET(client_sock, &read_flags)) {
		printf("GOT SOCKET MESSAGE...\n");
		//clear set
		FD_CLR(client_sock, &read_flags);
		return 1;
	}

	return 0;
}


int socketInitialise()
{
    int c;
    struct sockaddr_in server , client;
    unsigned char client_message[200];

    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");

    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 8888 );

    int yes;

    if ( setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0 )
    {
        perror("setsockopt SO_REUSEADDR. Error");
    }

    //Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        //print the error message
        perror("bind failed. Error");
        return 1;
    }
    puts("bind done");

    //Listen
    listen(socket_desc , 3);

    //Accept incoming connection
    puts("Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);

    //accept connection from an incoming client
    client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
    if (client_sock < 0)
    {
        perror("accept failed");
        return 1;
    }
    puts("Connection accepted");

    return 0;
}

int socketRead(int fd, union tech_data *tech_data)
{
	struct timeval firstResp;
	uint64_t tech;
    int c , read_size;
    struct sockaddr_in client;
    unsigned char client_message[200];
    unsigned char defaultResponse[] = {0x5F,0x81,0x81,0x04,0x04,0x00,0x00,0x00,0x00}; //Antenna Off
    unsigned char pollResponse[] = {0x5F,0x81,0x81,0x01,0x00,0x02,0x00}; //Poll for card response
    unsigned char straightResponse[] = {0x5F,0x84,0x81,0x15,0x00,0xFE}; //Straight through response
    unsigned char cardPresentResponse[] = {0x5F,0x81,0x81,0x01,0x02,0x06,0x01}; //Card Present response
    unsigned char cardSwappedResponse[] = {0x5F,0x81,0x81,0x01,0x02,0x06,0xEE}; //Card Swapped response
    unsigned char cardNotPresentPollResponse[] = {0x5F,0x81,0x81,0x01,0x02,0x02,0xFF}; //Card Not Present response
    unsigned char cardNotPresentResponse[] = {0x5F,0x81,0x81,0x01,0x02,0x06,0xFF}; //Card Not Present response

    unsigned char desfireWrapper[] = {0x90,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	int tlvTag;
	int tlvLength;
	int tlvCommand;
	int tlvValuePointer;
	int tlvValueOffset;

	//***************TEST APDU COMMANDS
	char *GET_CHALLENGE = "\x00\x84\x00\x00\x08";
	int rc = 0;
	int count = 0;
	asprintf(&outputBuffer, "");
	unsigned char inputBuffer[128];
	//********************************

	memset(&client_message, 0, sizeof(client_message));

    //Receive a message from client
    while( (read_size = recv(client_sock , client_message , 200 , 0)) >= 0 )
    {
    	if (read_size == 0){
    			printf("connection timeout - wait again\n");
    		 	 puts("Waiting for incoming connections...");
    		 	 //accept connection from an incoming client
    		    client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
    		    printf("Connection accepted\n");
    		    return 0;
    	}

    	printf("INPUT DATA: ");
		for (idx = 0; idx < read_size; idx++){
				printf("%02X ", client_message[idx]);
		}
    	printf("\n");

    	parseTlvCommand(&client_message, sizeof(client_message), &tlvTag, &tlvLength,  &tlvCommand, &tlvValueOffset);
		printf("TAG: %02X\n", tlvTag);
		printf("COMMAND: %02X\n", tlvCommand);
		printf("ACTUAL LEN: %02X\n", tlvLength);
		printf("OFFSET: %02X\n", tlvValueOffset);
		printf("ACTUAL VALUE: ");
		for (idx = 0; idx < tlvLength; idx++){
				printf("%02X ", client_message[idx+tlvValueOffset]);
		}
		printf("\n");

		if (tlvCommand == 0x200){

			/* DO SELECT TEST IF CARD PRESENT*/
			int idx = 0;
			rc = feclr_transceive(fd, 0,
									  SELECT_EF_ACCESS, 7, 0,
									  rsp_buffer, sizeof(rsp_buffer),
									  &rx_frame_size, &rx_last_bits,
									  0,
									  &status);
			if (rc < 0) {
				printf("SELECT Transceive failed with error: \"%s\"\n",
									  strerror(rc));
				status = FECLR_STS_TIMEOUT;
			}

			if (rx_frame_size == 0x00) {
				printf("card not Present \n");
				status = FECLR_STS_TIMEOUT;
				rx_frame_size =  sizeof(cardNotPresentPollResponse);
				memcpy(out_buffer, cardNotPresentPollResponse, rx_frame_size);
			} else {

				printf("POLL RESPONSE: 0x%02X\n", tlvCommand);

				printf("ATQ: ");
				for (idx = 0; idx < sizeof(tech_data->iso14443a_jewel.iso14443a.atqa); idx++) {
					printf("0x%02X ", tech_data->iso14443a_jewel.iso14443a.atqa[idx]);
				}
				printf("\n");

				printf("UID: ");
				for (idx = 0; idx < tech_data->iso14443a_jewel.iso14443a.uid_size; idx++) {
					printf("0x%02X ", tech_data->iso14443a_jewel.iso14443a.uid[idx]);
				}
				printf("\n");

				memcpy(&out_buffer[sizeof(pollResponse)+sizeof(tech_data->iso14443a_jewel.iso14443a.atqa)], tech_data->iso14443a_jewel.iso14443a.uid, tech_data->iso14443a_jewel.iso14443a.uid_size);
				memcpy(&out_buffer[sizeof(pollResponse)], tech_data->iso14443a_jewel.iso14443a.atqa, sizeof(tech_data->iso14443a_jewel.iso14443a.atqa));
				memcpy(out_buffer, pollResponse, sizeof(pollResponse));

				//update LENGTH to actual length of response + 2 for message byte and table line number
				out_buffer[4] = sizeof(tech_data->iso14443a_jewel.iso14443a.atqa)+tech_data->iso14443a_jewel.iso14443a.uid_size+2;
				rx_frame_size = sizeof(pollResponse)+sizeof(tech_data->iso14443a_jewel.iso14443a.atqa)+tech_data->iso14443a_jewel.iso14443a.uid_size;
			}
		} else if (tlvCommand == 0xFE) {
    		printf("COMMAND THROUGH MODE: 0x%02X\n", tlvCommand);

			printf("NATIVE: ");
			for (idx = 0; idx < tlvLength; idx++) {
				printf("0x%02X ", client_message[idx+tlvValueOffset]);
			}
			printf("\n");


			desfireWrapper[1] = client_message[tlvValueOffset];
			desfireWrapper[4] = tlvLength-1;
			desfireWrapper[tlvLength+4] = 0x00;
			memcpy(&desfireWrapper[5], &client_message[tlvValueOffset+1], tlvLength-1);

			//if only instruction byte do not add the SE byte
			if (tlvLength == 1){
				tlvLength = 0;
			}

			printf("desfireWrapper: ");
			for (idx = 0; idx < tlvLength+5; idx++) {
				printf("0x%02X ", desfireWrapper[idx]);
			}
			printf("\n");

			/* GET_CHALLENGE */
			int idx = 0;
			rc = feclr_transceive(fd, 0,
						  desfireWrapper, tlvLength+5, 0,
						  rsp_buffer, sizeof(rsp_buffer),
						  &rx_frame_size, &rx_last_bits,
						  0,
						  &status);
			if (rc < 0) {
				printf("GET_CHALLENGE Transceive failed with error: \"%s\"\n",
									  strerror(rc));
			}

			if (rx_frame_size == 0x00) {
				printf("card not Present \n");
				status = FECLR_STS_TIMEOUT;
				rx_frame_size =  sizeof(cardNotPresentResponse);
				memcpy(out_buffer, cardNotPresentResponse, rx_frame_size);
			} else {
				printf("PRE - R-APDU: ");

				for (idx = 0; idx < rx_frame_size; idx++) {
					printf("0x%02X ", rsp_buffer[idx]);
					asprintf(&outputBuffer, "%s%02X",outputBuffer,rsp_buffer[idx]);
				}

				printf("\n");

				printf("SW1 SW2: ");

				for (idx = rx_frame_size - 2; idx < rx_frame_size; idx++) {
					printf("0x%02X ", rsp_buffer[idx]);
					asprintf(&outputBuffer, "%s%02X",outputBuffer,rsp_buffer[idx]);
				}

				printf("\n");

				printf("SW2 = 0x%02X \n", rsp_buffer[rx_frame_size - 1]);

				out_buffer[sizeof(straightResponse)] = rsp_buffer[rx_frame_size - 1];

				memcpy(&out_buffer[sizeof(straightResponse)+1], rsp_buffer, rx_frame_size-2);
				memcpy(out_buffer, straightResponse, sizeof(straightResponse));

				//update LENGTH to actual length of response + 1 for message byte
				out_buffer[4] = rx_frame_size;
				rx_frame_size += sizeof(straightResponse)-1;
			}

    	} else if (tlvCommand == 0x600){
    		printf("COMMAND DETECT CARD GONE: 0x%02X\n", tlvCommand);
    		//TODO - detect if card is present

			/* DO SELECT TEST IF CARD PRESENT*/
			int idx = 0;
			rc = feclr_transceive(fd, 0,
									  SELECT_EF_ACCESS, 7, 0,
									  rsp_buffer, sizeof(rsp_buffer),
									  &rx_frame_size, &rx_last_bits,
									  0,
									  &status);
			if (rc < 0) {
				printf("SELECT Transceive failed with error: \"%s\"\n",
									  strerror(rc));
				status = FECLR_STS_TIMEOUT;
			}

			if (rx_frame_size != 0x00) {
				printf("card Present \n");
				rx_frame_size =  sizeof(cardPresentResponse);
				memcpy(out_buffer, cardPresentResponse, rx_frame_size);
			} else {
				printf("card not Present \n");
				status = FECLR_STS_TIMEOUT;
				rx_frame_size =  sizeof(cardNotPresentResponse);
				memcpy(out_buffer, cardNotPresentResponse, rx_frame_size);
			}

    	} else {
			rx_frame_size =  sizeof(defaultResponse);
			memcpy(out_buffer, defaultResponse, rx_frame_size);
    	}

		if (socketWrite() == -1){
			return 0;
		}

        memset(&client_message, 0, sizeof(client_message));
        asprintf(&outputBuffer, "");
    }

    if(read_size == 0)
    {
        puts("Client disconnected");
        fflush(stdout);
    }
    else if(read_size == -1)
    {
        perror("recv failed");
    }

    return 0;
}

int socketReadMifare(int fd, union tech_data *tech_data)
{
	struct timeval firstResp;
	uint64_t tech;
    int c , read_size;
    struct sockaddr_in client;
    unsigned char client_message[200];
    unsigned char defaultResponse[] = {0x5F,0x81,0x81,0x04,0x04,0x00,0x00,0x00,0x00}; //Antenna Off
    unsigned char pollResponse[] = {0x5F,0x81,0x81,0x01,0x00,0x02,0x00}; //Poll for card response
    unsigned char straightResponse[] = {0x5F,0x84,0x81,0x15,0x00,0xFE}; //Straight through response
    unsigned char cardPresentResponse[] = {0x5F,0x81,0x81,0x01,0x02,0x06,0x01}; //Card Present response
    unsigned char cardSwappedResponse[] = {0x5F,0x81,0x81,0x01,0x02,0x06,0xEE}; //Card Swapped response
    unsigned char cardNotPresentPollResponse[] = {0x5F,0x81,0x81,0x01,0x02,0x02,0xFF}; //Card Not Present response
    unsigned char cardNotPresentResponse[] = {0x5F,0x81,0x81,0x01,0x02,0x06,0xFF}; //Card Not Present response

    unsigned char desfireWrapper[] = {0x90,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	int tlvTag;
	int tlvLength;
	int tlvCommand;
	int tlvValuePointer;
	int tlvValueOffset;

	//***************TEST APDU COMMANDS
	char *GET_CHALLENGE = "\x00\x84\x00\x00\x08";
	int rc = 0;
	int count = 0;
	asprintf(&outputBuffer, "");
	unsigned char inputBuffer[128];
	//********************************

	memset(&client_message, 0, sizeof(client_message));

    //Receive a message from client
    while( (read_size = recv(client_sock , client_message , 200 , 0)) >= 0 )
    {
    	if (read_size == 0){
    			printf("connection timeout - wait again\n");
    		 	 puts("Waiting for incoming connections...");
    		 	 //accept connection from an incoming client
    		    client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
    		    printf("Connection accepted\n");
    		    return 0;
    	}

    	printf("INPUT DATA: ");
		for (idx = 0; idx < read_size; idx++){
				printf("%02X ", client_message[idx]);
		}
    	printf("\n");

    	parseTlvCommand(&client_message, sizeof(client_message), &tlvTag, &tlvLength,  &tlvCommand, &tlvValueOffset);
		printf("TAG: %02X\n", tlvTag);
		printf("COMMAND: %02X\n", tlvCommand);
		printf("ACTUAL LEN: %02X\n", tlvLength);
		printf("OFFSET: %02X\n", tlvValueOffset);
		printf("ACTUAL VALUE: ");
		for (idx = 0; idx < tlvLength; idx++){
				printf("%02X ", client_message[idx+tlvValueOffset]);
		}
		printf("\n");

		if (tlvCommand == 0x200){

			/* DO SELECT TEST IF CARD PRESENT*/
			int idx = 0;
			rc = feclr_transceive(fd, 0,
									  SELECT_EF_ACCESS, 7, 0,
									  rsp_buffer, sizeof(rsp_buffer),
									  &rx_frame_size, &rx_last_bits,
									  0,
									  &status);
			if (rc < 0) {
				printf("SELECT Transceive failed with error: \"%s\"\n",
									  strerror(rc));
				status = FECLR_STS_TIMEOUT;
			}

			if (rx_frame_size == 0x00) {
				printf("card not Present \n");
				status = FECLR_STS_TIMEOUT;
				rx_frame_size =  sizeof(cardNotPresentPollResponse);
				memcpy(out_buffer, cardNotPresentPollResponse, rx_frame_size);
			} else {

				printf("POLL RESPONSE: 0x%02X\n", tlvCommand);

				printf("ATQ: ");
				for (idx = 0; idx < sizeof(tech_data->iso14443a_jewel.iso14443a.atqa); idx++) {
					printf("0x%02X ", tech_data->iso14443a_jewel.iso14443a.atqa[idx]);
				}
				printf("\n");

				printf("UID: ");
				for (idx = 0; idx < tech_data->iso14443a_jewel.iso14443a.uid_size; idx++) {
					printf("0x%02X ", tech_data->iso14443a_jewel.iso14443a.uid[idx]);
				}
				printf("\n");

				memcpy(&out_buffer[sizeof(pollResponse)+sizeof(tech_data->iso14443a_jewel.iso14443a.atqa)], tech_data->iso14443a_jewel.iso14443a.uid, tech_data->iso14443a_jewel.iso14443a.uid_size);
				memcpy(&out_buffer[sizeof(pollResponse)], tech_data->iso14443a_jewel.iso14443a.atqa, sizeof(tech_data->iso14443a_jewel.iso14443a.atqa));
				memcpy(out_buffer, pollResponse, sizeof(pollResponse));

				//update LENGTH to actual length of response + 2 for message byte and table line number
				out_buffer[4] = sizeof(tech_data->iso14443a_jewel.iso14443a.atqa)+tech_data->iso14443a_jewel.iso14443a.uid_size+2;
				rx_frame_size = sizeof(pollResponse)+sizeof(tech_data->iso14443a_jewel.iso14443a.atqa)+tech_data->iso14443a_jewel.iso14443a.uid_size;
			}
		} else if (tlvCommand == 0xFE) {
    		printf("COMMAND THROUGH MODE: 0x%02X\n", tlvCommand);

			printf("NATIVE: ");
			for (idx = 0; idx < tlvLength; idx++) {
				printf("0x%02X ", client_message[idx+tlvValueOffset]);
			}
			printf("\n");

			int idx = 0;
			rc = feclr_transceive(fd, 0,
						  client_message, tlvLength, 0,
						  rsp_buffer, sizeof(rsp_buffer),
						  &rx_frame_size, &rx_last_bits,
						  0,
						  &status);

			printf("RAW Transceive rc: \"%s\"\n",
												  strerror(rc));
			printf("RAW Transceive status: \"%s\"\n",
					status);

			if (rc < 0) {
				printf("Transceive failed with error: 0x%02X \n",
						status);
			}

			if (rx_frame_size == 0x00) {
				printf("card not Present \n");
				status = FECLR_STS_TIMEOUT;
				rx_frame_size =  sizeof(cardNotPresentResponse);
				memcpy(out_buffer, cardNotPresentResponse, rx_frame_size);
			} else {
				printf("PRE - R-APDU: ");

				for (idx = 0; idx < rx_frame_size; idx++) {
					printf("0x%02X ", rsp_buffer[idx]);
					asprintf(&outputBuffer, "%s%02X",outputBuffer,rsp_buffer[idx]);
				}

				printf("\n");

				printf("SW1 SW2: ");

				for (idx = rx_frame_size - 2; idx < rx_frame_size; idx++) {
					printf("0x%02X ", rsp_buffer[idx]);
					asprintf(&outputBuffer, "%s%02X",outputBuffer,rsp_buffer[idx]);
				}

				printf("\n");

				printf("SW2 = 0x%02X \n", rsp_buffer[rx_frame_size - 1]);

				out_buffer[sizeof(straightResponse)] = rsp_buffer[rx_frame_size - 1];

				memcpy(&out_buffer[sizeof(straightResponse)+1], rsp_buffer, rx_frame_size-2);
				memcpy(out_buffer, straightResponse, sizeof(straightResponse));

				//update LENGTH to actual length of response + 1 for message byte
				out_buffer[4] = rx_frame_size;
				rx_frame_size += sizeof(straightResponse)-1;
			}

    	} else if (tlvCommand == 0x600){
    		printf("COMMAND DETECT CARD GONE: 0x%02X\n", tlvCommand);
    		//TODO - detect if card is present

			/* DO SELECT TEST IF CARD PRESENT*/
			int idx = 0;
			rc = feclr_transceive(fd, 0,
									  SELECT_EF_ACCESS, 7, 0,
									  rsp_buffer, sizeof(rsp_buffer),
									  &rx_frame_size, &rx_last_bits,
									  0,
									  &status);
			if (rc < 0) {
				printf("SELECT Transceive failed with error: \"%s\"\n",
									  strerror(rc));
				status = FECLR_STS_TIMEOUT;
			}

			if (rx_frame_size != 0x00) {
				printf("card Present \n");
				rx_frame_size =  sizeof(cardPresentResponse);
				memcpy(out_buffer, cardPresentResponse, rx_frame_size);
			} else {
				printf("card not Present \n");
				status = FECLR_STS_TIMEOUT;
				rx_frame_size =  sizeof(cardNotPresentResponse);
				memcpy(out_buffer, cardNotPresentResponse, rx_frame_size);
			}

    	} else {
			rx_frame_size =  sizeof(defaultResponse);
			memcpy(out_buffer, defaultResponse, rx_frame_size);
    	}

		if (socketWrite() == -1){
			return 0;
		}

        memset(&client_message, 0, sizeof(client_message));
        asprintf(&outputBuffer, "");
    }

    if(read_size == 0)
    {
        puts("Client disconnected");
        fflush(stdout);
    }
    else if(read_size == -1)
    {
        perror("recv failed");
    }

    return 0;
}

int socketWrite()
{
		if (status == FECLR_STS_OK || status == FECLR_STS_TIMEOUT || status == 0xC038FE02) {
			printf("R-APDU: ");
			for (idx = 0; idx < rx_frame_size; idx++) {
				printf("0x%02X ", out_buffer[idx]);
				asprintf(&outputBuffer, "%s%02X",outputBuffer,rsp_buffer[idx]);
			}
			printf("\n");

	        //Send the message back to client

	        if( send(client_sock , out_buffer , rx_frame_size , MSG_NOSIGNAL) <= 0)
	        {
	            puts("Send failed");
	            return 1;
	        }

	 	} else {
			 printf("*NO CARD ERROR\n");
			 return -1;
		}

		if (status == FECLR_STS_TIMEOUT) {
			printf("*NO CARD DETECTED\n");
			return -1;
		}

    return 0;
}

int parseTlvCommand(unsigned char *buffer, int length, int *tlvTag, int *tlvLength, int *tlvCommand, int *tlvValueOffset) {

		int startBuffer = (intptr_t)buffer;
        // Get tag
        int tag=*(buffer++);
        int tagLength,tmp;
        length--;
        if((tag&0x1F)==0x1F) {
            if((length--)==0) return -1;
            tag=(tag<<8)|*(buffer++);
            if((tag&0x80)==0x80) {
                if((length--)==0) return -1;
                tag=(tag<<8)|*(buffer++);
                if((tag&0x80)==0x80) {
                    if((length--)==0) return -1;
                    tag=(tag<<8)|*(buffer++);
                    if((tag&0x80)==0x80) {
                        // Longer than 4 byte tags are NOT supported
                        return -1;
                    }
                }
            }
        } else {
            if(tag==0) {
            	return -1;
            }
        }

        (*tlvTag) = tag;

        // Get length
        if((length--)==0) return -1;
        tmp=*(buffer++);
        tagLength=0;

        switch(tmp) {
            case 0x84:
                if((length--)==0) return -1;
                tagLength=*(buffer++);
                /* no break */
            case 0x83:
                if((length--)==0) return -1;
                tagLength=(tagLength<<8)|*(buffer++);
                /* no break */
            case 0x82:
                if((length--)==0) return -1;
                tagLength=(tagLength<<8)|*(buffer++);
                /* no break */
            case 0x81:
                if((length--)==0) return -1;
                tagLength=(tagLength<<8)|*(buffer++);
                break;
            default:
                if(tmp>=0x80) {
                    // Other 8x variants are NOT supported
                    return -1;
                }
                tagLength=tmp;
                break;
        }



    	if ((*tlvTag) == 0x5F818101 && tagLength >= 0x02){
//    		tlvCommand=(tlvtest[tlvValueOffset]<<8)|tlvtest[tlvValueOffset+1];
//    		commandOffset = 0x02;
    		(*tlvCommand)=*(buffer++);
    		(*tlvCommand)=((*tlvCommand)<<8)|*(buffer++);
    		tagLength--;
    		tagLength--;

    		if ((*tlvCommand) == 0x0200){
    			printf("COMMAND POLL: %02X\n", (*tlvCommand));
    		}
    		if ((*tlvCommand) == 0x0400){
    			printf("COMMAND LOAD TABLE: %02X\n", (*tlvCommand));
    		}
    		if ((*tlvCommand) == 0x0000){
    			printf("COMMAND ANTENNA OFF: %02X\n", (*tlvCommand));
    		}
    	}

    	if ((*tlvTag) == 0x5F848115 && tagLength >= 0x01){
//    		tlvCommand=tlvtest[tlvValueOffset];
//    		commandOffset = 0x01;
    		(*tlvCommand)=*(buffer++);
    		tagLength--;
    		if ((*tlvCommand) == 0xFE){
    			printf("COMMAND THROUGH MODE: %02X\n", (*tlvCommand));
    		}
    	}

    	(*tlvLength) = tagLength;

        (*tlvValueOffset) = (intptr_t)buffer - startBuffer;

        // Check value
        if(tagLength>length) return -1;

    return 0;
}
