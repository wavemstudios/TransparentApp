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
size_t rx_frame_size;
uint8_t rx_last_bits;
uint64_t status;
char *outputBuffer;

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

int socketRead(int fd)
{
    int c , read_size;
    struct sockaddr_in client;
    unsigned char client_message[200];

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
    		    continue;
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

    	if (tlvCommand == 0xFE){
    		printf("COMMAND THROUGH MODE: %02X\n", tlvCommand);
    	}

		printf("C-APDU: ");
		for (idx = 0; idx < tlvLength; idx++) {
			printf("0x%02X ", client_message[idx+tlvValueOffset]);
		}
		printf("\n");

		/* GET_CHALLENGE */
		int idx = 0;
		rc = feclr_transceive(fd, 0,
					  &client_message[tlvValueOffset], tlvLength, 0,
					  rsp_buffer, sizeof(rsp_buffer),
					  &rx_frame_size, &rx_last_bits,
					  0,
					  &status);
		if (rc < 0) {
			printf("GET_CHALLENGE Transceive failed with error: \"%s\"\n",
								  strerror(rc));
		}

		socketWrite();

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
		if (status == FECLR_STS_OK) {
			printf("R-APDU: ");
			for (idx = 0; idx < rx_frame_size; idx++) {
				printf("0x%02X ", rsp_buffer[idx]);
				asprintf(&outputBuffer, "%s%02X",outputBuffer,rsp_buffer[idx]);
			}
			printf("\n");

	        //Send the message back to client

	        if( send(client_sock , rsp_buffer , rx_frame_size , MSG_NOSIGNAL) <= 0)
	        {
	            puts("Send failed");
	            return 1;
	        }

	 	} else {
			 write(client_sock ,"NO CARD" , sizeof("NO CARD"));
			 printf("*NO CARD\n");
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
