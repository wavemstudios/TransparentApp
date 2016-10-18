/*
 * apduListener.c
 *
 *  Created on: 10 Oct 2016
 *      Author: steve
 */

#include<stdio.h>
#include<string.h>    //strlen
#include<sys/socket.h>
#include<arpa/inet.h> //inet_addr
#include<unistd.h>    //write
#include<feig/feclr.h>

#include "conversions.h"

int apduListener(int fd)
{
    int socket_desc , client_sock , c , read_size, idx;
    struct sockaddr_in server , client;
    char client_message[200];

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

	//***************TEST APDU COMMANDS
	char *GET_CHALLENGE = "\x00\x84\x00\x00\x08";
	unsigned char rsp_buffer[258];
	size_t rx_frame_size;
	uint8_t rx_last_bits;
	uint64_t status;
	int rc = 0;
	int count = 0;
	char *outputBuffer;
	asprintf(&outputBuffer, "");
	unsigned char inputBuffer[128];
	//********************************

	memset(&client_message, 0, sizeof(client_message));

    //Receive a message from client
    while( (read_size = recv(client_sock , client_message , 200 , 0)) >= 0 )
    {
    	if (read_size % 2){
    		printf("*Invalid request\n");
    		write(client_sock ,"Invalid request" , sizeof("Invalid request"));
    		continue;
    	}

    	if (read_size == 0){
    			printf("connection timeout - wait again\n");
    		 	 puts("Waiting for incoming connections...");
    		 	 //accept connection from an incoming client
    		    client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
    		    printf("Connection accepted\n");
    		    continue;
    	}

    	unsigned char *p_client_message = client_message;
    	//Convert HEX string into binary
        for( count=0; count<(read_size/2); count++ )
        {
        	//NOTE icc is a pointer
        	inputBuffer[count] = hex2bin( p_client_message );
        	p_client_message += 2;
        }

		printf("C-APDU: ");
		for (idx = 0; idx < read_size/2; idx++) {
			printf("0x%02X ", inputBuffer[idx]);
		}
		printf("\n");


		/* GET_CHALLENGE */
		int idx = 0;
		rc = feclr_transceive(fd, 0,
				inputBuffer, read_size/2, 0,
					  rsp_buffer, sizeof(rsp_buffer),
					  &rx_frame_size, &rx_last_bits,
					  0,
					  &status);
		if (rc < 0) {
			printf("GET_CHALLENGE Transceive failed with error: \"%s\"\n",
								  strerror(rc));
		}

		if (status == FECLR_STS_OK) {
			printf("R-APDU: ");
			for (idx = 0; idx < rx_frame_size; idx++) {
				printf("0x%02X ", rsp_buffer[idx]);
				asprintf(&outputBuffer, "%s%02X",outputBuffer,rsp_buffer[idx]);
			}
			printf("\n");

	        //Send the message back to client

	        write(client_sock , outputBuffer , rx_frame_size*2);

	        printf("*C-APDU: %s\n", client_message);
	        printf("*R-APDU: %s\n\n", outputBuffer);

		} else {
			 write(client_sock ,"NO CARD" , sizeof("NO CARD"));
			 printf("*NO CARD\n");
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
