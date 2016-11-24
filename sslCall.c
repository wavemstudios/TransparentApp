#include <stdio.h> /* printf, sprintf */
#include <stdlib.h> /* exit, atoi, malloc, free */
#include <unistd.h> /* read, write, close */
#include <string.h> /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netdb.h> /* struct hostent, gethostbyname */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include "sslCall.h"

#include "macros.h"

int doSslCall(char *body)
{

	//Curl call
	//curl -i -X POST -H "Content-Type: text/xml" -d "<Request type=\"CardEaseXML\" version=\"1.0.0\"></Request>"


    struct hostent *server;
    struct sockaddr_in serv_addr;
    int retval, sent, received, total, message_size;
    char *message;
    char response[4096];
    int portno = 443; 	// 80 HTTP - 443 HTTPS
    char *host = "test.cardeasexml.com";
//    char *host = "google.com";

 //****** TEST
 //   server = gethostbyname(host);
 //   printf("Hostname: %s\n", server->h_name);
 //   printf("IP Address: %s\n", inet_ntoa(*((struct in_addr *)server->h_addr)));
 //***********
    char *path = "/generic.cex";
    char *method = "POST";
    char *headers = "Content-Type: text/xml\n";
 //   char *body = "<Request type=\"CardEaseXML\" version=\"1.0.0\"></Request>";
    /* How big is the message? */
    message_size=0;
	printf("Workout size message\n");
	message_size+=strlen("%s %s HTTP/1.1\nHOST: %s\n");
	message_size+=strlen(method);                      	/* method         */
	message_size+=strlen(path);         				/* path           */
	message_size+=strlen(headers);                  	/* headers        */
	message_size+=strlen("Content-length: %d\n")+30; 	/* content length */
	message_size+=strlen("\n");                      	/* blank line     */
	message_size+=strlen(body);                     	/* body           */

	printf("Allocating...\n");
	/* allocate space for the message */
	message=malloc(message_size);


	sprintf(message,"%s %s HTTP/1.1\nHOST: %s\n",method,path,host);                                        /* path           */
	strcat(message,headers);
	sprintf(message,"%scontent-length: %d\n",message,strlen(body));
	strcat(message,"\r\n");                                /* blank line     */
	strcat(message,body);                           /* body           */

    printf("Processed\n");
    /* What are we going to send? */
    printf("Request:\n%s\n",message);
    /* lookup the ip address */

    total = strlen(message);
    /* create the socket */

    int sockfd;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0){
    	printf("ERROR opening socket\n");
    	free(message);
    	return -1;
    }

    server = gethostbyname(host);
     if (server == NULL){
     	printf("ERROR, no such host\n");
     	free(message);
     	return -1;
     }

    /* fill in the structure */
	memset(&serv_addr,0,sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(portno);
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
			/* connect the socket */
	if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0){
		printf("ERROR connecting\n");
    	free(message);
    	return -1;
	}

	/* send the request */

     // initialize OpenSSL - do this once and stash ssl_ctx in a global var
	 SSL_load_error_strings ();
	 SSL_library_init ();
	 SSL_CTX *ssl_ctx = SSL_CTX_new (TLSv1_2_method ());

	 //UPDATE Creditcall uses TLS v1.2 - we should try call TLSv1_2_method and not SSLv23_client_method

	 // create an SSL connection and attach it to the socket
	 SSL *SSLconn = SSL_new(ssl_ctx);
	 SSL_set_fd(SSLconn, sockfd);

	 SSL_connect(SSLconn);

	retval = SSL_write(SSLconn,message,total);
	if (retval == 0){
		printf("ERROR writing message to SSL socket = 0\n");
		free(message);
		return -1;
	} else if (retval < 0){
		printf("ERROR writing message to SSL socket < 0\n");
		free(message);
		return -1;
	}

    /* receive the response */
    memset(response, 0, sizeof(response));
    total = sizeof(response)-1;
    received = 0;
    printf("Response: \n");

    retval = SSL_read(SSLconn, response, 1024);

    if (retval == 0){
    	printf("ERROR reading message from SSL socket = 0\n");
   		free(message);
   		return -1;
   	} else if (retval < 0){
   		printf("ERROR reading message from SSL socket < 0\n");
   		free(message);
   		return -1;
   	}

    if (received == total){
        error("ERROR storing complete response from socket\n");
        free(message);
        return -1;
    }

    printf("%s", response);

    SSL_shutdown(SSLconn);
    SSL_free(SSLconn);

    /* close the socket */
    close(sockfd);

    free(message);

    return 0;
}
