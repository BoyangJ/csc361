/*------------------------------
* Name: Boyang Jiao
* UvicID: V00800928
* Date: May 27, 2016
*
* server.c
* Description: HTTP server program
* CSC 361
* Instructor: Kui Wu
-------------------------------*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAX_STR_LEN 4096         /* maximum string length */

//default server port number and directory
#define SERVER_PORT_ID 80
static const char SERVER_DEFAULT_DIRECTORY[] = "web";

#define DEBUG 0

//function prototypes
void cleanExit(int sockets[], int size);
void response200(int sockid, int newsockid, char *sendline);
void response404(int sockid, int newsockid, char *sendline);
void response501(int sockid, int newsockid, char *sendline);
void addServerInfo(char *sendline);
void addDateInfo(char *sendline);

int writen(int sd, char *ptr, int size);
int readn(int sd, char *ptr, int size);

/*---------------------main() routine--------------------------*
 * tasks for main
 * generate socket and get socket id,
 * max number of connection is 3 (maximum length the queue of pending connections may grow to)
 * Accept request from client and generate new socket
 * Communicate with client and close new socket after done
 *---------------------------------------------------------------------------*/

main(int argc, char *argv[])
{
    char directory[MAX_STR_LEN];
    int sockid, newsockid; /* return value of the accept() call */
    int port;

    struct sockaddr_in server;

    //inform user if DEBUG is enabled
    if (DEBUG) {
        printf("DEBUG IS CURRENTLY ENABLED.\n");
        printf("\n");
    }
	
    //input contains port number and directory
    if (argc > 2) {
    	port = atoi(argv[1]);
	strcpy(directory, argv[2]);

    //input only has port number, no directory
    } else if (argc > 1) {
        port = atoi(argv[1]);

        printf("Directory not input! Using default directory of \"%s\".\n", SERVER_DEFAULT_DIRECTORY);
	strcpy(directory, SERVER_DEFAULT_DIRECTORY);

    //input has no port number or directory
    } else if (argc == 1 ) {
        printf("Port number not input! Using default port number of %d.\n", SERVER_PORT_ID);
        port = SERVER_PORT_ID;

        printf("Directory not input! Using default directory of \"%s\".\n", SERVER_DEFAULT_DIRECTORY);
        strcpy(directory, SERVER_DEFAULT_DIRECTORY);

    } else {
        printf("Error: Port Number or Directory Name not provided.\n");
        cleanExit(NULL, 0);
    }

    //port = 0 if user inputs invalid port number
    //user also cannot enter a negative port number
    if (port <= 0) {
        printf("Invalid port number input! Using default port number of %d.\n", SERVER_PORT_ID);
        port = SERVER_PORT_ID;
    }

    //debug printouts
    if (DEBUG) {
        printf("---User input Debug info---\n");
	printf("port = %d\n", port);
	printf("directory = %s\n", directory);
        printf("\n");
    }

    bzero(&server, sizeof(server));

    //open the socket
    if ( (sockid = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Error creating socket.\n");
        cleanExit(NULL, 0);
    }

    //connection type is TCP
    server.sin_family = AF_INET;

    //server address
    server.sin_addr.s_addr = htons(INADDR_ANY);

    //server port
    server.sin_port = htons(port);

    //bind server info to opened socket
    if( bind(sockid, (struct sockaddr*) &server, sizeof(server)) < 0) {
        printf("Error: Cannot bind to socket.\n");

        int sockets[] = {sockid};
        cleanExit(sockets, sizeof(sockets)/sizeof(int));
    }

    //listen for connections on the socket
    if ((listen(sockid, 3)) < 0) {
        printf("Error occurred while listening to socket.\n");

        int sockets[] = {sockid};
        cleanExit(sockets, sizeof(sockets)/sizeof(int));
    }

    while (1)
    {
        //accept an incoming connection on the socket
        newsockid = accept(sockid, (struct sockaddr*) NULL, NULL);
        if (newsockid < 0) {
            printf("Error: Error accepting connection.\n");

            int sockets[] = {sockid};
            cleanExit(sockets, sizeof(sockets)/sizeof(int));
        }

        //process the incoming request and send a response
        perform_http(sockid, newsockid, directory);
 
        close(newsockid);      
    }
}

/*---------------------------------------------------------------------------*
 *
 * cleans up opened sockets when killed by a signal.
 *
 *---------------------------------------------------------------------------*/

void cleanExit(int sockets[], int size)
{
    int index;
    for (index = 0; index < size; index++) {
        printf("Closing socket %d.\n", sockets[index]);
        close(sockets[index]);
    }
    exit(0);
}

/*---------------------------------------------------------------------------*
 *
 * Accepts a request from "sockid" and sends a response to "sockid".
 *
 *---------------------------------------------------------------------------*/

perform_http(int sockid, int newsockid, char *directory)
{
    char recvline[MAX_STR_LEN];
    char sendline[MAX_STR_LEN];

    char hostname[MAX_STR_LEN];
    char method[MAX_STR_LEN];
    char identifier[MAX_STR_LEN];
    char protocol[MAX_STR_LEN];
    char protocol_version[MAX_STR_LEN];

    char filename[MAX_STR_LEN] = "";

    //read request from client on socket
    if ((read(newsockid, recvline, MAX_STR_LEN)) < 0) {
        printf("Error occurred while reading request on socket.\n");

        int sockets[] = {sockid, newsockid};
        cleanExit(sockets, sizeof(sockets)/sizeof(int));
    }

    if (sscanf(recvline, "%s http://%99[^/]/%s %99[^/]/%s[^\n]", method, hostname, identifier, protocol, protocol_version) != 5) {
        printf("Error: Bad request from client.\n");
        response404(sockid, newsockid, sendline);
        close(newsockid);
    }
    
    //check if http request is "GET"
    if (strcmp(method, "GET") != 0) {
        response501(sockid, newsockid, sendline);
    }

    //check if protocol is "HTTP"
    if (strcmp(protocol, "HTTP") != 0) {
        response501(sockid, newsockid, sendline);
    }

    //check if protocol_version is "1.0"
    if (strcmp(protocol_version, "1.0") != 0) {
        response501(sockid, newsockid, sendline);
    }

    //check if requested file exists    
    strcat(filename, directory);
    strcat(filename, "/");
    strcat(filename, identifier);

    if( access( filename, F_OK ) != -1 ) {
        //read the entire file and send as response body
        char *file_contents = 0;
        long length;
        FILE *f = fopen(filename, "rb");

        fseek (f, 0, SEEK_END);
        length = ftell (f);
        fseek (f, 0, SEEK_SET);
        file_contents = malloc (length);

        if (file_contents)
        {
            fread(file_contents, 1, length, f);
        }

        fclose (f);

        strcpy(sendline, file_contents);
        response200(sockid, newsockid, sendline);
    } else {
        response404(sockid, newsockid, sendline);
    }

    //debug printouts if DEBUG is enabled
    if (DEBUG) {
        printf("---HTTP request debug info---\n");
        printf("method = %s\n", method);
        printf("identifier = %s\n", identifier);
        printf("protocol = %s\n", protocol);
        printf("protocol_version = %s\n", protocol_version);
        printf("\n");
    }

}


void response200(int sockid, int newsockid, char *sendline) {
    char resp_header[MAX_STR_LEN];

    //resp_header contains the response header, and sendline contains the body
    strcpy(resp_header, "HTTP/1.0 200 OK.\r\n");

    addDateInfo(resp_header);
    addServerInfo(resp_header);
    strcat(resp_header, "\r\n");

    strcat(resp_header, sendline);
    strcpy(sendline, resp_header);

    if ((writen(newsockid, sendline, strlen(sendline)+1)) < 0) {
        printf("Error occurred while writing response on socket.\n");

        int sockets[] = {sockid, newsockid};
        cleanExit(sockets, sizeof(sockets)/sizeof(int));
    }
    close(newsockid);
}

void response404(int sockid, int newsockid, char *sendline) {
    //returns a 404 Not Found message as response
    strcpy(sendline, "HTTP/1.0 404 Not Found.\r\n");

    addDateInfo(sendline);
    addServerInfo(sendline);
    strcat(sendline, "\r\n");

    if ((writen(newsockid, sendline, strlen(sendline)+1)) < 0) {
        printf("Error occurred while writing response on socket.\n");
        
        int sockets[] = {sockid, newsockid};
        cleanExit(sockets, sizeof(sockets)/sizeof(int));
    }

    close(newsockid);
}

void response501(int sockid, int newsockid, char *sendline) {
    //returns a 501 Not Implemented message as response
    strcpy(sendline, "HTTP/1.0 501 Not Implemented.\r\n");

    addDateInfo(sendline);
    addServerInfo(sendline);
    strcat(sendline, "\r\n");

    if ((writen(newsockid, sendline, strlen(sendline)+1)) < 0) {
        printf("Error occurred while writing response on socket.\n");
        
        int sockets[] = {sockid, newsockid};
        cleanExit(sockets, sizeof(sockets)/sizeof(int));
    }
    close(newsockid);
}

void addServerInfo(char *sendline) {
    struct utsname server_info;
    uname(&server_info);

    strcat(sendline, "Server: ");
    strcat(sendline, server_info.nodename);
    strcat(sendline, "/");
    strcat(sendline, server_info.release);
    strcat(sendline, " (");
    strcat(sendline, server_info.sysname);
    strcat(sendline, ") \r\n");

}

void addDateInfo(char* sendline) {
    char buffer[MAX_STR_LEN];
    time_t now = time(0);
    struct tm tm = *gmtime(&now);
    strftime(buffer, sizeof buffer, "%a, %d %b %Y %H:%M:%S %Z", &tm);

    strcat(sendline, "Date: ");
    strcat(sendline, buffer);
    strcat(sendline, "\r\n");

}


