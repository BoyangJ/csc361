/*------------------------------
* Name: Boyang Jiao
* UvicID: V00800928
* Date: May 27, 2016
*
* client.c
* Description: HTTP client program
* CSC 361
* Instructor: Kui Wu
-------------------------------*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/* define maximal string and reply length, this is just an example.*/
/* MAX_RES_LEN should be defined larger (e.g. 4096) in real testing. */
#define MAX_STR_LEN 120
#define MAX_RES_LEN 4096

//default values for port number and page
#define DEFAULT_PORT_NUMBER 80
static const char DEFAULT_PAGE[] = "index.html";

#define DEBUG 0

//function prototypes
int writen(int sd, char *ptr, int size);
int readn(int sd, char *ptr, int size);

/* --------- Main() routine ------------
 * three main task will be executed:
 * accept the input URI and parse it into fragments for further operation
 * open socket connection with specified sockid ID
 * use the socket id to connect specified server
 * don't forget to handle errors
 */

main(int argc, char *argv[])
{
    char uri[MAX_STR_LEN];
    char hostname[MAX_STR_LEN];
    char hostaddr[MAX_STR_LEN];
    char identifier[MAX_STR_LEN];
    int sockid, port;

    //inform user if DEBUG is enabled
    if (DEBUG) {
        printf("DEBUG IS CURRENTLY ENABLED.\n");
        printf("\n");
    }

    //argument 1 is requested uri
    if (argc > 1) {
        strcpy(uri, argv[1]);
    } else {
        printf("Error: URI not provided.\n");
        exit(0);
    }

    parse_URI(uri, hostname, &port, identifier);

    sockid = open_connection(hostname, port, hostaddr);

    perform_http(sockid, identifier, hostaddr);
}

/*------ Parse an "uri" into "hostname" and resource "identifier" --------*/
parse_URI(char *uri, char *hostname, int *port, char *identifier)
{

    //input: [hostname]:[port]/[page]
    if (sscanf(uri, "http://%99[^:]:%i/%99[^\n]", hostname, port, identifier) == 3) 
    {

    //input: [hostname]/[page].          Default port number.
    } else if (sscanf(uri, "http://%99[^/]/%99[^\n]", hostname, identifier) == 2) {
        *port = DEFAULT_PORT_NUMBER;

    //input: [hostname]:[port].          Default page.
    } else if (sscanf(uri, "http://%99[^:]:%i[^\n]", hostname, port) == 2) {
        bzero(identifier, MAX_STR_LEN);
        strcpy(identifier, DEFAULT_PAGE);

    //input: [hostname].                 Default port number and page.
    } else if (sscanf(uri, "http://%99[^\n]", hostname) == 1) {
        *port = DEFAULT_PORT_NUMBER;
        bzero(identifier, MAX_STR_LEN);
        strcpy(identifier, DEFAULT_PAGE);

    //input does not match any; report error
    } else {
        printf("Error with input URI. Exiting.\n");
        exit(0);
    }

    //Debug printouts
    if (DEBUG) {
        printf("---URI Debug info---\n");
        printf("Hostname = %s\n", hostname);
        printf("Port = %d\n", *port);
        printf("Identifier = %s\n", identifier);
        printf("\n");
    }

}

perform_http(int sockid, char *identifier, char *hostaddr)
{
    /* connect to server and retrieve response */
    char sendline[MAX_STR_LEN];
    char recvline[MAX_RES_LEN];

    bzero(sendline, MAX_STR_LEN);
    bzero(recvline, MAX_RES_LEN);

    //create the HTTP request string
    snprintf(sendline, MAX_STR_LEN, "GET http://%s/%s HTTP/1.0\r\n\r\n", hostaddr, identifier);

    //create a copy of sendline to display as output
    //(this is only used for display output purposes)
    char sendline_copy[MAX_STR_LEN];
    strncpy(sendline_copy, sendline, strlen(sendline)-3);

    //Request begin.
    printf("---Request begin---\n");
    printf("%s\n", sendline_copy);
    printf("Host: %s\n", hostaddr);
    printf("\n");

    if ((writen(sockid, sendline, strlen(sendline)+1)) < 0) {
        printf("Error occurred while writing request on socket.\n");
        close(sockid);
        exit(0);
    }

    //Request end.
    printf("---Request end---\n");
    printf("HTTP request sent, awaiting response...\n");
    printf("\n");

    if ((readn(sockid, recvline, MAX_RES_LEN)) < 0) {
        printf("Error occurred while reading response on socket.\n");
        close(sockid);
        exit(0);
    }

    //response header and body separated by "\r\n\r\n"
    char *resp_header = recvline;
    char *resp_body;

    char *delim;
    delim = strstr(resp_header, "\r\n\r\n");
    resp_body = delim + 4;
    resp_header[strlen(resp_header) - strlen(delim)] = '\0';

    //Response header.
    printf("---Response header---\n");
    printf("%s\n", resp_header);
    printf("\n");

    //Response body.
    printf("---Response body---\n");
    printf("%s\n", resp_body);
    printf("\n");

    close(sockid);
}

/*---------------------------------------------------------------------------*
 *
 * open_conn() routine. It connects to a remote server on a specified port.
 *
 *---------------------------------------------------------------------------*/

int open_connection(char *hostname, int port, char *hostaddr)
{
    int sockfd;
    /* generate socket
     * connect socket to the host address
     */
    struct sockaddr_in server;

    //open the socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("Error creating socket.\n");
        exit(0);
    }

    bzero(&server, sizeof(server));

    //connection type is TCP
    server.sin_family = AF_INET;

    //set the server IP
    struct hostent *server_ent;

    //get host information by hostname
    server_ent = gethostbyname(hostname);
    if (server_ent == NULL)
    {
        printf("Error: Cannot find IP address with given hostname.\n");
        close(sockfd);
        exit(0);
    }  
    memcpy(&server.sin_addr, server_ent->h_addr, server_ent->h_length); //server IP

    strcpy(hostaddr, server_ent->h_name);

    //set the server port #
    server.sin_port = htons(port);

    //make sure connection did not fail or is refused
    if ( connect(sockfd, (struct sockaddr*) &server, sizeof(server)) < 0)
    {
        printf("Error: Connection failed.\n");
        close(sockfd);
        exit(0);
    }

    //Debug printouts if DEBUG is enabled.
    if (DEBUG) {
        printf("---TCP connection Debug info---\n");
        printf("sockfd = %d.\n", sockfd);
        printf("port = %d.\n", port);
        printf("h_name = %s\n", server_ent->h_name);
        printf("server IP = %s\n", inet_ntoa(server.sin_addr));
        printf("\n");
    }

    return sockfd;
}













