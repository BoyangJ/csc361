Name: Boyang Jiao
UVicID: V00800928
Date: May 27, 2016
Course: CSC 361
Instructor: Kui Wu

Assignment 1: Web Client and Web Server

--------------------
--- INTRODUCTION ---
--------------------
This project involved creating a simple web client and simple web server which communicated through a TCP connection and socket programming.
Application-layer protocols included HTTP request primitives and responses.


---------------------------------
--- PROJECT FILE DESCRIPTIONS ---
---------------------------------
1. SimpClient.c - Code for the simple web client. This program accepts a URI as input, opens a socket, and uses a TCP connection to access the specified URI.
    Input format: http://[hostname]:[port]/[page]
        hostname - the host name of the desired server. Mandatory.
        port - the port number to connect to. Optional; default value is 80.
        page - the page you want to request. Optional; default value is "index.html".

    Output: The output is divided into four sections: Request begin, Request end, Response header, and Response body
        Request begin - the HTTP GET request that is sent on the socket
        Request end - message while awaiting response from the server
        Response header - the HTTP header of the response from the server
        Response body - the data of the response from the server
    The program will also output error messages when errors are encountered.

    EXAMPLE: $ ./SimpClient http://www.csc.uvic.ca:80/index.htm
         This will return a "HTTP/1.1 200 OK" message as the response header from the server.

    *In the code for SimpClient, setting the definition of the "DEBUG" value to 1 will allow debug info to be printed as output. By default, this is disabled.

2. SimpServer - Code for the simple web server. This program accepts two inputs, opens a socket to listen to, and uses a TCP connection to send requested files.
    Input format: [port] [directory]
        port - the port number the server will listen to. Optional; default value is 80.
        directory - the directory in which requested files are searched for. Optional; default value is "web".

    Output: The server program will only output errors or debug information, if enabled.

    EXAMPLE: $ ./SimpServer 9000 web
        This will open a socket on port 9000, and accept any incoming connections on that socket. Requested files will be searched for in the "web" directory.

    *In the code for SimpServer, setting the definition of the "DEBUG" value to 1 will allow debug info to be printed as output. By default, this is disabled.

3. util.c - Utility file that contains functions used by both SimpClient and SimpServer.

4. README.txt - This readme file. Contains project descriptions and instructions.

5. makefile - The make file used for easy compilation of the project files.

6. (directory) web - The directory containing a sample html file.

7. web/index.html - A sample html file.


-----------------------------------
--- HTTP Requests and Responses ---
-----------------------------------
SimpClient will send HTTP GET requests with the following format:
    GET http://[hostname]/[page] HTTP/1.0 \r\n\r\n

SimpServer will send HTTP responses with the "Date" and "Server" fields.
SimpServer will only send the following response codes and messages:
    HTTP/1.0 200 OK.
    [response body]

    HTTP/1.0 404 Not Found.

    HTTP/1.0 501 Not Implemented.


---------------------------
--- PROGRAM COMPILATION ---
---------------------------
A makefile has been included in the submission of this project, and can be used to easily compile all assets.

Instructions:
    1. In your terminal, switch to the project's directory.
    2. Type the command "make" to compile all the project files in accordance to the makefile.
        2a. (Alternative) The command "make -f makefile" will do the same thing.

Alternatively, the project files can be manually compiled separately with the following commands:
    1. "gcc SimpClient.c util.c -o SimpClient"
    2. "gcc SimpServer.c util.c -o SimpServer"


-------------------------
--- PROGRAM EXECUTION ---
-------------------------
Run the web server with command "$ ./SimpServer 9000 web"

In a separate terminal window, run the client with the router hostname, same port number, and desired page. "$ ./SimpClient http://10.10.1.100:9000/index.html"

This will return a 200 OK message from the server, and the contents of the web/index.html file will be outputted as well.


------------------
--- REFERENCES ---
------------------
Various sample code files from the UVic CSC 361 connex site were used, including:
client.c, server.c, util.c, Makefile.txt.

Assignment specifications file can also be found on connex.




