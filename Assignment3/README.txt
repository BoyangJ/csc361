Name: Boyang Jiao
UVicID: V00800928
Date: July 22, 2016
Course: CSC 361
Instructor: Kui Wu

Assignment 3: Analysis of IP Protocol

--------------------
--- INTRODUCTION ---
--------------------
This project involved creating a program to parse and analyse a traceroute trace file.
The following points of information were extracted from the trace file:
    source IP address, destination IP address, the IP address(es) of any intermediate routers in the traceroute, the protocols found in the IP headers, the number of fragments and the fragment offset of the traceroute datagram, and the average and standard deviation of the RTT between the source and each intermediate router.

Additionally, five traceroute files were all analysed using the program, and the results of each traceroute were compared.


---------------------------------
--- PROJECT FILE DESCRIPTIONS ---
---------------------------------
1. tracer.c - Code for the traceroute trace file reader. This program accepts one input - the filename of the TCP trace file.
    Input format: [filename]
        filename - The name of the traceroute capture file.

    Output: The output includes four sections:
        1. IP addresses of the source, the ultimate destination, and all intermediate routers.
        2. The values of the protocol field in the IP headers of the traceroute packets.
        3. The fragment information of the original datagram.
        4. The average and sd RTT values between the source and each intermediate router.
    The program will also output error messages when input errors occur.

    EXAMPLE: $ ./tracer trace1.pcapng
        This will make the program read the capture file named "trace1.pcapng".

2. util.c - Utility file that contains the struct definitions used by the traceroute capture file parser program.
    Structs: router, packet_time

3. REQ2.txt - Text file that contains the table and answers for Requirement 2. It comapres the results of five different trace files, all with the same destination address.

4. README.txt - This readme file. Contains project descriptions and instructions.

5. makefile - The make file used for easy compilation of the project files.


---------------------------
--- PROGRAM COMPILATION ---
---------------------------
A makefile has been included in the submission of this project, and can be used to easily compile all assets.

Instructions:
    1. In your terminal, switch to the project's directory.
    2. Type the command "make" to compile all the project files in accordance to the makefile.
        2a. (Alternative) The command "make -f makefile" will do the same thing.

Alternatively, the project files can be manually compiled separately with the following commands:
    1. "gcc tracer.c util.c -o tracer -lpcap -lm"


-------------------------
--- PROGRAM EXECUTION ---
-------------------------
Run the program with command "# ./packet [filename]"


------------------
--- REFERENCES ---
------------------
Various sample code files from the UVic CSC 361 connex site were used, including:
packet_parser.c and packet_count.c

Assignment specifications file can also be found on connex.


























