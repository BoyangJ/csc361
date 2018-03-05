Name: Boyang Jiao
UVicID: V00800928
Date: June 24, 2016
Course: CSC 361
Instructor: Kui Wu

Assignment 2: TCP Traffic Analysis

--------------------
--- INTRODUCTION ---
--------------------
This project involved creating a program to parse and analyse a TCP packet trace file.
Information, including connections' source and destination IP addresses, port numbers, status, start and end times, packet information, and data length were extracted from the trace file. 
Additionally, some general information about the number of connections and statistical values, like connection duration, RTT, number of packets, and window size, were calculated.


---------------------------------
--- PROJECT FILE DESCRIPTIONS ---
---------------------------------
1. packet.c - Code for the TCP packet trace file reader. This program accepts one input - the filename of the TCP trace file.
    Input format: [filename]
        filename - The name of the TCP traffic capture file.

    Output: The output is divided into four sections:
        A) Total number of connections - reports the number of connections (defined by the 4-tuple of src_IP, dst_IP, src_port, dst_port)
        B) Connections' details - provides detailed information of each connection, including:
            source IP address, destination IP address, source port, destination port,
            status (based on SYN and FIN messages),
            start time, end time, and duration,
            number of packets from source -> dest and dest -> source, and total number of packets, 
            number of data bytes from source -> dest and dest -> source, and total number of data bytes.
        C) General information - contains information of number of complete TCP connections, reset connections, and open connections (when trace file ended).
        D) Complete TCP connection statistics - minimum, mean, and maximum values of complete connections for:
            time durations, RTT values, number of packets, and receive window size
    The program will also output error messages when input errors occur.

    EXAMPLE: $ ./packet sample-capture-file
        This will let the program read the trace file named "sample-capture-file".

2. util.c - Utility file that contains the struct definitions used by the packet parser program
    Structs: ip_packet, TCP_hdr, and connection

3. README.txt - This readme file. Contains project descriptions and instructions.

4. makefile - The make file used for easy compilation of the project files.


---------------------------
--- PROGRAM COMPILATION ---
---------------------------
A makefile has been included in the submission of this project, and can be used to easily compile all assets.

Instructions:
    1. In your terminal, switch to the project's directory.
    2. Type the command "make" to compile all the project files in accordance to the makefile.
        2a. (Alternative) The command "make -f makefile" will do the same thing.

Alternatively, the project files can be manually compiled separately with the following commands:
    1. "gcc packet.c util.c -o packet -lpcap"


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














