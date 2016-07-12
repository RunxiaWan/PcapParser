// PcapParser project doc.go

/*
PcapParser document
*/
package main

/*
this work are focus on parsing a Pcap file that defragment the fragments it has and assemble the tcp package in it.
Idealy, you can use ./PcapParser -in inputfile -out outputfile to parse a pcap file.
Now the programme is runnable, you can use it to defragment IPV4 fragments and reassemble tcp segments.
Working issue:
1. IPV6 defragmentation
2. Error handling
3. Synchronizing issue to exit the programme*/
