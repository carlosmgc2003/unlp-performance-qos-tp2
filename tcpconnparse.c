/* Program to extract TCP connection-level information */
/* from a TCP/IP packet trace file.                    */
/*                                                     */
/* Usage:  gcc -o tcpconnparse tcpconnparse.c          */
/*         tcpconnparse < infile > outfile             */
/*                                                     */
/* Reads the input trace file with TCP/IP pkt info.    */
/* Produces output file summarizing completed TCP      */
/* connections (start time, end time, duration, srcIP, */
/* dstIP, srcPort, dstPort, pkts sent, pkts recd,      */
/* bytes sent, bytes received, and so on.              */
/* Also produces output files                          */
/*    pktsperconn.dat - number of IP packets           */
/*    bytesperconn.dat - number of bytes               */
/*    timeperconn.dat - connection duration            */
/*                                                     */
/* Original version by Raja Epsilon for his CMPT 855   */
/* course project in December 1998.                    */
/*                                                     */
/* Revisions by Carey Williamson, February 1999        */
/* Modified by Carey Williamson, October 2002          */

#include <stdio.h>
#include <string.h>

/* Manifest constants */
#define MAX_CONNS 8000
#define IP_ADDR_LENGTH 16
#define IP_ACK_SIZE 52
#define FLAG_LENGTH 5

/* Debugging flag */
/* #define DEBUG 1 */

#define SF_ONLY 1   /* print connections with SYN and FIN only */

/* A TCP connection is uniquely identified by a 4-tuple:       */
/*       IPSrcAddr, SrcPort, IPDstAddr, DstPort                */
/* In the best of worlds, we always see the SYN (start) and    */
/* FIN (end) of each connection, and can count all of the      */
/* packets and bytes that occur during the connection.         */
/* Can also determine conn duration, from start and end times. */
/* In the real (finite) trace, we might miss the start or end  */
/* of some connections, but we can still keep stats on them.   */
/* Note that the mapping of "client" and "server" to IP source */
/* and IP destination address is unpredictable, since we don't */
/* always see the first packet of each connection.             */

/* Data structure for TCP connection state information */
struct TCP_Conn_Descriptor
  {
    char IPSrcAddr[IP_ADDR_LENGTH];  /* IP source address */
    char IPDstAddr[IP_ADDR_LENGTH];  /* IP destination address */

    int SrcPort;                     /* Port number used by IP source */
    int DstPort;                     /* Port number used by IP destination */

    int SYN_flag;        /* SYN flag was explicitly seen at conn startup */
    int FIN_flag;        /* FIN flag was explicitly seen at conn teardown */
    int reset;           /* a reset flag was explicitly seen during conn  */

    int numSYN;      /* counter to check for extra SYNs (retransmissions) */
    int numFIN;      /* counter to check for extra FINs (retransmissions) */

    float start_time;  /* start time (SYN pkt) in microseconds */
    float end_time;    /* end time (FIN pkt) in microseconds */

    unsigned long SrctoDst_Sseqnum;  /* starting seqnum for S->D traffic */
    unsigned long SrctoDst_Fseqnum;  /* ending seqnum for S->D traffic */

    unsigned long DsttoSrc_Sseqnum;  /* starting seqnum for D->S traffic */
    unsigned long DsttoSrc_Fseqnum;  /* ending seqnum for D->S traffic */

    unsigned long SrctoDst_Sacknum;  /* starting acknum for S->D traffic */
    unsigned long SrctoDst_Facknum;  /* ending acknum for S->D traffic */

    unsigned long DsttoSrc_Sacknum;  /* starting acknum for D->S traffic */
    unsigned long DsttoSrc_Facknum;  /* ending acknum for D->S traffic */

    int SrctoDst_IPbytes;    /* number of bytes from S->D at the IP layer */
    int DsttoSrc_IPbytes;    /* number of bytes from D->S at the IP layer */

    int SrctoDst_pkts;       /* number of IP pkts from S->D */
    int DsttoSrc_pkts;       /* number of IP pkts from D->S */

    int SrctoDst_acks;       /* number of ack pkts from S->D */
    int DsttoSrc_acks;       /* number of ack pkts from S->D */

    int bidirectional; /* flag to indicate if data traffic is bidirectional */
  };

/* Global data structures and variables */
struct TCP_Conn_Descriptor TCP_Conn_Array[MAX_CONNS];
int total_conns, total_pkts, resets, resetconns;
int total_SFconns, total_SXconns, total_XFconns, total_XXconns;
int total_SFpkts, total_SXpkts, total_XFpkts, total_XXpkts;
int total_bidirectional;

/* Variables for reading in a line of trace file, which has following form: */
/*   time IPsrc IPdst IPsize TCPseq srcPort dstPort TCPack TCPflags */
/* 0.000000 192.168.1.201 -> 192.168.1.200 60 TCP 4297 80 4040844510 : 4040844510 0 win: 5840 S */
float tstamp;
char S_Addr[IP_ADDR_LENGTH];
char D_Addr[IP_ADDR_LENGTH];
int S_port, D_port;
int ipSize;
unsigned long seqNum, ackNum, seqNum2;
char flags[FLAG_LENGTH];
char garby[10];

/* Forward definitions of procedures and functions */
int find_conn(void);
void process_new_packet(void);
void Initialize(void);
void clear_strings(void);

main(void)
  {
    FILE *fp;
    int index;
    int i;

    /* Initialization */
    Initialize();
    clear_strings();

    total_conns = 0;
    total_pkts = 0;
    resets = 0;
    resetconns = 0;

    /* main loop: process each line of the input file */
/*   time IPsrc -> IPdst IPsize prot srcPort dstPort TCPseq : TCPseq2 TCPack win: winsize TCPflags */
/* 0.000000 192.168.1.201 -> 192.168.1.200 60 TCP 4297 80 4040844510 : 4040844510 0 win: 5840 S */
    while(scanf(" %f %s %s %s %d %s %d %d %u %s %u %u %s %s %[SFPAR]", 
		&tstamp, S_Addr, garby, D_Addr, &ipSize, garby,
		&S_port, &D_port, &seqNum, garby, &seqNum2, &ackNum,
		garby, garby, flags) != EOF)
      {
	process_new_packet();
      } /*end while loop*/

    /* calculate state of the connections and packets seen */
    total_SFconns = 0;
    total_SXconns = 0;
    total_XFconns = 0;
    total_XXconns = 0;
    total_bidirectional = 0;
    for( i = 0; i < total_conns; i++)
      {
	if( TCP_Conn_Array[i].SYN_flag )
	  {
	    if( TCP_Conn_Array[i].FIN_flag )
	      {
		total_SFconns++;
		total_SFpkts += TCP_Conn_Array[i].SrctoDst_pkts;
		total_SFpkts += TCP_Conn_Array[i].DsttoSrc_pkts;
	      }
	    else
	      {
		total_SXconns++;
		total_SXpkts += TCP_Conn_Array[i].SrctoDst_pkts;
		total_SXpkts += TCP_Conn_Array[i].DsttoSrc_pkts;
	      }
	  }
	else
	  {
	    if( TCP_Conn_Array[i].FIN_flag )
	      {
		total_XFconns++;
		total_XFpkts += TCP_Conn_Array[i].SrctoDst_pkts;
		total_XFpkts += TCP_Conn_Array[i].DsttoSrc_pkts;
	      }
	    else
	      {
		total_XXconns++;
		total_XXpkts += TCP_Conn_Array[i].SrctoDst_pkts;
		total_XXpkts += TCP_Conn_Array[i].DsttoSrc_pkts;
	      }
	  }
	if( TCP_Conn_Array[i].bidirectional )
	  total_bidirectional++;
      }
    
    /* now print the results summary */
    printf("Total Packets: %d (SF %d, SX %d, XF %d, XX %d) (R %d pkts %d conns)\n",
	   total_pkts,
	   total_SFpkts, total_SXpkts, total_XFpkts, total_XXpkts, resets, resetconns);
    printf("Total Connections Seen: %d (SF %d, SX %d, XF %d, XX %d) (B %d)\n",
	   total_conns,
	   total_SFconns, total_SXconns, total_XFconns, total_XXconns,
	   total_bidirectional);

    /* now print the results for each connection in the table */
    printf(" i  start      IPsrc    port     IPdst    port  B->P->A  B<-P<-A TB TP   end      dur   state\n");
    for( i = 0; i < total_conns; i++)
      {
	printf("%d %8.6f %s %d %s %d %d %d %d %d %d %d %d %d %8.6f %8.6f %c%d%c%d%c%d %d %d\n",
	       i,
	       TCP_Conn_Array[i].start_time,
	       TCP_Conn_Array[i].IPSrcAddr,
	       TCP_Conn_Array[i].SrcPort,
	       TCP_Conn_Array[i].IPDstAddr,
	       TCP_Conn_Array[i].DstPort,
	       TCP_Conn_Array[i].SrctoDst_IPbytes,
	       TCP_Conn_Array[i].SrctoDst_pkts,
	       TCP_Conn_Array[i].SrctoDst_acks,
	       TCP_Conn_Array[i].DsttoSrc_IPbytes,
	       TCP_Conn_Array[i].DsttoSrc_pkts,
	       TCP_Conn_Array[i].DsttoSrc_acks,
	       TCP_Conn_Array[i].SrctoDst_IPbytes +
	           TCP_Conn_Array[i].DsttoSrc_IPbytes,
	       TCP_Conn_Array[i].SrctoDst_pkts + 
	           TCP_Conn_Array[i].DsttoSrc_pkts,
	       TCP_Conn_Array[i].end_time,
	       TCP_Conn_Array[i].end_time - TCP_Conn_Array[i].start_time,
	       (TCP_Conn_Array[i].SYN_flag ? 'S' : 'X'),
	       TCP_Conn_Array[i].numSYN,
	       (TCP_Conn_Array[i].FIN_flag ? 'F' : 'X'),
	       TCP_Conn_Array[i].numFIN,
	       (TCP_Conn_Array[i].reset ? 'R' : 'G'),
	       TCP_Conn_Array[i].reset,
	       TCP_Conn_Array[i].SrctoDst_Fseqnum -
	       TCP_Conn_Array[i].SrctoDst_Sseqnum - 1,
	       TCP_Conn_Array[i].DsttoSrc_Fseqnum -
	       TCP_Conn_Array[i].DsttoSrc_Sseqnum - 1);
      }

    /* print bytes per connection summary info into bytesperconn.dat */
    fp = fopen("bytesperconn.dat", "w");
    if( fp == NULL)
      {
	printf("Failed to open file bytesperconn.dat!\n");
	exit(0);
      }

    for( i = 0; i < total_conns; i++)
      {
#ifdef SF_ONLY
	if( (TCP_Conn_Array[i].SYN_flag) &&
	    (TCP_Conn_Array[i].FIN_flag) &&
            (TCP_Conn_Array[i].reset == 0) )
#endif SF_ONLY
	fprintf(fp, "%ld\n",
		TCP_Conn_Array[i].SrctoDst_IPbytes +
		TCP_Conn_Array[i].DsttoSrc_IPbytes);
      }

    fclose(fp);

    /* print packets per connection summary info into pktsperconn.dat */
    fp = fopen("pktsperconn.dat", "w");
    if( fp == NULL)
      {
	printf("Failed to open file pktsperconn.dat!\n");
	exit(0);
      }

    for( i = 0; i < total_conns; i++)
      {
#ifdef SF_ONLY
	if( (TCP_Conn_Array[i].SYN_flag) &&
	    (TCP_Conn_Array[i].FIN_flag) &&
            (TCP_Conn_Array[i].reset == 0) )
#endif SF_ONLY
	fprintf(fp, "%ld\n",
		TCP_Conn_Array[i].SrctoDst_pkts +
		TCP_Conn_Array[i].DsttoSrc_pkts);
      }

    fclose(fp);

    /* print connection duration summary info into timeperconn.dat */
    fp = fopen("timeperconn.dat", "w");
    if( fp == NULL)
      {
	printf("Failed to open file timeperconn.dat!\n");
	exit(0);
      }

    for( i = 0; i < total_conns; i++)
      {
#ifdef SF_ONLY
	if( (TCP_Conn_Array[i].SYN_flag) &&
	    (TCP_Conn_Array[i].FIN_flag) &&
            (TCP_Conn_Array[i].reset == 0) )
#endif SF_ONLY
	fprintf(fp, "%f\n",
		TCP_Conn_Array[i].end_time -
		TCP_Conn_Array[i].start_time);
      }

    fclose(fp);
  }

/* Search the TCP connection table for a match.           */
/* Note that S_Addr, S_port, D_Addr, D_port are globals,  */
/* which were set when reading in the current input line. */
/* Return index where a match is found, or -1 otherwise.  */
int find_conn(void)
  {
   int i;

   for( i = 0; i < total_conns; i++ )
     {
       if( (strcmp(TCP_Conn_Array[i].IPSrcAddr, S_Addr) == 0) &&
	   (TCP_Conn_Array[i].SrcPort == S_port) &&
	   (strcmp(TCP_Conn_Array[i].IPDstAddr, D_Addr) == 0) &&
	   (TCP_Conn_Array[i].DstPort == D_port) )
	 return( i );
       if( (strcmp(TCP_Conn_Array[i].IPSrcAddr, D_Addr) == 0) &&
	   (TCP_Conn_Array[i].SrcPort == D_port) &&
	   (strcmp(TCP_Conn_Array[i].IPDstAddr, S_Addr) == 0) &&
	   (TCP_Conn_Array[i].DstPort == S_port) )
	 return( i );
     }

   return( -1 );
}

/* Clear out the TCP connection table data structure */
void Initialize(void)
  {
    int i, j;

    for( i = 0; i < MAX_CONNS; i++ )
      {
	for( j = 0; j < IP_ADDR_LENGTH; j++ )
	  {
	    TCP_Conn_Array[i].IPSrcAddr[j] = '\0';
	    TCP_Conn_Array[i].IPDstAddr[j] = '\0';
	  }

	TCP_Conn_Array[i].SrcPort = 0;
	TCP_Conn_Array[i].DstPort = 0;

	TCP_Conn_Array[i].SYN_flag = 0;
	TCP_Conn_Array[i].FIN_flag = 0;
	TCP_Conn_Array[i].reset = 0;

	TCP_Conn_Array[i].numSYN = 0;
	TCP_Conn_Array[i].numFIN = 0;

	TCP_Conn_Array[i].start_time = 0;
	TCP_Conn_Array[i].end_time = 0;

	TCP_Conn_Array[i].SrctoDst_Sseqnum = 0;
	TCP_Conn_Array[i].SrctoDst_Fseqnum = 0;
	TCP_Conn_Array[i].SrctoDst_Sacknum = 0;
	TCP_Conn_Array[i].SrctoDst_Facknum = 0;

	TCP_Conn_Array[i].DsttoSrc_Sseqnum = 0;
	TCP_Conn_Array[i].DsttoSrc_Fseqnum = 0;
	TCP_Conn_Array[i].DsttoSrc_Sacknum = 0;
	TCP_Conn_Array[i].DsttoSrc_Facknum = 0;

	TCP_Conn_Array[i].SrctoDst_IPbytes = 0;
	TCP_Conn_Array[i].SrctoDst_pkts = 0;
	TCP_Conn_Array[i].SrctoDst_acks = 0;

	TCP_Conn_Array[i].DsttoSrc_IPbytes = 0;
	TCP_Conn_Array[i].DsttoSrc_pkts = 0;
	TCP_Conn_Array[i].DsttoSrc_acks = 0;

	TCP_Conn_Array[i].bidirectional = 0;
      }
  }


/* Clear out string variables, since not all IP addresses are same length */
void clear_strings(void)
  {
    int i;
    for( i = 0; i < IP_ADDR_LENGTH; i++ )
      {
	S_Addr[i] = '\0';
	D_Addr[i] = '\0';
      }
    flags[0] = '\0';
    flags[1] = '\0';
  }

/* Process a new packet (i.e., one line of the trace file) */
void process_new_packet(void)
  {
    int i, forward, index;

    total_pkts++;
#ifdef DEBUG
    printf("%f %s %d %s %d %d %u %u %s\n",
	   tstamp, S_Addr, S_port, D_Addr, D_port,
	   ipSize, seqNum, ackNum, flags);
#endif DEBUG

    index = find_conn();
    if( index < 0 )
      {
#ifdef DEBUG
	printf("Setting up new connection record %d...\n", total_conns);
#endif DEBUG

	/* no record of this TCP connection yet, so add it */
	index = total_conns++;
	if( index == MAX_CONNS )
	  {
	    fprintf(stderr, "Whoa!! Too many connections!!\n");
	    exit(0);
	  }

	/* record the IP addresses and port numbers */
	for( i = 0; i < IP_ADDR_LENGTH; i++ )
	  {
	    TCP_Conn_Array[index].IPSrcAddr[i] = S_Addr[i];
	    TCP_Conn_Array[index].IPDstAddr[i] = D_Addr[i];
	  }
	TCP_Conn_Array[index].SrcPort = S_port;
	TCP_Conn_Array[index].DstPort = D_port;

	/* see if this is the normal SYN start to the connection */
	if( flags[0] == 'S' )
	  {
	    TCP_Conn_Array[index].SYN_flag = 1;
	    if( ipSize == 60 )
	      ipSize -= 8;
	  }
	if( flags[0] == 'R' )
	  {
	    if( TCP_Conn_Array[index].reset == 0 )
	      resetconns++;
	    TCP_Conn_Array[index].reset++;
	    resets++;
	    ipSize += 12;
	  }

	/* record now as the start time of the connection, */
        /* regardless of whether SYN was seen or not       */
	TCP_Conn_Array[index].start_time = tstamp;

	/* record our starting sequence number and ack number */
	TCP_Conn_Array[index].SrctoDst_Sseqnum = seqNum;
	TCP_Conn_Array[index].SrctoDst_Sacknum = ackNum;
      }
    else
      {
#ifdef DEBUG
	printf("Updating existing connection record %d...\n", index);
#endif DEBUG
      }

    /* when we get here, 'index' tells us which conn in the table */
    /* we are working with. It may have existed before, or has    */
    /* just been added. In either case, update the statistics.    */
    
    /* see if this is a SrctoDst or a DsttoSrc packet,            */
    /* compared to the first packet of the connection             */
    if( strcmp(S_Addr, TCP_Conn_Array[index].IPSrcAddr) == 0 )
      forward = 1;
    else forward = 0;

    /* count the number of SYN (start) pkts seen in the handshake */
    if( flags[0] == 'S' )
      {
	TCP_Conn_Array[index].numSYN++;
	if( ipSize == 60 )
	  ipSize -= 8;

	/* record our starting sequence number and ack number */
	TCP_Conn_Array[index].DsttoSrc_Sseqnum = seqNum;
	TCP_Conn_Array[index].DsttoSrc_Sacknum = ackNum;
      }
    if( flags[0] == 'R' )
      {
	if( TCP_Conn_Array[index].reset == 0 )
	  resetconns++;
	TCP_Conn_Array[index].reset++;
	TCP_Conn_Array[index].end_time = tstamp;
	resets++;
	ipSize += 12;
      }
    /* record time of latest packet on this connection */
    if( flags[0] == 'A' )
      {
	TCP_Conn_Array[index].end_time = tstamp;
      }

    /* check for the FIN (end) flag */
    /* Note that this code records the connection end time as the */
    /* time of the LAST FIN flag seen                             */
    if( flags[0] == 'F' )
      {
	TCP_Conn_Array[index].FIN_flag = 1;
	TCP_Conn_Array[index].numFIN++;
	TCP_Conn_Array[index].end_time = tstamp;

	/* record sequence number upon close, as a sanity check */
	if( forward )
	  {
	    TCP_Conn_Array[index].SrctoDst_Fseqnum = seqNum;
	    TCP_Conn_Array[index].SrctoDst_Facknum = ackNum;
	  }
	else
	  {
	    TCP_Conn_Array[index].DsttoSrc_Fseqnum = seqNum;
	    TCP_Conn_Array[index].DsttoSrc_Facknum = ackNum;
	  }
      }

    /* update byte count and packet count */
    if( forward )
      {
	TCP_Conn_Array[index].SrctoDst_IPbytes += ipSize - IP_ACK_SIZE;
	TCP_Conn_Array[index].SrctoDst_pkts++;
	if( ipSize <= IP_ACK_SIZE )
	  TCP_Conn_Array[index].SrctoDst_acks++;
	else
	  {
	    /* must be a data packet, so check for bidirectionality */
	    if( TCP_Conn_Array[index].DsttoSrc_pkts >
		TCP_Conn_Array[index].DsttoSrc_acks )
	      TCP_Conn_Array[index].bidirectional = 1;
	  }
      }
    else /* reverse direction traffic */
      {
	TCP_Conn_Array[index].DsttoSrc_IPbytes += ipSize - IP_ACK_SIZE;
	TCP_Conn_Array[index].DsttoSrc_pkts++;
	if( ipSize <= IP_ACK_SIZE )
	  TCP_Conn_Array[index].DsttoSrc_acks++;
	else
	  {
	    /* must be a data packet, so check for bidirectionality */
	    if( TCP_Conn_Array[index].SrctoDst_pkts >
		TCP_Conn_Array[index].SrctoDst_acks )
	      TCP_Conn_Array[index].bidirectional = 1;
	  }
      }
  }


