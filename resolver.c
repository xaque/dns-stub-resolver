#include<arpa/inet.h>
#include<netinet/in.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<time.h>
#include<sys/types.h>
#include<sys/socket.h>
#include <assert.h>

typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;
typedef unsigned short dns_rr_count;
typedef unsigned short dns_query_id;
typedef unsigned short dns_flags;

typedef struct {
  char *name;
  dns_rr_type type;
  dns_rr_class class;
  dns_rr_ttl ttl;
  dns_rdata_len rdata_len;
  unsigned char *rdata;
} dns_rr;

struct dns_answer_entry;
struct dns_answer_entry {
  char *value;
  struct dns_answer_entry *next;
};
typedef struct dns_answer_entry dns_answer_entry;

void print_bytes(unsigned char *bytes, int byteslen) {
  int i, j, byteslen_adjusted;
  unsigned char c;

  if (byteslen % 8) {
    byteslen_adjusted = ((byteslen / 8) + 1) * 8;
  } else {
    byteslen_adjusted = byteslen;
  }
  for (i = 0; i < byteslen_adjusted + 1; i++) {
    if (!(i % 8)) {
      if (i > 0) {
        for (j = i - 8; j < i; j++) {
          if (j >= byteslen_adjusted) {
            printf("  ");
          } else if (j >= byteslen) {
            printf("  ");
          } else if (bytes[j] >= '!' && bytes[j] <= '~') {
            printf(" %c", bytes[j]);
          } else {
            printf(" .");
          }
        }
      }
      if (i < byteslen_adjusted) {
        printf("\n%02X: ", i);
      }
    } else if (!(i % 4)) {
      printf(" ");
    }
    if (i >= byteslen_adjusted) {
      continue;
    } else if (i >= byteslen) {
      printf("   ");
    } else {
      printf("%02X ", bytes[i]);
    }
  }
  printf("\n");
}

void canonicalize_name(char *name) {
  /*
  * Canonicalize name in place.  Change all upper-case characters to
  * lower case and remove the trailing dot if there is any.  If the name
  * passed is a single dot, "." (representing the root zone), then it
  * should stay the same.
  *
  * INPUT:  name: the domain name that should be canonicalized in place
  */

  int namelen, i;

  // leave the root zone alone
  if (strcmp(name, ".") == 0) {
    return;
  }

  namelen = strlen(name);
  // remove the trailing dot, if any
  if (name[namelen - 1] == '.') {
    name[namelen - 1] = '\0';
  }

  // make all upper-case letters lower case
  for (i = 0; i < namelen; i++) {
    if (name[i] >= 'A' && name[i] <= 'Z') {
      name[i] += 32;
    }
  }
}

int name_ascii_to_wire(char *name, unsigned char *wire) {
  /*
  * Convert a DNS name from string representation (dot-separated labels)
  * to DNS wire format, using the provided byte array (wire).  Return
  * the number of bytes used by the name in wire format.
  *
  * INPUT:  name: the string containing the domain name
  * INPUT:  wire: a pointer to the array of bytes where the
  *              wire-formatted name should be constructed
  * OUTPUT: the length of the wire-formatted name.
  */
  canonicalize_name(name);
  int i = 0;
  //Break up hostname by . delimiter
  char* pch = strtok(name, ".");
  while (pch){
    int len = strlen(pch);
    wire[i++] = (unsigned short) len;
    //Write each character in the segment to wire
    for (int ii = 0; ii < len; ii++){
      wire[i+ii] = pch[ii];
    }
    i += len;
    pch = strtok(NULL, ".");
  }
  wire[i++] = '\0';
  return i;
}

int isvalueinarray(int val, int *arr, int size){
    int i;
    for (i=0; i < size; i++) {
        if (arr[i] == val)
            return 1;
    }
    return 0;
}

char *name_ascii_from_wire(unsigned char *wire, int *indexp) {
  /*
  * Extract the wire-formatted DNS name at the offset specified by
  * *indexp in the array of bytes provided (wire) and return its string
  * representation (dot-separated labels) in a char array allocated for
  * that purpose.  Update the value pointed to by indexp to the next
  * value beyond the name.
  *
  * INPUT:  wire: a pointer to an array of bytes
  * INPUT:  indexp, a pointer to the index in the wire where the
  *              wire-formatted name begins
  * OUTPUT: a string containing the string representation of the name,
  *              allocated on the heap.
  */
  int starti = *indexp;
  //printf(":%x\n", starti);
  char* name = malloc(1024);
  int name_i = 0;
  unsigned char cur;
  int tmpstk[100];//100 max pointer depth
  memset(tmpstk, 0, 100);
  int inptr = 0;
  int hasbeen = 0;
  int ptr_i = 0;
  //Loop through the bytes of the wire
  while (cur = wire[(*indexp)++]){
    //It's a count (for a string literal)
    if (cur < 192){
      //Add <count> characters to the name
      for (int i = 0; i < cur; i++){
        //printf("%c", wire[*indexp + i]);
        name[name_i++] = wire[*indexp + i];
      }
      //printf("\n");
      //Apend with a .
      name[name_i++] = '.';
      *indexp += cur;
      // End of pointer, return to value pushed onto tmpstk
      if (inptr && (wire[*indexp] == 0 || *indexp >= ptr_i)){
        inptr--;
        *indexp = tmpstk[inptr] + 1;
        if (!inptr){
          break;
        }
      }
    }
    else{//It's a pointer
    ptr_i = *indexp;
    //printf("cur:%x\n", ptr_i);
    //Prevent infinite loops by breaking if you've already been to this pointer

    // if (isvalueinarray(ptr_i, tmpstk, inptr)){
    //   (*indexp)++;
    //   break;
    // }
    if (hasbeen && ptr_i >= starti){
      (*indexp)++;
      break;
    }
    //14-byte pointer address
    unsigned long ptr = (((int) cur & 0x3f) << 8) | (int) wire[*indexp];
    if (ptr >= starti || (hasbeen && !inptr)){
      break;
    }
    else{//Add current indexp to tmpstk and jump to pointer
      tmpstk[inptr++] = *indexp;
      *indexp = (int) ptr;
      hasbeen = 1;
    }

  }
}
name[name_i] = '\0';
//Remove trailing .
canonicalize_name(name);
return &name[0];
}

dns_rr rr_from_wire(unsigned char *wire, int *indexp, int query_only) {
  /*
  * Extract the wire-formatted resource record at the offset specified by
  * *indexp in the array of bytes provided (wire) and return a
  * dns_rr (struct) populated with its contents. Update the value
  * pointed to by indexp to the next value beyond the resource record.
  *
  * INPUT:  wire: a pointer to an array of bytes
  * INPUT:  indexp: a pointer to the index in the wire where the
  *              wire-formatted resource record begins
  * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
  *              we are extracting a full resource record or only a
  *              query (i.e., in the question section of the DNS
  *              message).  In the case of the latter, the ttl,
  *              rdata_len, and rdata are skipped.
  * OUTPUT: the resource record (struct)
  */
}


int rr_to_wire(dns_rr rr, unsigned char *wire, int query_only) {
  /*
  * Convert a DNS resource record struct to DNS wire format, using the
  * provided byte array (wire).  Return the number of bytes used by the
  * name in wire format.
  *
  * INPUT:  rr: the dns_rr struct containing the rr record
  * INPUT:  wire: a pointer to the array of bytes where the
  *             wire-formatted resource record should be constructed
  * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
  *              we are constructing a full resource record or only a
  *              query (i.e., in the question section of the DNS
  *              message).  In the case of the latter, the ttl,
  *              rdata_len, and rdata are skipped.
  * OUTPUT: the length of the wire-formatted resource record.
  *
  */
}

unsigned short create_dns_query(char *qname, dns_rr_type qtype, unsigned char *wire) {
  /*
  * Create a wire-formatted DNS (query) message using the provided byte
  * array (wire).  Create the header and question sections, including
  * the qname and qtype.
  *
  * INPUT:  qname: the string containing the name to be queried
  * INPUT:  qtype: the integer representation of type of the query (type A == 1)
  * INPUT:  wire: the pointer to the array of bytes where the DNS wire
  *               message should be constructed
  * OUTPUT: the length of the DNS wire message
  */
  int ns = name_ascii_to_wire(qname, wire);//Name portion of header
  wire[ns++] = (char) (qtype >> 8);//Type - first byte
  wire[ns++] = (char) (qtype & 0xff);//Type - second byte
  wire[ns++] = 0x00;//Class - first byte
  wire[ns++] = 0x01;//Class - second byte
  return ns;
}

dns_answer_entry *get_answer_address(char *qname, dns_rr_type qtype, unsigned char *wire) {
  /*
  * Extract the IPv4 address from the answer section, following any
  * aliases that might be found, and return the string representation of
  * the IP address.  If no address is found, then return NULL.
  *
  * INPUT:  qname: the string containing the name that was queried
  * INPUT:  qtype: the integer representation of type of the query (type A == 1)
  * INPUT:  wire: the pointer to the array of bytes representing the DNS wire message
  * OUTPUT: a linked list of dns_answer_entrys the value member of each
  * reflecting either the name or IP address.  If
  */
  dns_answer_entry* head_entry = malloc(sizeof(dns_answer_entry));//Head of linked list to be returned.
  dns_answer_entry** cur_entry = &head_entry;//Current entry in the linked list.
  int num_ans = ((int)wire[6] << 8) | (int) wire[7];
  //printf("%i\n", num_ans);
  int headersize = 12;
  int qsize = strlen(qname) + 6;
  int i = headersize + qsize;
  //Loop for each Answer entry given
  for (int j = 0; j < num_ans; j++){
    char* name = name_ascii_from_wire(wire, &i);
    dns_answer_entry* ans = head_entry;
    if (strcmp(name, qname) == 0){
      unsigned short type = ((int) wire[i++] << 8) | (int) wire[i++];
      //printf("Record: %x\n", type);
      i += 2;//Skip past class
      i += 4;//Skip past TTL
      int rdatalen = ((int) wire[i++] << 8) | (int) wire[i++];
      int pre_rdata = i;
      if (type == 0x01){//A record
        //extract ip
        unsigned char ip[4];
        ip[0] = wire[i++];
        ip[1] = wire[i++];
        ip[2] = wire[i++];
        ip[3] = wire[i++];
        //Make string from IP
        char* ipstring = malloc(16);
        sprintf(ipstring, "%i.%i.%i.%i", ip[0], ip[1], ip[2], ip[3]);
        dns_answer_entry* oldentry = *cur_entry;
        oldentry->value = ipstring;
        dns_answer_entry* newentry = malloc(sizeof(dns_answer_entry));
        oldentry->next = newentry;
        cur_entry = &newentry;
      }
      else if (type == 0x05){//CNAME record
        char* cname = name_ascii_from_wire(wire, &i);
        qname = cname;
        dns_answer_entry* oldentry = *cur_entry;
        oldentry->value = cname;
        dns_answer_entry* newentry = malloc(sizeof(dns_answer_entry));
        oldentry->next = newentry;
        cur_entry = &newentry;
      }
      assert(i == pre_rdata + rdatalen);//If @i is somehow offtrack, exit.
    }
    free(name);
  }

  return head_entry;
}

int send_recv_message(unsigned char *request, int requestlen, unsigned char *response, char *server, unsigned short port) {
  /*
  * Send a message (request) over UDP to a server (server) and port
  * (port) and wait for a response, which is placed in another byte
  * array (response).  Create a socket, "connect()" it to the
  * appropriate destination, and then use send() and recv();
  *
  * INPUT:  request: a pointer to an array of bytes that should be sent
  * INPUT:  requestlen: the length of request, in bytes.
  * INPUT:  response: a pointer to an array of bytes in which the
  *             response should be received
  * OUTPUT: the size (bytes) of the response received
  */

  struct sockaddr_in servaddr;
  socklen_t addrlen;
  int recvlen;
  int fd;
  unsigned char buf[1024];
  //Values for server connection
  memset((char*)&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(port);
  servaddr.sin_addr.s_addr = inet_addr(server);

  addrlen = sizeof(servaddr);

  //Open UDP socket
  if ((fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
    printf("cannot create socket\n");
    return 0;
  }

  //Connect to socket
  connect(fd, (struct sockaddr *) &servaddr, addrlen);

  //Send DNS question
  if ((send(fd, request, requestlen, 0) < 0 )){
    printf("sendfailed\n");
  }

  //Get reponse from server.
  recvlen = recv(fd, buf, 1024, 0);
  //printf("received %d bytes\n", recvlen);

  memcpy(response, buf, recvlen);
  response[recvlen] = '\0';

  //close(fd);
  return recvlen;
}

int generate_header(unsigned short qid, unsigned char* header){
  //Pretty much just hard-coded the bytes for the header of the request.
  header[0] = (char) (qid >> 8);
  header[1] = (char) (qid & 0xff);
  header[2] = 0x01;
  header[3] = 0x00;
  header[4] = 0x00;
  header[5] = 0x01;
  header[6] = 0x00;
  header[7] = 0x00;
  header[8] = 0x00;
  header[9] = 0x00;
  header[10] = 0x00;
  header[11] = 0x00;
  return 12;
}

dns_answer_entry *resolve(char *qname, char *server) {
  char* origname = malloc(1024);
  memset(origname, 0, 100);
  strcpy(origname, qname);
  //Generate random query ID
  unsigned short qid = (unsigned short) rand();
  unsigned char header[12];
  int hlen = generate_header(qid, header);
  unsigned char wire[256];
  int wirelen = create_dns_query(qname, 0x01, wire);
  unsigned char* dnsreq = (unsigned char*) malloc(hlen + wirelen);
  int i = 0;
  //Copy each byte from header to dnsreq
  for (; i < hlen; i++){
    dnsreq[i] = header[i];
  }
  for (int j = 0; j < wirelen; j++){
    dnsreq[i+j] = wire[j];
  }
  //printf("Request:\n");
  //print_bytes(dnsreq, hlen + wirelen);

  unsigned char* response = (unsigned char*) malloc(1024);
  int rlen = send_recv_message(dnsreq, hlen + wirelen, response, server, 53);
  //printf("Response:\n");
  //print_bytes(response, rlen);

  //If the response doesn't have a matching query ID, something went wrong.
  unsigned short ans_qid = ((int)response[0] << 8) | (int) response[1];
  if (qid != ans_qid || rlen < 12){
    return NULL;
  }
  dns_answer_entry* finans = get_answer_address(origname, 0x01, response);
  free(origname);
  free(dnsreq);
  free(response);
  return finans;
}

int main(int argc, char *argv[]) {
  srand(time(NULL));
  dns_answer_entry *ans;
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <domain name> <server>\n", argv[0]);
    exit(1);
  }
  ans = resolve(argv[1], argv[2]);
  while (ans->next) {
    printf("%s\n", ans->value);
    dns_answer_entry* tmp = ans;
    ans = ans->next;
    free(tmp->value);
    free(tmp);
  }
  if (ans){
    free(ans);
  }

}
