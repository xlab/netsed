//  This work is based on the original netsed 0.01c by Michal Zalewski.
//  Please contact Julien VdG <julien@silicone.homelinux.org> if you encounter
//  any problems with this version.
//  The changes compared to version 0.01c are related in the NEWS file.
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <signal.h>
#include <netdb.h>
#include <time.h>

#define VERSION "0.02c"
#define MAXRULES 50
#define MAX_BUF  100000

#define ERR(x...) fprintf(stderr,x)

#define DEBUG
#ifdef DEBUG
#define DBG(x...) printf(x)
#else
#define DBG(x...)
#endif

#define UDP_TIMEOUT 30

struct rule_s {
  char *from,*to;
  const char *forig, *torig;
  int fs,ts;
  int live;
};

enum state_e {
  UNREPLIED,
  ESTABLISHED,
  DISCONNECTED,
  TIMEOUT
};

struct tracker_s {
  // recvfrom information: 'connect' address
  struct sockaddr* csa;
  socklen_t csl;
  // connection socket to client
  int csock;
  // socket to forward to server
  int fsock;
  // last event time, for timeout
  time_t time;
  // 
  enum state_e state;

  // chain it
  struct tracker_s * n;
};

void freetracker (struct tracker_s * conn)
{
  if(conn->csa != NULL) { // udp
    free(conn->csa);
  } else { // tcp
    close(conn->csock);
  }
  close(conn->fsock);
  free(conn);
}

time_t now;
int lsock, rules;
struct rule_s rule[MAXRULES];

struct tracker_s * connections = NULL;

volatile int stop=0;

void usage_hints(const char* why) {
  ERR("Error: %s\n\n",why);
  ERR("Usage: netsed proto lport rhost rport rule1 [ rule2 ... ]\n\n");
  ERR("  proto   - protocol specification (tcp or udp)\n");
  ERR("  lport   - local port to listen on (see README for transparent\n");
  ERR("            traffic intercepting on some systems)\n");
  ERR("  rhost   - where connection should be forwarded (0 = use destination\n");
  ERR("            address of incoming connection, see README)\n");
  ERR("  rport   - destination port (0 = dst port of incoming connection)\n");
  ERR("  ruleN   - replacement rules (see below)\n\n");
  ERR("General syntax of replacement rules: s/pat1/pat2[/expire]\n\n");
  ERR("This will replace all occurrences of pat1 with pat2 in any matching packet.\n");
  ERR("An additional parameter (count) can be used to expire a rule after 'count'\n");
  ERR("successful substitutions. Eight-bit characters, including NULL and '/',\n");
  ERR("can be passed using HTTP-like hex escape sequences (e.g. CRLF as %%0a%%0d).\n");
  ERR("A match on '%%' can be achieved by specifying '%%%%'. Examples:\n\n");
  ERR("  's/andrew/mike/1'     - replace 'andrew' with 'mike' (only first time)\n");
  ERR("  's/andrew/mike'       - replace all occurrences of 'andrew' with 'mike'\n");
  ERR("  's/andrew/mike%%00%%00' - replace 'andrew' with 'mike\\x00\\x00'\n");
  ERR("                          (manually padding to keep original size)\n");
  ERR("  's/%%%%/%%2f/20'         - replace the 20 first occurence of '%%' with '/'\n\n");
  ERR("Rules are not active across packet boundaries, and they are evaluated\n");
  ERR("from first to last, not yet expired rule, as stated on the command line.\n");
  exit(1);
}

#ifdef __GNUC__
// avoid gcc from inlining those two function when optimizing, as otherwise
// the function whould break strict-aliasing rules by dereferencing pointers...
in_port_t get_port(struct sockaddr *sa) __attribute__ ((noinline));
void set_port(struct sockaddr *sa, in_port_t port) __attribute__ ((noinline));
#endif

in_port_t get_port(struct sockaddr *sa) {
  switch (sa->sa_family) {
    case AF_INET:
      return ntohs(((struct sockaddr_in *) sa)->sin_port);
    case AF_INET6:
      return ntohs(((struct sockaddr_in6 *) sa)->sin6_port);
    default:
      return 0;
  }
} /* get_port(struct sockaddr *) */

void set_port(struct sockaddr *sa, in_port_t port) {
  switch (sa->sa_family) {
    case AF_INET:
      ((struct sockaddr_in *) sa)->sin_port = htons(port);
      break;
    case AF_INET6:
      ((struct sockaddr_in6 *) sa)->sin6_port = htons(port);
    default:
      break;
  }
} /* set_port(struct sockaddr *, in_port_t) */

void error(const char* reason) {
  ERR("[-] Error: %s\n",reason);
  ERR("netsed: exiting.\n");
  exit(2);
}


char hex[]="0123456789ABCDEF";

void shrink_to_binary(struct rule_s* r) {
  int i;

  r->from=malloc(strlen(r->forig));
  r->to=malloc(strlen(r->torig));
  if ((!r->from) || (!r->to)) error("shrink_to_binary: unable to malloc() buffers");

  for (i=0;i<strlen(r->forig);i++) {
    if (r->forig[i]=='%') {
      // Have to shrink.
      i++;
      if (r->forig[i]=='%') {
        // '%%' -> '%'
        r->from[r->fs]='%';
        r->fs++;
      } else {
        int hexval;
        char* x;
        if (!r->forig[i]) error("shrink_to_binary: src pattern: unexpected end.");
        if (!r->forig[i+1]) error("shrink_to_binary: src pattern: unexpected end.");
        x=strchr(hex,toupper(r->forig[i]));
        if (!x) error("shrink_to_binary: src pattern: non-hex sequence.");
        hexval=(x-hex)*16;
        x=strchr(hex,toupper(r->forig[i+1]));
        if (!x) error("shrink_to_binary: src pattern: non-hex sequence.");
        hexval+=(x-hex);
        r->from[r->fs]=hexval;
        r->fs++; i++;
      }
    } else {
      // Plaintext case.
      r->from[r->fs]=r->forig[i];
      r->fs++;
    }
  }

  for (i=0;i<strlen(r->torig);i++) {
    if (r->torig[i]=='%') {
      // Have to shrink.
      i++;
      if (r->torig[i]=='%') {
        // '%%' -> '%'
        r->to[r->ts]='%';
        r->ts++;
      } else {
        int hexval;
        char* x;
        if (!r->torig[i]) error("shrink_to_binary: dst pattern: unexpected end.");
        if (!r->torig[i+1]) error("shrink_to_binary: dst pattern: unexpected end.");
        x=strchr(hex,toupper(r->torig[i]));
        if (!x) error("shrink_to_binary: dst pattern: non-hex sequence.");
        hexval=(x-hex)*16;
        x=strchr(hex,toupper(r->torig[i+1]));
        if (!x) error("shrink_to_binary: dst pattern: non-hex sequence.");
        hexval+=(x-hex);
        r->to[r->ts]=hexval;
        r->ts++; i++;
      }
    } else {
      // Plaintext case.
      r->to[r->ts]=r->torig[i];
      r->ts++;
    }
  }
}


void bind_and_listen(int af, int tcp, const char *portstr) {
  int ret;
  struct addrinfo hints, *res, *reslist;

  memset(&hints, '\0', sizeof(hints));
  hints.ai_family = af;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_socktype = tcp ? SOCK_STREAM : SOCK_DGRAM;

  if ((ret = getaddrinfo(NULL, portstr, &hints, &reslist))) {
    ERR("getaddrinfo(): %s\n", gai_strerror(ret));
    error("Impossible to resolve listening port.");
  }
  /* We have useful addresses. */
  for (res = reslist; res; res = res->ai_next) {
    int one = 1;

    if ( (lsock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
      continue;
    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    //fcntl(lsock,F_SETFL,O_NONBLOCK);
    if (bind(lsock, res->ai_addr, res->ai_addrlen) < 0) {
      ERR("bind(): %s", strerror(errno));
      close(lsock);
      continue;
    }
    if (tcp) {
      if (listen(lsock, 16) < 0) {
        close(lsock);
        continue;
      }
    } else { // udp
      int one=1;
      setsockopt(lsock,SOL_SOCKET,SO_OOBINLINE,&one,sizeof(int));
    }
    /* Successfully bound and now also listening. */
    break;
  }
  freeaddrinfo(reslist);
  if (res == NULL)
    error("Listening socket failed.");
}

char buf[MAX_BUF];
char b2[MAX_BUF];

int sed_the_buffer(int siz) {
  int i=0,j=0;
  int newsize=0;
  int changes=0;
  int gotchange=0;
  for (i=0;i<siz;) {
    gotchange=0;
    for (j=0;j<rules;j++) {
      if ((!memcmp(&buf[i],rule[j].from,rule[j].fs)) && (rule[j].live!=0)) {
        changes++;
        gotchange=1;
        printf("    Applying rule s/%s/%s...\n",rule[j].forig,rule[j].torig);
        rule[j].live--;
        if (rule[j].live==0) printf("    (rule just expired)\n");
        memcpy(&b2[newsize],rule[j].to,rule[j].ts);
        newsize+=rule[j].ts;
        i+=rule[j].fs;
        break;
      }
    }
    if (!gotchange) {
      b2[newsize]=buf[i];
      newsize++;
      i++;
    }
  }
  if (!changes) printf("[*] Forwarding untouched packet of size %d.\n",siz);
  else printf("[*] Done %d replacements, forwarding packet of size %d (orig %d).\n",
              changes,newsize,siz);
  return newsize;
}


// prototype this function so that the content is in the same order as in
// previous read_write_sed function.
void b2server_sed(struct tracker_s * conn, ssize_t rd);

void server2client_sed(struct tracker_s * conn) {
    ssize_t rd;
    rd=read(conn->fsock,buf,sizeof(buf));
    if ((rd<0) && (errno!=EAGAIN))
    {
      DBG("[!] server disconnected. (rd err) %s\n",strerror(errno));
      conn->state = DISCONNECTED;
    }
    if (rd == 0) {
      // nothing read but select said ok, so EOF
      DBG("[!] server disconnected. (rd)\n");
      conn->state = DISCONNECTED;
    }
    if (rd>0) {
      printf("[+] Caught server -> client packet.\n");
      rd=sed_the_buffer(rd);
      conn->time = now;
      conn->state = ESTABLISHED;
      if (sendto(conn->csock,b2,rd,0,conn->csa, conn->csl)<=0) {
        DBG("[!] client disconnected. (wr)\n");
        conn->state = DISCONNECTED;
      }
    }
}

void client2server_sed(struct tracker_s * conn) {
    ssize_t rd;
    rd=read(conn->csock,buf,sizeof(buf));
    if ((rd<0) && (errno!=EAGAIN))
    {
      DBG("[!] client disconnected. (rd err)\n");
      conn->state = DISCONNECTED;
    }
    if (rd == 0) {
      // nothing read but select said ok, so EOF
      DBG("[!] client disconnected. (rd)\n");
      conn->state = DISCONNECTED;
    }
    b2server_sed(conn, rd);
}

void b2server_sed(struct tracker_s * conn, ssize_t rd) {
    if (rd>0) {
      printf("[+] Caught client -> server packet.\n");
      rd=sed_the_buffer(rd);
      conn->time = now;
      if (write(conn->fsock,b2,rd)<=0) {
        DBG("[!] server disconnected. (wr)\n");
        conn->state = DISCONNECTED;
      }
    }
}

void sig_chld(int signo)
{
  pid_t  pid;
  int    stat;
  while ( (pid = waitpid(-1, &stat, WNOHANG)) > 0)
    printf("[!] child %d terminated\n", pid);
  return;
} 

void sig_int(int signo)
{
  DBG("[!] user interrupt request (%d)\n",getpid());
  stop = 1;
}

int main(int argc,char* argv[]) {
  int i, ret;
  in_port_t fixedport = 0;
  struct sockaddr_storage fixedhost;
  struct addrinfo hints, *res, *reslist;
  int tcp;
  struct tracker_s * conn;

  memset(&fixedhost, '\0', sizeof(fixedhost));
  printf("netsed " VERSION " by Julien VdG <julien@silicone.homelinux.org>\n"
         "     based on 0.01c from Michal Zalewski <lcamtuf@ids.pl>\n");
  setbuffer(stdout,NULL,0);
  if (argc<6) usage_hints("not enough parameters");
  if (strcasecmp(argv[1],"tcp")*strcasecmp(argv[1],"udp")) usage_hints("incorrect procotol");
  tcp = strncasecmp(argv[1], "udp", 3);
  // parse rules
  for (i=5;i<argc;i++) {
    char *fs=0, *ts=0, *cs=0;
    printf("[*] Parsing rule %s...\n",argv[i]);
    fs=strchr(argv[i],'/');
    if (!fs) error("missing first '/' in rule");
    fs++;
    ts=strchr(fs,'/');
    if (!ts) error("missing second '/' in rule");
    *ts=0;
    ts++;
    cs=strchr(ts,'/');
    if (cs) { *cs=0; cs++; }
    rule[rules].forig=fs;
    rule[rules].torig=ts;
    if (cs) rule[rules].live=atoi(cs); else rule[rules].live=-1;
    shrink_to_binary(&rule[rules]);
//    printf("DEBUG: (%s) (%s)\n",rule[rules].from,rule[rules].to);
    rules++;    
  }

  printf("[+] Loaded %d rule%s...\n", rules, (rules > 1) ? "s" : "");

  memset(&hints, '\0', sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_CANONNAME;
  hints.ai_socktype = tcp ? SOCK_STREAM : SOCK_DGRAM;

  if ((ret = getaddrinfo(argv[3], argv[4], &hints, &reslist))) {
    ERR("getaddrinfo(): %s\n", gai_strerror(ret));
    error("Impossible to resolve remote address or port.");
  }
  /* We have candidates for remote host. */
  for (res = reslist; res; res = res->ai_next) {
    int sd = -1;

    if ( (sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
      continue;
    /* Has successfully built a socket for this address family. */
    /* Record the address structure and the port. */
    fixedport = get_port(res->ai_addr);
    memcpy(&fixedhost, res->ai_addr, res->ai_addrlen);
    close(sd);
    break;
  }
  freeaddrinfo(reslist);
  if (res == NULL)
    error("Failed in resolving remote host.");

  if (fixedhost.ss_family && fixedport)
    printf("[+] Using fixed forwarding to %s,%s.\n",argv[3],argv[4]);
  else
    printf("[+] Using dynamic (transparent proxy) forwarding.\n");

  bind_and_listen(fixedhost.ss_family, tcp, argv[2]);

  printf("[+] Listening on port %s/%s.\n", argv[2], argv[1]);

  signal(SIGPIPE,SIG_IGN);
  // TODO: use sigaction
  signal(SIGCHLD,sig_chld);
  signal(SIGINT,sig_int);

  while (!stop) {
    struct sockaddr_storage s;
    socklen_t l = sizeof(s);
    struct sockaddr_storage conho;
    in_port_t conpo;
    char ipstr[INET6_ADDRSTRLEN], portstr[12];

    int sel;
    fd_set rd_set;
    struct timeval timeout;
    int nfds = lsock;
    FD_ZERO(&rd_set);
    FD_SET(lsock,&rd_set);
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    {
      conn = connections;
      // TODO: process time to adjust timeout
      while(conn != NULL) {
        if(tcp) {
          FD_SET(conn->csock, &rd_set);
          if (nfds < conn->csock) nfds = conn->csock;
        }
        FD_SET(conn->fsock, &rd_set);
        if (nfds < conn->fsock) nfds = conn->fsock;
        // point on next
        conn = conn->n;
      }
    }

    sel=select(nfds+1, &rd_set, (fd_set*)0, (fd_set*)0, &timeout);
    time(&now);
    if (stop)
    {
      break;
    }
    if (sel < 0) {
      if (errno == EINTR)
        continue; // we will get some SIGCHLD
      DBG("[!] select fail! %s\n", strerror(errno));
      break;
    }
    if (sel == 0) {
//      DBG("[*] select timeout\n");
//      continue; // select timeout
    }

    if (FD_ISSET(lsock, &rd_set)) {
      int csock=-1;
      ssize_t rd=-1;
      if (tcp) {
        csock = accept(lsock,(struct sockaddr*)&s,&l);
      } else {
        // udp does not handle accept, so track connections manually
        // also set csock if a new connection need to be registered
        // to share the code with tcp ;)
        rd = recvfrom(lsock,buf,sizeof(buf),0,(struct sockaddr*)&s,&l);
        if(rd >= 0) {
          conn = connections;
          while(conn != NULL) {
            // look for existing connections
            if ((conn->csl == l) && (0 == memcmp(&s, conn->csa, l))) {
              // found
              break;
            }
            // point on next
            conn = conn->n;
          }
          // not found
          if(conn == NULL) {
            // udp 'connection' socket is the listening one
            csock = lsock;
          } else {
            DBG("[+] Got incoming datagram from existing connection.\n");
          }
        } else {
          ERR("recvfrom(): %s", strerror(errno));
        }
      }

      // new connection (tcp accept, or udp conn not found)
      if ((csock)>=0) {
        int one=1;
        getnameinfo((struct sockaddr *) &s, l, ipstr, sizeof(ipstr),
                    portstr, sizeof(portstr), NI_NUMERICHOST | NI_NUMERICSERV);
        printf("[+] Got incoming connection from %s,%s", ipstr, portstr);
        conn = malloc(sizeof(struct tracker_s));
        if(NULL == conn) error("netsed: unable to malloc() connection tracker struct");
        // protocol specific init
        if (tcp) {
          setsockopt(csock,SOL_SOCKET,SO_OOBINLINE,&one,sizeof(int));
          conn->csa = NULL;
          conn->csl = 0;
          conn->state = ESTABLISHED;
        } else {
          conn->csa = malloc(l);
          if(NULL == conn->csa) error("netsed: unable to malloc() connection tracker sockaddr struct");
          memcpy(conn->csa, &s, l);
          conn->csl = l;          
          conn->state = UNREPLIED;
        }
        conn->csock = csock;
        conn->time = now;

        l = sizeof(s);
        getsockname(csock,(struct sockaddr*)&s,&l);
        getnameinfo((struct sockaddr *) &s, l, ipstr, sizeof(ipstr),
                    portstr, sizeof(portstr), NI_NUMERICHOST | NI_NUMERICSERV);
        printf(" to %s,%s\n", ipstr, portstr);
        conpo = get_port((struct sockaddr *) &s);

        memcpy(&conho, &s, sizeof(conho));

        if (fixedport) conpo=fixedport; 
        if (fixedhost.ss_family)
          memcpy(&conho, &fixedhost, sizeof(conho));

        memcpy(&s, &conho, sizeof(s));
        getnameinfo((struct sockaddr *) &s, l, ipstr, sizeof(ipstr),
                    portstr, sizeof(portstr), NI_NUMERICHOST | NI_NUMERICSERV);
        printf("[*] Forwarding connection to %s,%s\n", ipstr, portstr);

        // forward to addr
        memcpy(&s, &conho, sizeof(s));
        set_port((struct sockaddr *) &s, conpo);
        l=sizeof(s);
        // connect will bind with some dynamic addr/port
        conn->fsock = socket(s.ss_family, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);

        if (connect(conn->fsock,(struct sockaddr*)&s,l)) {
           printf("[!] Cannot connect to remote server, dropping connection.\n");
           freetracker(conn);
           conn = NULL;
        } else {
          setsockopt(conn->fsock,SOL_SOCKET,SO_OOBINLINE,&one,sizeof(int));
          conn->n = connections;
          connections = conn;
        }
      }
      // udp has data process forwarding
      if((rd >= 0) && (conn != NULL)) {
        b2server_sed(conn, rd);
      }
    } // lsock is set
    // all other sockets
    conn = connections;
    struct tracker_s ** pconn = &connections;
    while(conn != NULL) {
      // incoming data ?
      if(tcp && FD_ISSET(conn->csock, &rd_set)) {
        client2server_sed(conn);
      }
      if(FD_ISSET(conn->fsock, &rd_set)) {
        server2client_sed(conn);
      }
      // timeout ? udp only
      //DBG("[!] connection last time: %d, now: %d\n", conn->time, now);
      if(!tcp && ((now - conn->time) > UDP_TIMEOUT)) {
        DBG("[!] connection timeout.\n");
        conn->state = TIMEOUT;
      }
      if(conn->state >= DISCONNECTED) {
        // remove it
        (*pconn)=conn->n;
        freetracker(conn);
        conn=(*pconn);
      } else {
        // point on next
        pconn = &(conn->n);
        conn = conn->n;
      }
    }
  }
  close(lsock);
  // close all tracker
  while(connections != NULL) {
    conn = connections;
    connections = conn->n;
    freetracker(conn);
  }

  exit(0);
}

// vim:sw=2:sta:et:
