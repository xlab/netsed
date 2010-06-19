#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <signal.h>
#include <netdb.h>

#define VERSION "0.02a"
#define MAXRULES 50
#define MAX_BUF  100000

#define ERR(x...) fprintf(stderr,x)

#define DEBUG
#ifdef DEBUG
#define DBG(x...) printf(x)
#else
#define DBG(x...)
#endif


struct rule_s {
  char *from,*to;
  const char *forig, *torig;
  int fs,ts;
  int live;
};


int lsock, csock,rules;
struct rule_s rule[MAXRULES];


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
  ERR("General replacement rules syntax: s/pat1/pat2[/expire]\n\n");
  ERR("This will replace all occurences of pat1 with pat2 in matching packets.\n");
  ERR("Additional parameter (count) can be used to expire rule after 'count'\n");
  ERR("succesful substitutions. Eight-bit characters, including NULL and '/', can\n");
  ERR("be passed using HTTP-alike hex escape sequences (eg. %%0a%%0d). Single '%%'\n");
  ERR("can be reached by using '%%%%'. Examples:\n\n");
  ERR("  's/anrew/mike/1'   - replace 'andrew' with 'mike' (once)\n");
  ERR("  's/anrew/mike'     - replace all occurences of 'andrew' with 'mike'\n");
  ERR("  's/anrew/mike%%00'  - replace 'andrew' with 'mike\\x00' (to keep orig. size)\n");
  ERR("  's/%%%%/%%2f/20'      - replace '%%' with '/' in first 20 packets\n\n");
  ERR("Rules are not working on cross-packet boundaries and are evaluated from\n");
  ERR("first to last not expired rule.\n");
  exit(1);
}


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


void bind_and_listen(int tcp,int port) {
  struct sockaddr_in laddr;
  lsock=socket(PF_INET,tcp ? SOCK_STREAM:SOCK_DGRAM,0);
//  fcntl(lsock,F_SETFL,O_NONBLOCK);
  laddr.sin_family = PF_INET;
  laddr.sin_port = htons (port);
  laddr.sin_addr.s_addr = 0;
  if (bind(lsock,(struct sockaddr*)&laddr,sizeof(laddr)))
    error("cannot bind to given port / protocol");
  if (listen(lsock,16))
    error("cannot listen on the socket (strange)");
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
              changes,siz,newsize);
  return newsize;
}


int read_write_sed(int s1,int s2) {
  int rd;

  int sel;
  fd_set rd_set;
  struct timeval timeout;
  FD_ZERO(&rd_set);
  FD_SET(s1,&rd_set);
  FD_SET(s2,&rd_set);
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;
  sel=select((s1<s2)?s2+1:s1+1, &rd_set, (fd_set*)0, (fd_set*)0, &timeout);
  if (sel < 0) {
    DBG("[!] select fail!\n");
    return 0; // s1 not connected
  }
    if (sel == 0) {
//    DBG("[*] select timeout\n");
    return 1; // select timeout
  }

  if (FD_ISSET(s1, &rd_set)) {
    DBG("[*] select server\n");
    rd=read(s1,buf,sizeof(buf));
    if ((rd<0) && (errno!=EAGAIN))
    {
      DBG("[!] server disconnected. (rd err)\n");
      return 0; // s1 not connected
    }
    if (rd == 0) {
      // nothing read but select said ok, so EOF
      DBG("[!] server disconnected. (rd)\n");
      return 0; // not able to send
    }
    if (rd>0) {
      printf("[+] Caught server -> client packet.\n");
      rd=sed_the_buffer(rd);
      if (write(s2,b2,rd)<=0) {
        DBG("[!] client disconnected. (wr)\n");
        return 0; // not able to send
      }
    }
  }
  
  if (FD_ISSET(s2, &rd_set)) {
    DBG("[*] select client\n");
    rd=read(s2,buf,sizeof(buf));
    if ((rd<0) && (errno!=EAGAIN))
    {
      DBG("[!] client disconnected. (rd err)\n");
      return 0; // s2 not connected
    }
    if (rd == 0) {
      // nothing read but select said ok, so EOF
      DBG("[!] client disconnected. (rd)\n");
      return 0; // not able to send
    }
    if (rd>0) {
      printf("[+] Caught client -> server packet.\n");
      rd=sed_the_buffer(rd);
      if (write(s1,b2,rd)<=0) {
        DBG("[!] server disconnected. (wr)\n");
        return 0; // not able to send
      }
    }
  }
  return 1;
}


int main(int argc,char* argv[]) {
  int i;
  int fixedhost=0,fixedport=0;
  printf("netsed " VERSION " by Michal Zalewski <lcamtuf@ids.pl>\n");
  setbuffer(stdout,NULL,0);
  if (argc<6) usage_hints("not enough parameters");
  if (strcmp(argv[1],"tcp")*strcmp(argv[1],"udp")) usage_hints("incorrect procotol");
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

  printf("[+] Loaded %d rules...\n",rules);
  if (!atoi(argv[2])) error("incorrect local port");
  bind_and_listen(strcmp(argv[1],"udp"),atoi(argv[2]));
  printf("[+] Listening on port %d/%s.\n",atoi(argv[2]),argv[1]);
  fixedport=atoi(argv[4]);
  fixedhost = inet_addr(argv[3]);
  if (fixedhost == -1) {
    struct hostent *resolvhost;
    resolvhost = gethostbyname(argv[3]);
    if (resolvhost==NULL) error("cannot resolve rhost");
    DBG("[+] resolved %s : %d.%d.%d.%d\n", argv[3], 
            (unsigned char)resolvhost->h_addr[0],
            (unsigned char)resolvhost->h_addr[1],
            (unsigned char)resolvhost->h_addr[2],
            (unsigned char)resolvhost->h_addr[3]);
    fixedhost=*((long*)resolvhost->h_addr); // don't know if this is quite portable, probably not
  }
  DBG("[?] inet : %08x\n",fixedhost);
  if (fixedhost && fixedport) printf("[+] Using fixed forwarding to %s:%s.\n",argv[3],argv[4]);
    else printf("[+] Using dynamic (transparent proxy) forwarding.\n");
  signal(SIGPIPE,SIG_IGN);
  signal(SIGCHLD,SIG_IGN);

  // Am I bad coder?;>

  while (1) {
    struct sockaddr_in s;
    int x,l=sizeof(struct sockaddr_in);
    int conho,conpo;
    usleep(1000); // Do not wanna select ;P
    if ((csock=accept(lsock,(struct sockaddr*)&s,&l))>=0) {
      printf("[+] Got incoming connection from %s:%d",inet_ntoa(s.sin_addr),ntohs(s.sin_port));
      l=sizeof(struct sockaddr_in);
      getsockname(csock,(struct sockaddr*)&s,&l);
      printf(" to %s:%d\n", inet_ntoa(s.sin_addr), ntohs(s.sin_port));
      conpo=ntohs(s.sin_port);
      conho=s.sin_addr.s_addr;
      if (fixedport) conpo=fixedport; 
      if (fixedhost) conho=fixedhost;
      s.sin_addr.s_addr=conho;
      printf("[*] Forwarding connection to %s:%d\n", inet_ntoa(s.sin_addr),conpo);
      if (!(x=fork())) {
        int fsock;
        int one=1;
        DBG("[+] processing (%d).\n",getpid());
        s.sin_addr.s_addr=conho;
        s.sin_port=htons(conpo);
        fsock=socket(PF_INET,strcmp(argv[1],"udp") ? SOCK_STREAM:SOCK_DGRAM,0);
        if (connect(fsock,(struct sockaddr*)&s,l)) {
           printf("[!] Cannot connect to remote server, dropping connection.\n");
           close(fsock);close(csock);
           exit(0);
        }
        setsockopt(csock,SOL_SOCKET,SO_OOBINLINE,&one,sizeof(int));
        setsockopt(fsock,SOL_SOCKET,SO_OOBINLINE,&one,sizeof(int));
        while (read_write_sed(fsock,csock));
        printf("[-] Client or server disconnect (%d).\n",getpid());
        close(fsock); close(csock);
        exit(0);
      }
      close(csock);
    }
  }
}

// vim:sw=2:sta:et:
