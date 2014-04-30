#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int main(int argc, char **argv)
{
	if(argc < 2) {
		fprintf(stderr, "usage: getaddrinfo item\n");
		return -1;
	}

	for(int i=1; i < argc; i++) {
		char *host = argv[i];
		struct addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family   = AF_INET;
		hints.ai_flags    = AI_CANONNAME;
		hints.ai_socktype = SOCK_STREAM;
		struct addrinfo *info = NULL;
		int r = getaddrinfo(host, NULL, &hints, &info);
		if(r != 0) {
			fprintf(stderr, "%s\tfailed\t%s (%d)\n", host, gai_strerror(r), r);
			continue;
		}
		struct addrinfo *ai = info;
		while(ai != NULL) {
			struct sockaddr *sa = ai->ai_addr;
			if(sa->sa_family == AF_INET) {
				struct sockaddr_in *in = (struct sockaddr_in *) ai->ai_addr;
				uint32_t *ip = (uint32_t *) &(in->sin_addr);
				*ip = ntohl(*ip);
				fprintf(stdout, "%s\t%u.%u.%u.%u\t%u\n",
					host, *ip >> 24, *ip >> 16 & 0xff, *ip >> 8 & 0xff, *ip & 0xff, *ip);
			}
			ai = ai->ai_next;
		}
		freeaddrinfo(info);
	}
	return 0;
}

