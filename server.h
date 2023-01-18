#include <stdio.h>          /* for printf() and fprintf() */
#include <stdlib.h>         /* for exit */
#include <sys/socket.h>     /* for socket(), bind(), and connect() */
#include <arpa/inet.h>      /* for sockaddr_in and inet_ntoa() */
#include <string.h>         /* for memset() */
#include <unistd.h>         /* for close() */
#include <string>           /* for length() */
#include <iostream>
#include <map>
#include <vector>           /* for init_rand usernames*/
#include <queue>            /* for queue of rand usernames */
#include <set>              /* for keeping list of users in a room*/
#include <stdarg.h>
#include <time.h>
#include <argp.h>

#define MAXPENDING 1024

struct room {
    std::string password;
    int isEmpty = 1;
    std::set<std::string> usersInRoom;
};

struct client {
    int sockfd;
    //std::string name;
    std::string room;
    struct timespec ttl;
}; 

enum command {
	Greet = 155,
	JOIN = 3,         //03
	LEAVE = 6,        //06
    LIST_USERS = 12,  //0c
	LIST_ROOMS = 9,   //09
	MSG = 18,         //12
    NICK = 15,        //0f
	CHAT = 21,        //15
    ALIVE = 19
};

struct server_arguments {
	int port;
};

std::map<std::string, struct room> roomRecord;
std::map<std::string, struct client> clientRecord;
std::priority_queue<int, std::vector<int>, std::greater<int> > rand_queue;
int maxRandUser = 0;

int init_server_sock(struct server_arguments *server_arg);
int init_username();
void handle_client_init(int clntSock);
uint8_t* recv_message(int clientSock, int len);
void default_msg(std::vector<uint8_t> *msgrespVect, std::string msg);
void close_client(std::string clientName);
void send_msg(int clientSock, std::vector<uint8_t> msgrespVect, int respStrlen);
bool removeClntFromCurrRoom(std::string clientName, std::string currClntRoom);
void handle_client_message(std::string clientName);