#include "server.h"

error_t server_parser(int key, char *arg, struct argp_state *state) {
	struct server_arguments *args = (server_arguments* ) (state->input);
	error_t ret = 0;
	switch(key) {
	case 'p':
		/* Validate that port is correct and a number, etc!! */
		args->port = atoi(arg);
		if (0 /* port is invalid */) {
			argp_error(state, "Invalid option for a port, must be a number");
		}
		break;
	default:
		ret = ARGP_ERR_UNKNOWN;
		break;
	}
	return ret;
}

struct server_arguments server_parseopt(int argc, char *argv[]) {
	struct server_arguments args;

	/* bzero ensures that "default" parameters are all zeroed out */
	bzero(&args, sizeof(args));

	struct argp_option options[] = {
		{ "port", 'p', "port", 0, "The port to be used for the server" ,0},
		{0}
	};
	struct argp argp_settings = { options, server_parser, 0, 0, 0, 0, 0 };
	if (argp_parse(&argp_settings, argc, argv, 0, NULL, &args) != 0) {
		printf("Got an error condition when parsing\n");
		
	}

	return args;
}

int init_server_sock(struct server_arguments *server_arg) {
    struct sockaddr_in servAddr;
    int servSock;
    // create server socket 
    if ((servSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0 ) {
        perror("error making socket\n");
        exit(-3);
    }

    const int enable = 1;

    if (setsockopt(servSock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
    	printf("setsockopt(SO_REUSEADDR) failed");
  		exit(1);
 	} 

    // construct the server addresss struct
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(server_arg->port);

    // bind struct to socket
    if(bind(servSock, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
        perror("error binding socket\n");
        exit(-3);
    }

    // set socket to listen
    if (listen(servSock, MAXPENDING) < 0 ) {
        perror("error binding socket\n");
        exit(-3);
    }

    return servSock;
}

int init_username() {
    if (rand_queue.empty()) {
        //give next rand entry and increment the max
        return maxRandUser++;
    } else {
        // give username of whats next in queue
        int top = rand_queue.top();
        rand_queue.pop();
        return top;
    }
}

void rand_back_in_queue(std::string clientName) {
    std::string parsedName = clientName.substr(0, clientName.size() - 1);
    if (parsedName == "rand") {
        // convert char number into int
        int randEntry = clientName.back() - '0';
        // Push entry into the queue
        rand_queue.push(randEntry);
    }
}

void handle_client_init(int clntSock) {
    int bytes_recv, bytes_sent;
    int len;
    int assignedNumb;
    uint8_t *msgrecv, *msgresp;       //         4  17  9a   0  r    a   n    d    
    std::vector<uint8_t> msgrespVect = {0, 0, 0, 4, 23, 154, 0, 114, 97, 110, 100};
    std::string namestring = "";
    struct client newClient;

    // peek into payload to see length
    if ((bytes_recv = recv(clntSock, &len, (size_t) 4, MSG_PEEK)) < 0) {
        perror("error peeking for length: ");
    }

    // Allocate to receive the rest
    len = htonl(len);
    msgrecv = (uint8_t *) malloc(len);
    
    // receive the rest 
    if ((bytes_recv = recv(clntSock, msgrecv, (size_t) len + 7, 0)) < 0) {
        perror("handling client recv error: ");
    }

    // Assign next rand username
    assignedNumb = init_username();
    msgrespVect.insert(msgrespVect.begin() + 3, 6);     //insert length of payload into vector
    msgrespVect.push_back(assignedNumb + '0');          // put rand entry at back of vector

    // make uint8 pointer point to vector so data can be sent
    msgresp = &msgrespVect[0];

    // send
    bytes_sent = send(clntSock, msgresp, 13, 0);
    if (bytes_sent < 0) {
        perror("error with sending ack accept");
    }

    for (long unsigned int i = 8; i < msgrespVect.size(); i++) {
        namestring.push_back((char) msgrespVect[i]);
    }

    newClient.sockfd = clntSock;
    clock_gettime(CLOCK_REALTIME, &newClient.ttl);

    clientRecord[namestring] = newClient;

   // clientRecord.insert({namestring, newClient});
    free(msgrecv);
   // close(clntSock);
}

uint8_t* recv_message(int clientSock, int len) {
    int bytes_recv;
    uint8_t* msgrecv = (uint8_t*)malloc(len + 7);
    bytes_recv = recv(clientSock, msgrecv, (size_t) len + 7, 0);
    if (bytes_recv < 0) {
        perror("Error with receive");
    }
    /*
    for (int i = 0; i < len + 7; i++) {
            printf("%02x ", msgrecv[i]);
    }
    printf("\n");  */
    return msgrecv;
} 

void default_msg(std::vector<uint8_t> *msgrespVect, std::string msg) {
        msgrespVect->pop_back();     // Pop zero at the end for payload
        msgrespVect->push_back(1);   // push the hardcoded one to the end payload
        // put length of string into payload. plus one for payload formality (to includes that weird 01 shit)
        msgrespVect->insert(msgrespVect->begin() + 3, msg.length() + 1);    
        msgrespVect->insert(msgrespVect->end(), msg.begin(), msg.end());  //put message in payload
}

void send_msg(int clientSock, std::vector<uint8_t> msgrespVect, int respStrlen) {
    int bytes_sent;
    uint8_t *msgresp;
    msgresp = &msgrespVect[0];
  /*  for (int i = 0; i < respStrlen + 7; i++) {
        printf("%02x ", msgresp[i]);
    } */
    bytes_sent = send(clientSock, msgresp, respStrlen + 7, 0);
    if (bytes_sent < 0) {
        perror("error with send");
    }
}

bool removeClntFromCurrRoom(std::string clientName, std::string currClntRoom) {
    if (currClntRoom != "") {
        roomRecord[currClntRoom].usersInRoom.erase(clientName);
        if (roomRecord[currClntRoom].usersInRoom.empty()) {
            roomRecord.erase(currClntRoom);
        }
        return true;
    }
    return false;
}

// Will close the client socket descriptor and removes them from the room they were in and the client record
void close_client(std::string clientName) {
    //erase client from clientRecord
    // If username was a rand entry, put it back in queue
    rand_back_in_queue(clientName);
    // If client is in a room, leave the room, else client is leaving the server
    removeClntFromCurrRoom(clientName, clientRecord[clientName].room);
    int closeError = close(clientRecord[clientName].sockfd);
    if (closeError < 0) {
        perror("We got a close error: ");
    }
    clientRecord.erase(clientName);
}

void handle_client_message(std::string clientName) {
   // std::cout << "THIS IS THE NAME" << name << std::endl;

    int clientSock = clientRecord[clientName].sockfd;
    int respStrlen = 1, strLen = 0, bytes_recv;
    uint8_t *msgrecv, details[7], len, command, secondByteLen;
    std::vector<uint8_t> msgrespVect = {0, 0, 0, 4, 23, 154, 0};

    bytes_recv = recv(clientSock, details, (size_t) 7, MSG_PEEK);

    // Client has either cntr^c, quit, or disconnected
    if (bytes_recv == 0) {
        close_client(clientName);
        return;
    }

    if (bytes_recv < 0) {
        perror("Error with peeking recv");
    }

    // details is first 7 bytes of payload, contains size, 417, and command
    command = details[6];
    len = details[3];
    secondByteLen = details[2];
    
   /* 
    printf("\nCOMMAND NUMB: %d\n", command);
    printf("COMMAND NUMB HEX: %02x\n", command); */

    // If 3rd byte is a one then we have 256 as the len, so recv up to that + the 4th byte len
    // Else receive just the len (4th byte)
    if (secondByteLen == 1) {
        msgrecv = recv_message(clientSock,len + 256);
    } else {
        msgrecv = recv_message(clientSock,len);
    }
    
    /* for (int i = 0; i < len + 7; i++) {
        printf("%02x ", msgrecv[i]);
    } */

    switch(command) {
        case ALIVE: 
            clock_gettime(CLOCK_REALTIME, &clientRecord[clientName].ttl);
            break;
        case LIST_USERS:   
            clock_gettime(CLOCK_REALTIME, &clientRecord[clientName].ttl);
            // increment through clientRecord and create payload listing all users
            if (clientRecord[clientName].room != "") {
                for(auto& user: roomRecord[clientRecord[clientName].room].usersInRoom) {
                    strLen = user.size();           // Getting len of name
                    respStrlen += (strLen + 1);             //
                    msgrespVect.push_back(strLen);
                    msgrespVect.insert(msgrespVect.end(), user.begin(), user.end());
                }
            } else {
                for (auto client = clientRecord.begin(); client != clientRecord.end(); client++) {
                    strLen = client->first.size();          // Getting len of name
                    respStrlen += (strLen + 1);             //
                    msgrespVect.push_back(strLen);
                    msgrespVect.insert(msgrespVect.end(), client->first.begin(), client->first.end());
                }
            }
            msgrespVect.insert(msgrespVect.begin() + 3, respStrlen);
            send_msg(clientSock, msgrespVect, respStrlen);
            clock_gettime(CLOCK_REALTIME, &clientRecord[clientName].ttl);
            break;
        case LIST_ROOMS:
            clock_gettime(CLOCK_REALTIME, &clientRecord[clientName].ttl);
            // Iterate through roomRecord and create payload accordingly
            for (auto room = roomRecord.begin(); room != roomRecord.end(); room++) {
                    strLen = room->first.size();          // Getting len of roomName
                    respStrlen += (strLen + 1);           // Add to length roomName to lenght of entire payload string
                    msgrespVect.push_back(strLen);        // Push length of string into payload
                    msgrespVect.insert(msgrespVect.end(), room->first.begin(), room->first.end());  // Insert string into payload
            }

            if (respStrlen > 255) {
                msgrespVect.erase(msgrespVect.begin() + 2);
                msgrespVect.insert(msgrespVect.begin() + 2, 1);
                msgrespVect.insert(msgrespVect.begin() + 3, respStrlen - 256);
            } else {
                // insert length of payload 
                msgrespVect.insert(msgrespVect.begin() + 3, respStrlen);
            }
            send_msg(clientSock, msgrespVect, respStrlen);
            break; 
        case NICK: 
            {
                clock_gettime(CLOCK_REALTIME, &clientRecord[clientName].ttl);
                char nickName[(msgrecv[7]) + 1];
                memcpy(nickName, &msgrecv[8], msgrecv[7]);
                nickName[(msgrecv[7])] = '\0';
           /*     printf("msg[8]: %02x \n", msgrecv[8]);
                printf("msg[7]: %02x \n", msgrecv[7]);
                printf("NICK NAME: %s \n", nickName); */
            
            if (clientRecord.count(nickName) == 0) {
                // If username was a rand entry, put it back in queue
                rand_back_in_queue(clientName);
                //std::string prevName;
                struct client oldClient;

                if (clientRecord[clientName].room != "") {
                    roomRecord[clientRecord[clientName].room].usersInRoom.erase(clientName);
                    roomRecord[clientRecord[clientName].room].usersInRoom.insert(nickName);
                }

                for (auto client = clientRecord.begin(); client != clientRecord.end();) {
                    if (client->second.sockfd == clientSock) {
                        oldClient.sockfd = client->second.sockfd;
                        oldClient.room = client->second.room;
                        client = clientRecord.erase(client);
                    } else {
                        ++client;
                    }
                }

                // Insert a new client with the new nickname and oldClient value(client struct)
                clientRecord.insert({nickName, oldClient});
                //clientRecord[nickName].name = nickName;

                //Stick one in place for the response payload
                msgrespVect.insert(msgrespVect.begin() + 3, 1);

            } else {
                // if nickname already exists but user is the one with that existing nickname, then allow "change"
                // else give the user that long ass message
                if (clientRecord[nickName].sockfd == clientSock) {
                    //Only need to stick 01 in position since name change is allowed, 
                    // so only need to create the acknowledgemnt payload
                    msgrespVect.insert(msgrespVect.begin() + 3, 1);
                } else {
                    // create payload message of already taken name
                    std::string nameTaken = "This nick has been nicked by someone else.";
                    // Increment by length of the string
                    respStrlen += nameTaken.length();
                    default_msg(&msgrespVect, nameTaken);
                }
            }
            /*    printf("CLIETN RECORD SIZE: %lu\n", clientRecord.size());
                printf("PRINTING MAP\n");
                for (auto &client : clientRecord) {
                    printf("NAME: %s SOCKFD: %d\n", clientRecord[client.first].name.c_str(), clientRecord[client.first].sockfd);
                } */
            send_msg(clientSock, msgrespVect, respStrlen);
            }
            break;
        case LEAVE:
            clock_gettime(CLOCK_REALTIME, &clientRecord[clientName].ttl);
            bool leavingRoom;
            // If client is in a room, leave the room, else client is leaving the server
            if ((leavingRoom = removeClntFromCurrRoom(clientName, clientRecord[clientName].room))) {
                // change client room field to ""
                clientRecord[clientName].room = "";
            } else {
                // If username was a rand entry, put it back in queue
                rand_back_in_queue(clientName);
            }
            //Stick one in place for the response payload
            msgrespVect.insert(msgrespVect.begin() + 3, 1);
            send_msg(clientSock, msgrespVect, respStrlen);
            // If client is leaving server, then close it's sockFD
            if (!leavingRoom) {
                close_client(clientName);
            }
            break;
        case JOIN:
        {
            clock_gettime(CLOCK_REALTIME, &clientRecord[clientName].ttl);
            std::string lengthExceeded;
            uint8_t roomNameLen = msgrecv[7];                //roomNameLen is at 8th byte of payload
            uint8_t passLen = msgrecv[8 + roomNameLen];     //passwordLen is at 8th byte + length of room name
            char roomName[roomNameLen + 1];
            char password[passLen + 1]; 
            struct room currRoom;
            bool isPasswordSame;
            std::set<std::string> currClntRoomUsers;
            // the room the client is currently in
            std::string currClntRoom = clientRecord[clientName].room;

            memcpy(roomName, &msgrecv[8], roomNameLen);
            memcpy(password, &msgrecv[9 + roomNameLen], passLen);
            roomName[roomNameLen] = '\0'; 
            password[passLen] = '\0'; 

            // room that returns when looking for room name. returns empty if room didn't exist
            currRoom = roomRecord[roomName];
            isPasswordSame = currRoom.password == password;

         /*   printf("ROOM NAME?: %s\n", roomName);
            printf("ROOM RECORD SIZE: %lu\n", roomRecord.size());
            printf("IS ROOM EMPTY?: %d\n", currRoom.isEmpty);
            printf("ROOM PASSWORD STRING: %s\n", currRoom.password.c_str());
            printf("client PASSWORD STRING: %s\n", password);
            printf("USERS IN ROOM BEFORE JOIN\n"); */

            //we have a new room so create it and assign password if applicable
            if (len != 0 && secondByteLen == 1) {
                lengthExceeded = "Length limit exceeded.";
                respStrlen += lengthExceeded.length(); 
                default_msg(&msgrespVect, lengthExceeded);
            } else if (currClntRoom == roomName) {
                std::string alreadyInRoom = "You attempt to bend space and time to reenter where you already are. You fail.";
                // Increment by length of the string for payload param
                respStrlen += alreadyInRoom.length();
                default_msg(&msgrespVect, alreadyInRoom);
            } else if (currRoom.isEmpty == 1) {
                // If client is already in a room, remove from room
                removeClntFromCurrRoom(clientName, currClntRoom);
                currRoom.isEmpty = 0;           // set room to not empty
                currRoom.password = password;   // set room password
                currRoom.usersInRoom.insert(clientName);    // put client into room users set
                roomRecord[roomName] = currRoom;            // set the room struct to roomName in roomRecord map
                clientRecord[clientName].room = roomName;   //assign room name to client
                //Only need to stick 01 in position since name change is allowed (for ack payload) 
                msgrespVect.insert(msgrespVect.begin() + 3, 1);
            } else {
                // If password is same, allow user to join, else don't
                if (isPasswordSame) {
                    // if current client is in a room, erase client from curr room
                    removeClntFromCurrRoom(clientName, currClntRoom);
                    // Insert user into room set and assign room to client
                    roomRecord[roomName].usersInRoom.insert(clientName);
                    //currRoom.usersInRoom.insert(clientName);
                    clientRecord[clientName].room = roomName;
                    //Only need to stick 01 in position since name change is allowed (for ack payload) 
                    msgrespVect.insert(msgrespVect.begin() + 3, 1);
                } else {       
                    // Password was invalid
                    std::string invalidPassword = "Invalid password. You shall not pass.";
                    // Increment by length of the string for payload param
                    respStrlen += invalidPassword.length();
                    default_msg(&msgrespVect, invalidPassword);
                }
            }
            send_msg(clientSock, msgrespVect, respStrlen);

            //If length limit has been exceeded by client, close client
            if (lengthExceeded == "Length limit exceeded.") {
                close_client(clientName);
            }
        }
            break;
        case MSG: 
        {
            clock_gettime(CLOCK_REALTIME, &clientRecord[clientName].ttl);
            // Check if user exists first 
            // If not send message back saying nick not present (00 00 00 11 04 17 9a 01 (Nick not present))
            // else if check if 1st 4bytes len isn't above 256. if it is (10 01) send length exceeded message, and disconnect client
            // else send the message to the person
            // 
            std::string lengthExceeded;
            bool goodMessage = false;
            if (len != 0 && secondByteLen == 1) {
                lengthExceeded = "Length limit exceeded.";
                respStrlen += lengthExceeded.length(); 
                default_msg(&msgrespVect, lengthExceeded);
            } else if (clientRecord.count(clientName) == 0) {
                std::string nickNotPres = "Nick not present";
                // Increment by length of the string for payload param
                respStrlen += nickNotPres.length();
                default_msg(&msgrespVect, nickNotPres);
            } else {
                uint8_t nameLen = msgrecv[7];                //roomNameLen is at 8th byte of payload
                uint8_t msgLen = msgrecv[9 + nameLen];     //passwordLen is at 8th byte + length of room name
                char recverName[nameLen + 1];
                char msg[msgLen + 1]; 
                int recverSockFD;
                goodMessage = true;

                memcpy(recverName, &msgrecv[8], nameLen);
                memcpy(msg, &msgrecv[10 + nameLen], msgLen);
                recverName[nameLen] = '\0'; 
                msg[msgLen] = '\0'; 
                recverSockFD = clientRecord[recverName].sockfd;

                //Stick one in place for the response payload to whever sent the message 
                msgrespVect.insert(msgrespVect.begin() + 3, 1);
                send_msg(clientSock, msgrespVect, respStrlen);

                respStrlen += msgLen;
                respStrlen += clientName.length();
                respStrlen += 2;

                // Take out the one we used for the response to the sender
                msgrespVect.erase(msgrespVect.begin() + 3);
                if (respStrlen > 255) {
                    msgrespVect.erase(msgrespVect.begin() + 2);
                    msgrespVect.insert(msgrespVect.begin() + 2, 1);
                    msgrespVect.insert(msgrespVect.begin() + 3, respStrlen - 256);
                } else {
                    // insert length of payload 
                    msgrespVect.insert(msgrespVect.begin() + 3, respStrlen);
                }

                msgrespVect.pop_back();             //pop 0 off vector
                msgrespVect.pop_back();             //pop 9a off vector
                msgrespVect.push_back(18);          // put command at back of vector
                msgrespVect.push_back(clientName.length());          // put length of sending user name at back of vector
                msgrespVect.insert(msgrespVect.end(), clientName.begin(), clientName.end());  //put message in payload
                msgrespVect.push_back(0);          // put 00 byte at back of vector
                msgrespVect.push_back(msgLen);          // put msglen at back of vector
                msgrespVect.insert(msgrespVect.end(), msg, msg+msgLen);  //put message in payload
                send_msg(recverSockFD, msgrespVect, respStrlen);
            }
            // Check if user exists first, if doesn't exists, send message back saying nick not present. if it does, do message stuff
            // Client says (Send user this message), if allowed server says to the receiving client ('this user sent you this message')
            // if not allowed (message to long) send length exceeded message, and disconnect client
            if (goodMessage == false) {
                send_msg(clientSock, msgrespVect, respStrlen);
            }
            
            //If length limit has been exceeded by client, close client
            if (lengthExceeded == "Length limit exceeded.") {
                close_client(clientName);
            }
        }
            break;
        case CHAT: 
        {
            clock_gettime(CLOCK_REALTIME, &clientRecord[clientName].ttl);
            std::string lengthExceeded;
            if (len != 0 && secondByteLen == 1) {
                lengthExceeded = "Length limit exceeded.";
                respStrlen += lengthExceeded.length(); 
                default_msg(&msgrespVect, lengthExceeded);
            } else if (clientRecord[clientName].room != "") {
                uint8_t roomLen = msgrecv[7];                //roomNameLen is at 8th byte of payload
                uint8_t msgLen = msgrecv[9 + roomLen];     //passwordLen is at 8th byte + length of room name
                char roomName[roomLen + 1];
                char msg[msgLen + 1]; 
                // int recverSockFD;
                //     int senderSockFD = clientRecord[clientName].sockfd;

                memcpy(roomName, &msgrecv[8], roomLen);
                memcpy(msg, &msgrecv[10 + roomLen], msgLen);
                roomName[roomLen] = '\0'; 
                msg[msgLen] = '\0'; 
                
            /*    std::cout << "CHATTING ROOM NAME: " << roomName << "\n";
                std::cout << "CHATTING MESS: " << msg << "\n";
                recverSockFD = clientRecord[roomName].sockfd;
                std::cout << "RECEIVERS sockfd: " << recverSockFD << "\n"; */

                //Stick one in place for the response payload to whever sent the message 
                msgrespVect.insert(msgrespVect.begin() + 3, 1);
                send_msg(clientSock, msgrespVect, respStrlen);

                respStrlen += msgLen;
                respStrlen += roomLen;
                respStrlen += clientName.length();
                respStrlen += 3;

                // Take out the one we used for the response to the sender
                msgrespVect.erase(msgrespVect.begin() + 3);
                if (respStrlen > 255) {

                    msgrespVect.erase(msgrespVect.begin() + 2);
                    msgrespVect.insert(msgrespVect.begin() + 2, 1);
                    msgrespVect.insert(msgrespVect.begin() + 3, respStrlen - 256);
                } else {
                    // insert length of payload 
                    msgrespVect.insert(msgrespVect.begin() + 3, respStrlen);
                }

                msgrespVect.pop_back();             //pop 0 off vector
                msgrespVect.pop_back();             //pop 9a off vector
                msgrespVect.push_back(21);          // put command at back of vector
                msgrespVect.push_back(roomLen);     // put length of room at back of vector
                msgrespVect.insert(msgrespVect.end(), roomName, roomName+roomLen);  //put room name in payload
                msgrespVect.push_back(clientName.length());     // put length of client sender name at back of vector
                msgrespVect.insert(msgrespVect.end(), clientName.begin(), clientName.end());  //put room name in payload
                msgrespVect.push_back(0);           // put 00 bytes at back of vector
                msgrespVect.push_back(msgLen);     // put message length at back of vector
                msgrespVect.insert(msgrespVect.end(), msg, msg+msgLen);  //put msg in payload

                // Send to everyone in the room
                for(auto& user: roomRecord[clientRecord[clientName].room].usersInRoom) {
                    if (clientName != user) {
                        send_msg(clientRecord[user].sockfd, msgrespVect, respStrlen);
                    }
                }
            } else {
                std::string voidCommand = "You shout into the void and hear nothing.";
                respStrlen += voidCommand.length(); 
                default_msg(&msgrespVect, voidCommand);
                send_msg(clientSock, msgrespVect, respStrlen);
            }

            //If length limit has been exceeded by client, close client
            if (lengthExceeded == "Length limit exceeded.") {
                send_msg(clientSock, msgrespVect, respStrlen);
                close_client(clientName);
            }
        }
            break;
        default:
            break;
    }
    free(msgrecv);
    if (bytes_recv < 0) {
        perror("error peeking for length: ");
    }
}

void expire_clients(timespec currentTime) {
    int timeElapsed;
    // original iterator
    std::map<std::string, struct client>::iterator client;
    for (client = clientRecord.begin(); client != clientRecord.end();) {
        std::map<std::string, struct client>::iterator this_client = client++;
        timeElapsed = currentTime.tv_sec - this_client->second.ttl.tv_sec;
        if (timeElapsed >= 30) {
            close_client(this_client->first);
        }
    }
}

int main (int argc, char *argv[]) {
    struct sockaddr_in clntAddr;
    unsigned int clntLen;
    int clntSock;
    fd_set fds;
    struct timespec currTime;

    struct server_arguments server_arg = server_parseopt(argc, argv);  // Parse the CMD line for server args
    
    int servSock = init_server_sock(&server_arg);

    // Create our timeval struct for timeout functionality
    struct timeval cull_clients = {0};
    cull_clients.tv_sec = 8;
    cull_clients.tv_usec = 0;
    clock_gettime(CLOCK_REALTIME, &currTime);
    for(;;) {
        clntLen = sizeof(clntAddr);
        FD_ZERO(&fds);  
        FD_SET(servSock, &fds); 

        for (auto x = clientRecord.begin(); x != clientRecord.end(); x++) {
            FD_SET(x->second.sockfd, &fds);    
        }
       // printf("before select:\n");
        int fds_ready = select(FD_SETSIZE, &fds, NULL, NULL, &cull_clients); 
        clock_gettime(CLOCK_REALTIME, &currTime);
        if (fds_ready < 0) {
            perror("select error: ");
        } else if (cull_clients.tv_sec == 0) {
            expire_clients(currTime);
            cull_clients.tv_sec = 10;
        } else if (FD_ISSET(servSock, &fds)) { // New client connection
            clntSock = accept(servSock, (struct sockaddr *) &clntAddr, &clntLen);
            if (clntSock < 0) {
                perror("error accepting\n");
            } else {
                handle_client_init(clntSock);
            }
        } else {
            // original iterator
            std::map<std::string, struct client>::iterator client;
            // Check which clientFD is ready to read from
            for (client = clientRecord.begin(); client != clientRecord.end();) {
                // Iterator copy (because of a segault issue when client leaves server with \leave)
                std::map<std::string, struct client>::iterator this_client = client++;
                
                if (FD_ISSET(this_client->second.sockfd, &fds)) {
                    // Client is sending command to server, so handle command
                    handle_client_message(this_client->first);                   
                }
            }
        }
    }
}