#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h> 
#include <unistd.h> 
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <dirent.h>
#include <pthread.h>
#include <netdb.h> 
#include <ctype.h>
#include <arpa/inet.h>
#include <stdbool.h>

bool isRoot = false;
char user[1024] = {};

int create_socket() {
    struct sockaddr_in serv_addr;
    int fd, opt = 1;
    struct hostent *local_host; 

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation failed. \n");
        return -1;
    }
  
    memset(&serv_addr, '0', sizeof(serv_addr));
  
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);
      
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) {
        printf("\nInvalid address or address not supported.\n");
        return -1;
    }
  
    if (connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection failed.\n");
        return -1;
    }
    return fd;
}

void *server_response(void *client_fd){
    int fd = *(int *) client_fd;
    char msg[1024] = {0};

    while (1) {
        memset(msg, 0, sizeof(msg));
        if (read(fd, msg, 1024) == 0) {
            printf("\n");
            exit(EXIT_SUCCESS);
        }
        printf("%s", msg);
        fflush(stdout);
    }
}

void *user_input(void *client_fd) {
    int fd = *(int *) client_fd;

    while (1) {
        char msg[1024] = {0}, buff = '0';
        int i=0;
        for(; i<strlen(user); i++) msg[i] = user[i];
        msg[i++] = ':';

        while(buff != ';') {
            buff = getchar();
            if(buff == '\n') buff = ' ';
            msg[i++] = buff;
            int temp = i-1;
            if(msg[temp] == ' ' && msg[temp-1] == ' ')  i--;
            if(msg[temp] == ';' && msg[temp-1] == ' ')  i--;
            if(msg[temp] == ' ' && msg[temp-1] == ':')  i--;
        }
        msg[i-1] = '\0';
        
        if (!isRoot) {
            if(strstr(msg, " CREATE USER ")) {
                printf("Error: access denied.\n%s# ", user);
                continue;
            }
            else if(strstr(msg, " GRANT PERMISSION ")) {
                printf("Error: access denied.\n%s# ", user);
                continue;
            } else send(fd, msg, sizeof(msg), 0);  
        }
        else send(fd, msg, sizeof(msg), 0);
    }
}

int main(int argc, char** argv) {
    pthread_t tid[2];
    int fd = create_socket();
    if(fd == -1) return 0;

    char msg[1024] = {};
    if(geteuid() == 0) {
        isRoot = true;
        strcpy(user, "root");
        sprintf(msg, "root");
    }
    else {
        if(argc != 5 || strcmp(argv[1], "-u") || strcmp(argv[3], "-p")) {
            printf("Error: invalid argument\n");
            return 0;
        }
        strcpy(user, argv[2]);
        sprintf(msg, "%s:%s",argv[2], argv[4]);
    }
    send(fd, msg, 1024, 0);

    pthread_create(&(tid[0]), NULL, &server_response, (void *) &fd);
    pthread_create(&(tid[1]), NULL, &user_input, (void *) &fd);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);

    close(fd);
    return 0;
}