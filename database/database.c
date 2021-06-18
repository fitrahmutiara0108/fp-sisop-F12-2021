#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <wait.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int curr_fd = -1, user_count = 0;
char global_user_id[1024], global_user_password[1024];
bool isRoot = false;

const int DATA_BUFFER_SIZE = sizeof(char) * 1024;

int create_socket() {
    struct sockaddr_in serv_addr;
    int opt = 1, fd;
    int addrlen = sizeof(serv_addr);

    char buffer[1024];

    fd_set readfds;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) <= 0) {
        printf("Socket creation failed. \n");
        exit(EXIT_FAILURE);
    }
      
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        printf("Error setting socket at fd: %d\n",fd);
        exit(EXIT_FAILURE);
    }
    printf("Socket creation success with fd: %d\n", fd);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(8080);
      
    if (bind(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))<0) {
        fprintf(stderr, "Binding failed [%s]\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (listen(fd, 3) < 0) {
        fprintf(stderr, "Listen failed [%s]\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    return fd;
}

void check_files() {
    struct stat s;
    stat("./databases", &s);
    if(!S_ISDIR(s.st_mode)) mkdir("./databases", 0777);
    stat("./databases/root", &s);
    if(!S_ISDIR(s.st_mode)) mkdir("./databases/root", 0777);

	if(access("commands.log", F_OK )) {
		FILE *file = fopen("commands.log", "w+");
		fclose(file);
	}
}

void append_to_log(char *str) {
    FILE *fp = fopen("commands.log", "a+");
    char timestamp[100];

    memset(timestamp,0,sizeof(timestamp));
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    strftime(timestamp,sizeof(timestamp),"%y-%m-%d %X",&tm);

    fprintf(fp, "%s:%s\n", timestamp, str);
    fclose(fp);
}

bool contains_disallowed_character(char *c) {
    for(int i=0; i<strlen(c); i++){
        if( !((c[i] >= 'a') && (c[i] <= 'z'))
            && !((c[i] >= 'A') && (c[i] <= 'Z'))
            && !(c[i] == '_' || c[i] == '-') 
            && !((c[i] >= '0') && (c[i] <= '9')) ) {
            return true;
        }
    }
    return false;
}

void get_user_data(char *id, char *pass, char *message, int *flag) {
    char *ptrUsr = strstr(message, "CREATE USER ");
    memset(pass, 0, DATA_BUFFER_SIZE);
    memset(id, 0, DATA_BUFFER_SIZE);
    if(ptrUsr){
        char *temp = strtok(message, " ");
        temp = strtok(NULL, " ");
        strcpy(id, strtok(NULL, " "));
        // printf("temp: %s\n", temp);
        // printf("id: %s\n", id);
        if (contains_disallowed_character(id)){
            *flag = 1;
            return;
        } else{
            temp = strtok(NULL, " ");
            // printf("temp: %s\n", temp);
            if(id && !strcmp(temp, "IDENTIFIED")){
                temp = strtok(NULL, " ");
                // printf("temp: %s\n", temp);
                if(id && !strcmp(temp, "BY")){
                    strcpy(pass, strtok(NULL, " "));
                    // printf("pass: %s\n", pass);
                    if (strstr(pass, ";")) pass[strlen(pass)] = "\0";

                } else *flag = 2;
            } else *flag = 2;
        }
    }
}

void user_register(int fd, char *cmd) {

    if(!isRoot) {
        send(fd, "Error: Access denied\n", DATA_BUFFER_SIZE, 0);
        return;
    }

    char id[1024], password[1024], temp[1024];
    FILE *fp = fopen("./databases/root/accounts.txt", "a+");
    if(fp == NULL) {
        send(fd, "Account table creation failed\n", DATA_BUFFER_SIZE, 0);
        return;
    }
    int flag = 0;
    get_user_data(id, password, cmd, &flag);

    char account_db[1024], check_user[1024];
    int isRegistered = 0;
    while (fscanf(fp, "%s", account_db) != EOF){
        strcpy(temp, account_db);
        strcpy(check_user, strtok(temp, ":"));
        if (!strcmp(check_user, id)) {
            isRegistered = 1;
            break;
        }
    }

    if (isRegistered){
        send(fd, "Error: Username is already registered\n", DATA_BUFFER_SIZE, 0); 
        printf("[Username is already registered] %s:%s\n", id, password);
    }
    else if(flag == 1) {
        send(fd, "Error: Username can only contain alphanumeric characters\n", DATA_BUFFER_SIZE, 0);
        printf("[Username can only contain alphanumeric characters] %s:%s\n", id, password);
    }
    else if(flag == 2)  {
        send(fd, "Invalid argument\n", DATA_BUFFER_SIZE, 0);
        printf("[Invalid argument] %s:%s\n", id, password);
    }
    else {
        fprintf(fp, "%s:%s\n", id, password);
        printf("[User created] %s:%s\n", id, password);
        send(fd, "User created\n", DATA_BUFFER_SIZE, 0);
    }
    fclose(fp);
}

void user_login(int fd, char *userdata, int *logged_in) {
    char id[1024], password[1024];
    FILE *fp = fopen("./databases/root/accounts.txt", "r+");
    if(fp == NULL) {
        send(fd, "Error: User database not found.\n", DATA_BUFFER_SIZE, 0);
        close(fd);
        return;
    }

    char account_db[1024];
    int valid = 0;
    while (fscanf(fp, "%s", account_db) != EOF){
        if (!strcmp(account_db, userdata)) {
            valid = 1;
            break;
        }
    }    

    if (valid) {
        curr_fd = fd;
        *logged_in = 1;
    } else {
        send(fd, "Error: Wrong username or password.\n", DATA_BUFFER_SIZE, 0);
        close(fd);
    }
    fclose(fp);
}

void create_cmd(int fd, char *message) {
    int flag = 0;
    char *ptrDB = strstr(message, "CREATE DATABASE ");
    char db_name[1024] = {}, db_dir[2048] = {};
    if(ptrDB){
        char *temp = strtok(message, " ");
        temp = strtok(NULL, " ");
        strcpy(db_name, strtok(NULL, " "));
        if (contains_disallowed_character(db_name)){
            flag = 1;
            return;
        } else{
            if (strstr(db_name, ";")) db_name[strlen(db_name)] = "\0";
        }
    }

    FILE *filePtr = fopen("./databases/root/databases.txt", "a+");
    if(!filePtr)
        send(fd, "Error: Cannot create database\n", 1024, 0);
    else {
        if(flag == 1) {
            send(fd, "Error: Invalid database name\n", DATA_BUFFER_SIZE, 0);
            printf("[Invalid database name] %s\n", db_name);
        }
        // else if(flag == 2) {
        //     send(fd, "Error: Invalid argument\n", DATA_BUFFER_SIZE, 0);
        //     printf("[Invalid argument]\n");
        // }
        else{
            fprintf(filePtr, "%s:%s\n", global_user_id, db_name);
            sprintf(db_dir, "./databases/%s\n", db_name);
            if(!mkdir(db_dir, 0777)) 
                send(fd, "Database created\n", DATA_BUFFER_SIZE, 0);
            else 
                send(fd, "Error: Database already exists\n", DATA_BUFFER_SIZE, 0);
        }
    }
    fclose(filePtr);
}

void drop_cmd(int fd, char *message) {
    int flag = 0;
    char *ptrDB = strstr(message, "DROP DATABASE ");
    char db_name[1024] = {}, db_dir[2048] = {};
    if(ptrDB){
        char *temp = strtok(message, " ");
        temp = strtok(NULL, " ");
        strcpy(db_name, strtok(NULL, " "));
        if (contains_disallowed_character(db_name)){
            flag = 1;
            return;
        } else{
            if (strstr(db_name, ";")) db_name[strlen(db_name)] = "\0";
        }
    }

    FILE *filePtr = fopen("./databases/root/databases.txt", "a+");
    FILE *tempPtr = fopen("./databases/root/temp.txt", "a+");
    char tmp[1024], row[1024], check_user[1024];
    
    if(!filePtr)
        send(fd, "Error: Cannot delete database\n", 1024, 0);
    else {
        if(flag == 1) {
            send(fd, "Error: Invalid database name\n", DATA_BUFFER_SIZE, 0);
            printf("[Invalid database name] %s\n", db_name);
        }
        else{
            flag = 0;
            while(fgets(row, 256, filePtr)){
                if(sscanf(row, "%255[^\n]", tmp) != 1) break;
                if(strstr(tmp, db_name)){
                    int userGet=0;
                    if(isRoot) {
                        userGet = 1;
                    } else{
                        strcpy(check_user, tmp);
                        char users[1024];
                        strcpy(users, strtok(check_user, ":"));
                        char *user = strtok(users, ",");
                        while(user) {
                            if(!strcmp(user, global_user_id)) {
                                userGet = 1; break;
                            }
                            user = strtok(NULL, ",");
                        }
                    }
                    if(userGet) {
                        flag = 0; continue;
                    } else{
                        flag = 1; break;
                    }
                }
                else fprintf(tempPtr, "%s\n", tmp);
            }

            if(!flag) {
                remove("./databases/root/databases.txt");
                rename("./databases/root/temp.txt", "./databases/root/databases.txt");
                sprintf(db_dir, "./databases/%s\n", db_name);
                if (!rmdir(db_dir))
                    send(fd, "Database deleted\n", DATA_BUFFER_SIZE, 0);
                else 
                    send(fd, "Error: Database doesn't exists\n", DATA_BUFFER_SIZE, 0);
            } else {
                remove("./databases/root/temp.txt");
                send(fd, "Error: Access denied\n", DATA_BUFFER_SIZE, 0);
            }
        }
    }
    fclose(filePtr);
}

int get_db_access_info(int fd, char *user_granted, char *db, int *flag) {
    FILE *accPtr = fopen("./databases/root/accounts.txt", "r+");
    char account_db[1024];
    int db_get = 0, user_get = 0, user_access_exists = 0;

    if(!accPtr)
        send(fd, "Error: Cannot get account data\n", 1024, 0);
    else {
        while (fscanf(accPtr, "%s", account_db) != EOF){
            if (strstr(account_db, user_granted)) {
                user_get = 1;
                break;
            }
        }
    }
    
    if(user_get){
        FILE *filePtr = fopen("./databases/root/databases.txt", "a+");
        FILE *tempPtr = fopen("./databases/root/temp.txt", "a+");
        char tmp[1024], row[1024], check_user[1024], users[1024];
        user_access_exists = 0;
        
        if(!filePtr)
            send(fd, "Error: Cannot get database data\n", 1024, 0);
        else {
            while(fgets(row, 1024, filePtr)){
                if(sscanf(row, "%255[^\n]", tmp) != 1) break;
                if(strstr(tmp, db)){
                    // printf("%s\n", tmp);
                    db_get = 1;
                    strcpy(check_user, tmp);
                    strcpy(users, strtok(check_user, ":"));
                    char *user = strtok(users, ",");
                    while(user) {
                        if(!strcmp(user, user_granted)) {
                            user_access_exists = 1; break;
                        }
                        user = strtok(NULL, ",");
                    }
                    // printf("%d\n", user_access_exists);
                    if(user_access_exists) {
                        break;
                    } else{
                        fprintf(tempPtr, "%s,%s:%s\n", users, user_granted, db);
                    }
                }
                else fprintf(tempPtr, "%s\n", tmp);
            }

            if(user_access_exists && db_get) {
                *flag = 1;
                return 0;
            } else if(!user_access_exists && db_get) {
                *flag = 0;
                return 1;
            } else if(!user_access_exists) {
                *flag = 2;
                return 0;
            }
        }
    } else {
        *flag = 3;
        return 0;
    }
}

void grant_permission_cmd(int fd, char *message) {

    if(!isRoot) {
        send(fd, "Error: Access denied\n", DATA_BUFFER_SIZE, 0);
        return;
    }

    char db_name[1024], id[1024];
    char *ptrUsr = strstr(message, "GRANT PERMISSION ");
    memset(db_name, 0, DATA_BUFFER_SIZE);
    memset(id, 0, DATA_BUFFER_SIZE);
    int flag = 0;
    if(ptrUsr){
        char *temp = strtok(message, " ");
        temp = strtok(NULL, " ");
        strcpy(db_name, strtok(NULL, " "));
        // printf("temp: %s\n", temp);
        // printf("db_name: %s\n", db_name);
        if (contains_disallowed_character(db_name)){
            flag = 1;
            return;
        } else{
            temp = strtok(NULL, " ");
            // printf("temp: %s\n", temp);
            if(db_name && !strcmp(temp, "INTO")){
                strcpy(id, strtok(NULL, " "));
                // printf("id: %s\n", id);
                if (strstr(id, ";")) id[strlen(id)] = "\0";
            } else flag = 2;
        }
    }

    if(flag == 1) {
        printf("[Database name is invalid] %s:%s\n", id, db_name);
        send(fd, "Error: Database name is invalid\n", DATA_BUFFER_SIZE, 0);
    }
    else if(flag == 2)  {
        printf("[Invalid argument] %s:%s\n", id, db_name);
        send(fd, "Error: Invalid argument\n", DATA_BUFFER_SIZE, 0);
    }
    else {
        flag = 0;
        if(get_db_access_info(fd, id, db_name, &flag)){
            remove("./databases/root/databases.txt");
            rename("./databases/root/temp.txt", "./databases/root/databases.txt");
            printf("[Access granted] %s:%s\n", id, db_name);
            send(fd, "Access granted\n", DATA_BUFFER_SIZE, 0);
        } else{
            if(flag == 1){
                remove("./databases/root/temp.txt");
                printf("[User already have access] %s:%s\n", id, db_name);
                send(fd, "Error: The user already have access to the database\n", DATA_BUFFER_SIZE, 0);
            }
            else if(flag == 2){
                remove("./databases/root/temp.txt");
                printf("[Database doesn't exist] %s:%s\n", id, db_name);
                send(fd, "Error: Database doesn't exist\n", DATA_BUFFER_SIZE, 0);
            }
            else if(flag == 3){
                printf("[User doesn't exist] %s:%s\n", id, db_name);
                send(fd, "Error: User doesn't exist\n", DATA_BUFFER_SIZE, 0);
            }
        }
    }

    
}

void *db_driver(void *argv) {
    int fd = *(int *) argv;
    char command[1024], message[1024] = {}, prompt[1024], temp[1024];
    int logged_in = 0;

    recv(fd, message, 1024, 0);
    strcpy(temp, message);
    char *user = strtok(temp, ":");

    if(!strcmp(user, "root")) {
        strcpy(prompt, "root# ");
        logged_in = 1;
        isRoot = true;
    }
    else {
        user_login(fd, message, &logged_in);
        strcpy(prompt, user);
        prompt[strlen(prompt)] = '#';
        prompt[strlen(prompt)] = ' ';
    }

    strcpy(global_user_id, user);
    if(!isRoot) strcpy(global_user_password, strtok(NULL, ":"));
    else strcpy(global_user_password, "");

    // printf("%s:%s\n", global_user_id, global_user_password);
    printf("%s: login\n", user);

    while (recv(fd, command, 1024, MSG_PEEK | MSG_DONTWAIT) != 0 && logged_in == 1) {
        
        send(fd, prompt, sizeof(prompt), 0);

        int valread = read(fd, command, 1024);
        if (valread) printf("Input: [%s]\n", command);
        else if (!valread) break;

        char writetolog[1024];
        strcpy(writetolog, command);

        if (strstr(command, ":CREATE USER ") != NULL && strstr(command, " IDENTIFIED BY ") != NULL) {
            user_register(fd, command);
            if(isRoot) append_to_log(writetolog);
        } 

        else if(strstr(command, ":CREATE DATABASE ") != NULL) {
            create_cmd(fd, command);
            append_to_log(writetolog);
        }

        else if(strstr(command, ":DROP DATABASE ") != NULL) {
            drop_cmd(fd, command);
            append_to_log(writetolog);
        }

        else if(strstr(command, ":GRANT PERMISSION ") != NULL && strstr(command, " INTO ") != NULL) {
            grant_permission_cmd(fd, command);
            if(isRoot) append_to_log(writetolog);
        }
        else send(fd, "Error: Invalid command\n", DATA_BUFFER_SIZE, 0);
    }
    isRoot = false;
    close(fd);
}

int main() {
    socklen_t addrlen;
    struct sockaddr_in server_addr;
    pthread_t tid;
    char buff[1024];
    int fd = create_socket(), new_fd;

    check_files();

    if(fd) {
        printf("\nServer is running\n\n");
        while (1) {
            new_fd = accept(fd, (struct sockaddr *)&server_addr, &addrlen);
            if (new_fd >= 0) {
                printf("New connection incoming with fd: %d\n", new_fd);
                pthread_create(&tid, NULL, &db_driver, (void *) &new_fd);
            } else fprintf(stderr, "Accepting failed [%s]\n", strerror(errno));
        } 
    }
}
