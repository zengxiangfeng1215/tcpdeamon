#define _GNU_SOURCE
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <fcntl.h>

#define SIZEBUFF 2048
#define STRINGSIZE 64
#define PORTID 80

const char logfilename[] = "deamon_log.txt";

struct FileTCP {
    char md5[STRINGSIZE];
    char filename[STRINGSIZE];
    int contLen;
};

int changeSwitch(char *string) {
    if (strcasestr(string, "md5") != NULL) {
        return 1;
    } else if (strcasestr(string, "filename") != NULL) {
        return 2;
    }
    return -1;
}

int checkContentLength(char *string){
    if (strcasestr(string, "Content-Length:") != NULL){
        return 1;
    }
    return 0;
}

int checkContentType(char *string) {
    if (strcasestr(string, "Content-Type:") != NULL) {
        return 1;
    }
    return 0;
}

char *parsePost(struct FileTCP *fileTCP, char *buff, int *switcher, int *bytes_size) {
    char *token = NULL;
    token = strtok(buff, "\r\n");
    while (token) {
        if(checkContentLength(token) == 1){
            fileTCP->contLen = atoi(token + strlen("Content-Length: "));
        }
        *bytes_size -= strlen(token) + 2;
        if (*switcher == 3 && checkContentType(token) == 1) {
            return token + strlen(token) + 4;
        }
        switch (*switcher) {
            case 1:
                strcpy((char *) fileTCP->md5, token);
                *switcher = -1;
                break;
            case 2:
                strcpy((char *) fileTCP->filename, token);
                *switcher = 3;
                break;
            default:
                break;
        }
        if (*switcher != 3 && strlen(token) > 40) {
            *switcher = changeSwitch(token);
        }
        token = strtok(NULL, "\r\n");
    }
    return NULL;
}

void listenTCP() {
    int log_file = open(logfilename, O_WRONLY | O_CREAT);
    if(log_file < 0){
        perror("Can't open log file!\n");
        exit(-1);
    }

    write(log_file, "Deamon started!\n", strlen("Deamon started!\n"));

    int sock;
    struct sockaddr_in addr;
    int bytes_read;
    char *string_buff[SIZEBUFF];

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("Socket error!\n");
        write(log_file, "Socket error!\n", strlen("Socket error!\n"));
        exit(1);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORTID);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listener, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Bind Error!\n");
        write(log_file, "Bind Error!\n", strlen("Bind Error!\n"));
        exit(2);
    }

    listen(listener, 8);

    while(1) {
        sock = accept(listener, NULL, NULL);
        if (sock < 0) {
            write(log_file, "Accept Error!\n", strlen("Accept Error!\n"));
            exit(3);
        }
        FILE *post_file;
        struct FileTCP fileTCP;
        fileTCP.contLen = 0;

        //md5
        unsigned char c[MD5_DIGEST_LENGTH];
        MD5_CTX mdContext;
        MD5_Init(&mdContext);

        int switcher = -1;
        char *pointer = NULL;

        while (1) {

            if ((bytes_read = (int) recv(sock, string_buff, SIZEBUFF, 0)) <= 0)
                break;
            if (pointer == NULL) {
                if(fileTCP.contLen != 0){
                    if(fileTCP.contLen == bytes_read){
                        fileTCP.contLen -= bytes_read;
                        bytes_read -= 48;
                    }else {
                        fileTCP.contLen -= bytes_read;
                    }
                }
                pointer = parsePost(&fileTCP, (char *) string_buff, &switcher, &bytes_read);
                post_file = fopen((char *) fileTCP.filename, "wb");
                if (pointer != NULL) {
                    if(post_file == NULL){
                        write(log_file, "Can't create file!\n", strlen("Can't create file!\n"));
                        break;
                    }
                    fwrite(pointer, sizeof(char), bytes_read - 6, post_file);
                    MD5_Update(&mdContext, pointer, bytes_read - 6);
                }
            } else {
                fileTCP.contLen -= bytes_read;
                if(fileTCP.contLen <= 48){
                    if(bytes_read >= 48){
                        fwrite(string_buff, sizeof(char), bytes_read - (48 - fileTCP.contLen), post_file);
                        MD5_Update(&mdContext, string_buff, bytes_read - (48 - fileTCP.contLen));
                    }
                }else {
                    fwrite(string_buff, sizeof(char), bytes_read, post_file);
                    MD5_Update(&mdContext, string_buff, bytes_read);
                }
            }
            bzero(string_buff, SIZEBUFF);
            if(fileTCP.contLen <= 48){//if(fileTCP.contLen <= 0)
                shutdown(sock, 1);
            }
        }
        close(sock);
        fclose(post_file);
        MD5_Final(c, &mdContext);
        char md5new_string[33];
        for(int i = 0; i < MD5_DIGEST_LENGTH; ++i)
            sprintf(&md5new_string[i*2], "%02x", c[i]);


        if (strcmp(md5new_string, fileTCP.md5) != 0) {
            remove((char *) fileTCP.filename);
            write(log_file, "Hash md5 failed! File not saved! : ", strlen("Hash md5 failed! File not saved! : "));
            write(log_file, fileTCP.filename, strlen(fileTCP.filename));
            write(log_file, "\nReceived file md5 : ", strlen("\nReceived file md5 : "));
            write(log_file, md5new_string, strlen(md5new_string));
            write(log_file, "\n", strlen("\n"));
        }else{
            write(log_file, "File received and saved! : ", strlen("File received and saved! : "));
            write(log_file, fileTCP.filename, strlen(fileTCP.filename));
            write(log_file, "\n", strlen("\n"));
        }
    }
    close(listener);
}

void printUsage(){
    printf("Usage:\n\t-d\tfor daemon\n\t-i\tfor interactive\n\t-?\n\t-h\tfor help\n");
}
void printHelp(){
    printf("TCP LINUX Deamon\nListens to a TCP port and accepts files via HTTP/POST\n");
    printf("It also checks the md5 sum of the file.\nIf it does not match the one in the parameters - the file will not saved.\n\n");
    printUsage();
    printf("\n\nAuthor: Anton Shkinder\nEmail: shkinder.anton@gmail.com\n\n");
}

int main(int argc, char **argv) {
    pid_t parpid;

    const char optString[] = "dih?";
    int opt = getopt(argc, argv, optString);
    if(opt == -1){
        printUsage();
    }
    while(opt != -1){
        switch (opt){
            case 'd':
                if((parpid=fork())<0)
                {
                    printf("\nCan't fork");
                    exit(1);
                }
                else if (parpid!=0)
                    exit(0);
                setsid();
                listenTCP();
                break;
            case 'i':
                listenTCP();
            case -1:
            case 'h':
            case '?':
            default:
                printHelp();
                break;
        }
        opt = getopt(argc, argv, optString);
    }
    return 0;
}
//ab5f2dc27085b9ceb01337fdcf18fb0b CV.pdf