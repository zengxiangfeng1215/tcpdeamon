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

char md5[] = "md5";
char filename[] = "filename";
char contentLength[] = "Content-Length: ";
char prefix[] = "--------------------------";
char boundary[] = "boundary";
char logfilename[] = "deamon_log.txt";

int log_file;

struct FileTCP {
    char md5[STRINGSIZE];
    char filename[STRINGSIZE];
    int contLen;
};

int changeSwitch(char *string) {
    if (strstr(string, md5) != NULL) {
        return 1;
    } else if (strstr(string, filename) != NULL) {
        return 2;
    }
    return -1;
}

int checkBoundary(char *string){
    if (strstr(string, prefix) != NULL && strstr(string, boundary) == NULL){
        return 1;
    }
    return 0;
}

int checkContentLength(char *string){
    if (strstr(string, contentLength) != NULL){
        return 1;
    }
    return 0;
}

int checkContentType(char *string) {
    if (strstr(string, "Content-Type:") != NULL) {
        return 1;
    }
    return 0;
}

char *pharsePost(struct FileTCP *fileTCP, char *buff, int *switcher, int *bytes_size) {
    char *token = NULL;
    token = strtok(buff, "\r\n");
    int flag = 0;
    while (token) {
        if(checkContentLength(token) == 1){
            fileTCP->contLen = atoi(token + strlen(contentLength));
        }
        if(flag || checkBoundary(token)){
            flag = 1;
            fileTCP->contLen -= strlen(token) + 2;
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

int formatPostFile(char *filename) {
    FILE *post_file;
    if ((post_file = fopen(filename, "rb")) != NULL) {
        fseek(post_file, 0, SEEK_END);
        long int size = ftell(post_file);
        long int size_to_remove = 48;
        long int size_to_save = size - size_to_remove;
        fclose(post_file);
        truncate(filename, size_to_save);
        return 1;
    }
    return 0;
}

int fileMD5(char *filename, char* md5_string) {
    unsigned char c[MD5_DIGEST_LENGTH];
    FILE *inFile = fopen(filename, "rb");

    MD5_CTX mdContext;
    int bytes;
    unsigned char data[SIZEBUFF];

    if (inFile == NULL) {
        perror("File can't be opened!");
        exit(6);
    }

    MD5_Init(&mdContext);
    while ((bytes = fread(data, 1, SIZEBUFF, inFile)) != 0)
        MD5_Update(&mdContext, data, bytes);
    MD5_Final(c, &mdContext);

//    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
//        printf("%02x", c[i]);

    fclose(inFile);

    char md5new_string[33];
    for(int i = 0; i < MD5_DIGEST_LENGTH; ++i)
        sprintf(&md5new_string[i*2], "%02x", c[i]);

    return strcmp(md5new_string,md5_string);
}

void listenTCP() {
    write(log_file, "Deamon started!\n", strlen("Deamon started!\n"));

    int sock;
    struct sockaddr_in addr;
    int bytes_read;
    char *string_buff[SIZEBUFF];
    struct FileTCP fileTCP;
    fileTCP.contLen = 0;

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

        int switcher = -1;
        char *pointer = NULL;

        while (1) {

            if ((bytes_read = (int) recv(sock, string_buff, SIZEBUFF, 0)) <= 0)
                break;
            if (pointer == NULL) {
                if(fileTCP.contLen != 0){
                    fileTCP.contLen -= bytes_read;
                }
                pointer = pharsePost(&fileTCP, (char *) string_buff, &switcher, &bytes_read);
                post_file = fopen((char *) fileTCP.filename, "wb");
                if (pointer != NULL) {
                    if(post_file == NULL){
                        write(log_file, "Can't create file!\n", strlen("Can't create file!\n"));
                        break;
                    }
                    fwrite(pointer, sizeof(char), bytes_read - 6, post_file);
                }
            } else {
                fileTCP.contLen -= bytes_read;
                fwrite(string_buff, sizeof(char), bytes_read, post_file);
            }
            bzero(string_buff, SIZEBUFF);
            if(fileTCP.contLen <= 0){
                shutdown(sock, 1);
            }
        }

        close(sock);
        fclose(post_file);

        if (formatPostFile((char *) fileTCP.filename) == 0) {
            write(log_file, "truncate Error!\n", strlen("truncate Error!\n"));
            exit(5);
        }

        if (fileMD5((char *) fileTCP.filename, (char *) fileTCP.md5) != 0) {
            remove((char *) fileTCP.filename);
            write(log_file, "Hash md5 failed! File not saved!\n", strlen("Hash md5 failed! File not saved!\n"));
        }else{
            write(log_file, "File received and saved!\n", strlen("File received and saved!\n"));
        }
    }
    close(listener);
}


int main(int argc, char **argv) {
    pid_t parpid;

    if (argc < 2)
    {
        printf("Usage: ./daemon -d for daemon or ./daemon -i for interactive \n Also send WD in 3 param if you need.\n");
        exit(1);
    }

    if (argc == 3){
        chdir(argv[2]);
    }

    log_file = open(logfilename, O_WRONLY | O_CREAT);
    if(log_file < 0){
        perror("Can't open log file!\n");
    }

    if (strcmp(argv[1],"-i")==0)
        listenTCP();
    else if (strcmp(argv[1],"-d")==0)
    {
        if((parpid=fork())<0)
        {
            printf("\nCan't fork");
            exit(1);
        }
        else if (parpid!=0)
            exit(0);
        setsid();
        listenTCP();
    }
    else
    {
        printf("Usage: ./daemon -d for daemon or ./daemon -i for interactive\n Also send WD in 3 param if you need.\n");
        exit(1);
    }
    return 0;
}
//ab5f2dc27085b9ceb01337fdcf18fb0b CV.pdf