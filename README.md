<!-- README.md -->
# TCP LINUX Deamon
TCP LINUX Deamon



**Listens to a TCP port and accepts files via HTTP/POST**

It also checks the md5 sum of the file and if it does not match the one in the parameters - the file will not saved.


# Usage

## How to compile
`cc -lssl -lcrypto deamon.c -o deamon`
## How to run
`sudo ./deamon -d` for deamon mode

`sudo ./deamon -i` for interctive mode

`sudo ./deamon -h` for help


## How to send file

Example:

`curl -F "md5=ab5f2dc27085b9ceb01337fdcf18fb0b" -F "filename=CV.pdf" -F "image=@/home/anton/CV.pdf" http://localhost:80`

**Passing parameters only in this order!**

`md5=*` - md5 sum of file

`filename=*` - save file in server part with this name

`image=@*` - path to file to upload

`http://localhost:80` - address

## How to stop
`sudo kill {PID}` - where PID - process ID of the deamon (htop can help you to find it)

**It also have log file named `deamon_log.txt`.**
