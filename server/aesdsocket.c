/**
 * File: aesdsocket.c
 *
 * Author: Jayash Arun raulkar
 * Date: 22 Feb 2024
 * References: AESD Course Slides
 */

/* Header files */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define PORT         	"9000"
#define FILENAME      	"/var/tmp/aesdsocketdata"
#define BUFF_SIZE   	1024

int exit_flag = 0;
int run_as_daemon = 0;
int sock_fd, accepted_fd, file_fd;

void signal_handler(int signo);
void close_n_exit(int exit_code);
void run_as_daemon_func();

int main(int argc, char *argv[]) 
{

	openlog(NULL, 0, LOG_USER);
	
	// Check for -d parameter
	if ((argc == 2) && (strcmp(argv[1], "-d") == 0))
	{
        	run_as_daemon = 1;
        	syslog(LOG_INFO, "Running aesdsocket as daemon(background)");
    	}
    	
    	// Register signal handlers for SIGINT and SIGTERM
    	if (signal(SIGINT, signal_handler) == SIG_ERR)
    	{
        	syslog(LOG_ERR, "ERROR: Failed to register signal handler");
    	}
    	if (signal(SIGTERM, signal_handler) == SIG_ERR)
    	{
        	syslog(LOG_ERR, "ERROR: Failed to register signal handler");
    	}
    	syslog(LOG_INFO, "Signal Handler registered");
    	
        // Create a socket
        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd == -1) 
        {
        	syslog(LOG_ERR, "ERROR: Failed to create socket");
        	close_n_exit(EXIT_FAILURE);
    	} 
    	syslog(LOG_INFO, "Socket creted succesfully: %d",sock_fd);   	
    	
    	// Setting addrinfo hints
    	struct addrinfo hints;
     	memset(&hints, 0, sizeof(hints));
   	hints.ai_family = AF_INET;
    	hints.ai_socktype = SOCK_STREAM;
    	hints.ai_flags = AI_PASSIVE;
    	
    	// Getting server address using getaddrinfo()
    	struct addrinfo *server_addr_info = NULL;
    	if (getaddrinfo(NULL, PORT, &hints, &server_addr_info) != 0)
    	{
        	syslog(LOG_ERR, "ERROR: Failed to get address");
        	if (server_addr_info != NULL)
        	{
            		freeaddrinfo(server_addr_info);
        	}
        	close_n_exit(EXIT_FAILURE);
    	}
    	syslog(LOG_INFO, "Address returned from getaddrinfo");  	
    	  
    	// Allow for reuse of port 9000
    	// ChatGpt Prompt : "how to use SO_REUSEADDR to allow for reuse of port"
    	int reuse_opt = 1;
    	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &reuse_opt, sizeof(int)) == -1) 
    	{
        	syslog(LOG_ERR, "ERROR: Failed to setsockopt");
        	if (server_addr_info != NULL)
        	{
            		freeaddrinfo(server_addr_info);
        	}
        	close_n_exit(EXIT_FAILURE);
    	}
    	syslog(LOG_INFO, "Set port reuse option");
	
	// Bind socket and port
    	if (bind(sock_fd, server_addr_info->ai_addr, server_addr_info->ai_addrlen) != 0)
    	{
        	syslog(LOG_PERROR, "ERROR: Failed to bind");
        	if (server_addr_info != NULL)
        	{
            		freeaddrinfo(server_addr_info);
        	}
        	close_n_exit(EXIT_FAILURE);
    	}
    	syslog(LOG_INFO, "Bind Successful");
	
	// Free server_addr_info after bind
    	if (server_addr_info != NULL)
    	{
        	freeaddrinfo(server_addr_info);
        	syslog(LOG_INFO, "Memory Free");
    	}
	
	// After acquiring address and binding depending on -d param
	if (run_as_daemon) 
	{
		syslog(LOG_INFO, "Running as daemon");
        	run_as_daemon_func();
    	}
	
	// Listen on Socket
	if (listen(sock_fd, 10) == -1) 
	{
        	syslog(LOG_ERR, "ERROR: Failed to listen");
        	close_n_exit(EXIT_FAILURE);
    	}
	
	
	char buffer[BUFF_SIZE] = {'\0'};
    	bool packet_complete = false;
    	int recv_bytes = 0;
    	int written_bytes = 0;
    	
	while(!exit_flag)
	{
        	struct sockaddr_in client_addr;
        	socklen_t client_addr_len = sizeof(client_addr);
        	accepted_fd = accept(sock_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        	if (accepted_fd == -1) 
        	{
            		syslog(LOG_WARNING, "WARNING: Failed to accept, retrying ...");
            	continue; // Continue accepting connections
        	}
        	syslog(LOG_INFO, "connection accepted: %d",accepted_fd);
        	
        	// Log accepted connection
        	// converts binary ip address to string format
        	char client_ip[INET_ADDRSTRLEN];
        	if (inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN) == NULL)
        	{
        		syslog(LOG_ERR, "ERROR: Failed to get ip");	
        	}
        	syslog(LOG_INFO, "Accepted connection from %s", client_ip);
        	
        	// Open file for aesdsocketdata
    		file_fd = open(FILENAME, O_CREAT | O_RDWR | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    		if (file_fd == -1)
    		{
        		syslog(LOG_ERR, "ERROR: Failed to create/open file");
        		close_n_exit(EXIT_FAILURE);
    		}
    		syslog(LOG_INFO, "File open successfully :%d",file_fd);
        	
        	do
        	{
        		memset(buffer, 0, BUFF_SIZE);
            		// recieve data from client
            		recv_bytes = recv(accepted_fd, buffer, BUFF_SIZE, 0);
            		if (recv_bytes == -1)
            		{
                		syslog(LOG_ERR, "ERROR: Failed to recieve byte from client");
        			close_n_exit(EXIT_FAILURE);
            		}
            		syslog(LOG_INFO, "data recieved");
            		
            		// write the string received to the file 
            		written_bytes = write(file_fd, buffer, recv_bytes);
            		if (written_bytes != recv_bytes)
            		{
                		syslog(LOG_ERR, "ERROR: Failed to write bytes to file");
        			close_n_exit(EXIT_FAILURE);
            		}
            		syslog(LOG_INFO, "data write to file");
            		
            		/* check for new line */
            		if (NULL != (memchr(buffer, '\n', recv_bytes)))
            		{
                		packet_complete = true;
            		}
        		
        	}while(!packet_complete);
        	
        	packet_complete = false;

        	// Set file pos to begining of file
        	off_t offset = lseek(file_fd, 0, SEEK_SET);
        	if (offset == -1)
        	{
        		syslog(LOG_ERR, "ERROR: Failed to SET file offset");
        		close_n_exit(EXIT_FAILURE);
        	}
        	syslog(LOG_INFO, "lseek set");
        	
        	/* read file contents till EOF */
        	int read_bytes = 0;
        	int send_bytes = 0;
        	do
        	{
        		memset(buffer, 0, BUFF_SIZE);
            		read_bytes = read(file_fd, buffer, BUFF_SIZE);
            		if (read_bytes == -1)
            		{
                		syslog(LOG_ERR, "ERROR: Failed to read from file");
        			close_n_exit(EXIT_FAILURE);
            		}
            		syslog(LOG_INFO, "read succesful is: %d", read_bytes);
            		syslog(LOG_INFO, "read succesful is: %s", buffer);
            		
            		if (read_bytes > 0)
            		{
                		/* send file data to client */
                		send_bytes = send(accepted_fd, buffer, read_bytes, 0);
                		if (send_bytes != read_bytes)
                		{
                    			syslog(LOG_ERR, "ERROR: Failed to Send bytes to client");
        				close_n_exit(EXIT_FAILURE);
                		}
                		syslog(LOG_INFO, "sent to client: %d",send_bytes);
            		}
        	}while(read_bytes > 0);
        	
        	close(file_fd);
     		if (close(accepted_fd) == 0)
        	{
            		syslog(LOG_INFO, "Closed connection from %s", client_ip);
        	}
        
		//close_n_exit(EXIT_SUCCESS);
	}
	
	//return 0;
}



void signal_handler(int signo)
{
 	if ((signo == SIGINT) || (signo == SIGTERM))
 	{
 		exit_flag = 1;
 		syslog(LOG_DEBUG, "Caught signal, exiting");
 	        close_n_exit(EXIT_SUCCESS);
 	}
}


void close_n_exit(int exit_code) 
{
 	// Close open sockets
 	if (sock_fd >= 0) 
 	{
 		syslog(LOG_INFO, "Closing sock_fd: %d", sock_fd);
 		close(sock_fd);
 		syslog(LOG_INFO, "Closed sock_fd: %d", sock_fd);
 	}
 	if (accepted_fd >=0) 
 	{
 		syslog(LOG_INFO, "Closing accepted_fd: %d", accepted_fd);
 	   	close(accepted_fd);
 	   	syslog(LOG_INFO, "Closed accepted_fd: %d", accepted_fd);
 	}
 	// Close file descriptors
 	if (file_fd >= 0) 
 	{
 		syslog(LOG_INFO, "Closing file_fd: %d", file_fd);
 	   	close(file_fd);
 	   	syslog(LOG_INFO, "Closied file_fd: %d", file_fd);
 	}
 	// Delete the file
 	remove("/var/tmp/aesdsocketdata");
	
 	// Close syslog
 	syslog(LOG_INFO, "Closing syslog");
 	closelog();
	
 	// Exit
 	exit(exit_code);
}

void run_as_daemon_func() 
{
    	pid_t pid, sid;

    	// Fork the parent process
    	fflush(stdout);
    	pid = fork();

    	// Error occurred during fork
    	if (pid < 0) 
    	{
        	syslog(LOG_ERR, "ERROR: Failed to fork");
        	close_n_exit(EXIT_FAILURE);
    	}

    	// Terminate parent process on successful fork
    	else if (pid > 0) 
    	{
    		syslog(LOG_INFO, "Terminating Parent");
        	exit(EXIT_SUCCESS);
    	}
	
	else if (pid == 0)
	{
		syslog(LOG_INFO, "Created Child Succesfully");
		// In child Process ->
    		// Creating new session for child
    		sid = setsid();
    		if (sid < 0) 
    		{
        		syslog(LOG_ERR, "ERROR: Failed to setsid");
        		close_n_exit(EXIT_FAILURE);
    		}

    		// Change working directory
    		if ((chdir("/")) < 0) 
    		{
        		syslog(LOG_ERR, "ERROR: Failed to chdir");
        		close_n_exit(EXIT_FAILURE);
    		}

    		// Close standard fd 0, 1 and 2
    		close(STDIN_FILENO);
    		close(STDOUT_FILENO);
    		close(STDERR_FILENO);
    		
    		
    		/* redirect standard files to /dev/null */
        	int fd = open("/dev/null", O_RDWR);
        	if (fd == -1)
        	{
            		syslog(LOG_PERROR, "open:%s\n", strerror(errno));
            		close(fd);
            		close_n_exit(EXIT_FAILURE);       
        	}
        	if (dup2(fd, STDIN_FILENO)  == -1)
        	{
            		syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
            		close(fd);
            		close_n_exit(EXIT_FAILURE);    
        	}
        	if (dup2(fd, STDOUT_FILENO)  == -1)
        	{
            		syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
            		close(fd);
            		close_n_exit(EXIT_FAILURE);    
        	}
        	if (dup2(fd, STDERR_FILENO)  == -1)
        	{
            		syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
            		close(fd);
            		close_n_exit(EXIT_FAILURE);    
        	}
        	close(fd);
	}
	
}

