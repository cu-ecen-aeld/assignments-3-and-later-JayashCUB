/**
 * File: aesdsocket.c
 *
 * Author: Jayash Arun raulkar
 * Date: 29 Feb 2024
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
#include <pthread.h>
#include <time.h>
#include "queue.h"

#define PORT         		"9000"
#define USE_AESD_CHAR_DEVICE   (1)
#if (USE_AESD_CHAR_DEVICE == 0)
    #define FILENAME           "/var/tmp/aesdsocketdata"
#elif (USE_AESD_CHAR_DEVICE == 1)
    #define FILENAME           "/dev/aesdchar"
#endif
#define BUFF_SIZE   		1024
#define SUCCESS      		0
#define FAILURE      		-1
#define DELAY_TIMEPERIOD	10

int exit_flag = 0;
int run_as_daemon = 0;
int sock_fd;
char client_ip[INET_ADDRSTRLEN];

typedef struct socket_node {
    pthread_t thread_id;
    int accepted_fd;
    bool thread_complete;
    pthread_mutex_t *thread_mutex;
    SLIST_ENTRY(socket_node) node_count;
}socket_node_t;

void signal_handler(int signo);
void close_n_exit(void);
int run_as_daemon_func();

#if (USE_AESD_CHAR_DEVICE == 0)
void *timestamp_thread(void *thread_node)
{
    	socket_node_t *node = NULL;
    	int status = FAILURE;
    	int file_fd = -1;
    	struct timespec time_period;
    	char output[BUFF_SIZE] = {'\0'};
    	time_t curr_time;
    	struct tm *tm_time;
    	int written_bytes = 0;
    	if (NULL == thread_node)
    	{
    	    	return NULL;
    	}
    	node = (socket_node_t *)thread_node;
    
    	while (!exit_flag)
    	{
        	if (clock_gettime(CLOCK_MONOTONIC, &time_period) != SUCCESS)
        	{
            		syslog(LOG_ERR, "ERROR: Failed to get time");
            		status = FAILURE;
            		goto exit;
        
        	}
        	time_period.tv_sec += DELAY_TIMEPERIOD;
        
        	if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &time_period, NULL) != SUCCESS)
        	{
            		syslog(LOG_ERR, "ERROR: Failed to sleep for 10 sec");
            		status = FAILURE;
            		goto exit;       
        	}
        	curr_time = time(NULL);
        	if (curr_time == FAILURE)
        	{
            		syslog(LOG_ERR, "ERROR: Failed to get current time");
            		status = FAILURE;
            		goto exit;      
        	}       
        	tm_time = localtime(&curr_time);
        	if (tm_time == NULL)
        	{
            		syslog(LOG_ERR, "ERROR: Failed to fill tm struct");
            		status = FAILURE;
            		goto exit;      
        	}
        
        	if (strftime(output, sizeof(output), "timestamp: %Y %B %d, %H:%M:%S\n", tm_time) == SUCCESS)
        	{
            		syslog(LOG_ERR, "ERROR: Failed to convert tm into string");
            		status = FAILURE;
            		goto exit;        
        	}	
        
        	file_fd = open(FILENAME, O_CREAT|O_RDWR|O_APPEND, S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);
        	if (file_fd == FAILURE)
        	{
            		syslog(LOG_ERR, "ERROR: Failed to create/open file");
            		status = FAILURE;
            		goto exit;
        	}       
        	if (pthread_mutex_lock(node->thread_mutex) != SUCCESS)
        	{
            		syslog(LOG_ERR, "ERROR: Failed to lock mutex");
            		status = FAILURE;
            		goto exit;
        	}
        	// Writing the timestamp
        	written_bytes = write(file_fd, output, strlen(output));
        	if (written_bytes != strlen(output))
        	{
            		syslog(LOG_ERR, "ERROR: Failed to write timestamp to file");
            		status = FAILURE;
            		pthread_mutex_unlock(node->thread_mutex);
            		goto exit;
        	}
        	if (pthread_mutex_unlock(node->thread_mutex) != SUCCESS)
        	{
            		syslog(LOG_ERR, "ERROR: Failed to unlock mutex");
            		status = FAILURE;
            		goto exit;
        	}
        	status = SUCCESS;
        	close(file_fd);
    	}
	exit:
     	if (status == FAILURE) 
    	{
    		node->thread_complete = false;
	} 
	else 
	{
    		node->thread_complete = true;
	}
     	return thread_node;
}
#endif


void *data_thread(void *thread_node)
{
    	int recv_bytes = 0;
    	char buffer[BUFF_SIZE] = {'\0'};
    	bool packet_complete = false;
    	int written_bytes = 0;
    	socket_node_t *node = NULL;
    	int status = FAILURE;
    	int file_fd = -1;
    	if (thread_node == NULL)
    	{
    	    return NULL;
    	}
    	else
    	{
    	    node = (socket_node_t *)thread_node;
    	    file_fd = open(FILENAME, O_CREAT|O_RDWR|O_APPEND, 
    	                   S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);
    	    if (file_fd == FAILURE)
    	    {
    	        syslog(LOG_ERR, "ERROR: Failed to create/open file");
    	        status = FAILURE;
    	        goto exit;
    	    }
	
    	    // Receive data till new line is found
    	    do
    	    {
    	        memset(buffer, 0, BUFF_SIZE);
    	        recv_bytes = recv(node->accepted_fd, buffer, BUFF_SIZE, 0);
    	        if (recv_bytes == FAILURE)
    	        {
    	            syslog(LOG_ERR, "ERROR: Failed to recieve byte from client");
    	            status = FAILURE;
    	            goto exit;
    	        }
    	        
    	        if (pthread_mutex_lock(node->thread_mutex) != SUCCESS)
    	        {
    	            syslog(LOG_ERR, "ERROR: Failed to lock mutex");
    	            status = FAILURE;
    	            goto exit;
    	        }
    	        
    	        written_bytes = write(file_fd, buffer, recv_bytes);
    	        if (written_bytes != recv_bytes)
    	        {
    	            syslog(LOG_ERR, "ERROR: Failed to write data");
    	            status = FAILURE;
    	            pthread_mutex_unlock(node->thread_mutex);
    	            goto exit;
    	        }
    	        if (pthread_mutex_unlock(node->thread_mutex) != SUCCESS)
    	        {
    	            syslog(LOG_ERR, "ERROR: Failed to unlock mutex");
    	            status = FAILURE;
    	            goto exit;
    	        }
    	        // Check if new line
    	        if ((memchr(buffer, '\n', recv_bytes)) != NULL)
    	        {
    	            packet_complete = true;
    	        }
    	    } while (!packet_complete);

    	    packet_complete = false;
	    
            close(file_fd);
            /* open file in read mode */
            file_fd = open(FILENAME, O_RDONLY, S_IRUSR | S_IRGRP | S_IROTH);
            if (FAILURE == file_fd)
            {
                syslog(LOG_ERR, "Error opening %s file: %s", FILENAME, strerror(errno));               
    	        status = FAILURE;
    	        goto exit;
    	    }

    	    // read till EOF 
    	    int read_bytes = 0;
    	    int send_bytes = 0;
    	    do
    	    {
    	        memset(buffer, 0, BUFF_SIZE);
    	        read_bytes = read(file_fd, buffer, BUFF_SIZE);
    	        if (read_bytes == -1)
    	        {
    	            	syslog(LOG_ERR, "ERROR: Failed to read from file");
   		    	status = FAILURE;
              		goto exit;
            	}
            	syslog(LOG_INFO, "read succesful is: %d", read_bytes);
            	syslog(LOG_INFO, "read succesful is: %s", buffer);
            			
            	if (read_bytes > 0)
            	{
        		// Send file data back to the client
            	    	send_bytes = send(node->accepted_fd, buffer, read_bytes, 0);
                	if (send_bytes != read_bytes)
                	{
                    		syslog(LOG_ERR, "ERROR: Failed to Send bytes to client");
                    		status = FAILURE;
                    		goto exit;
                	}
                	status = SUCCESS;
            	}
            } while (read_bytes > 0);
    	}
	exit:
		if (file_fd != -1)
    		{
        		close(file_fd);
    		}
    		if (close(node->accepted_fd) == SUCCESS)
    		{
    		    	syslog(LOG_INFO, "Closed connection from %s", client_ip);
    		}
    		if (status == FAILURE) 
    		{
    			node->thread_complete = false;
		} 
		else 
		{
    			node->thread_complete = true;
		}

    	return thread_node;
}


int main(int argc, char *argv[]) 
{
	int status = SUCCESS;
	socket_node_t *data_ptr = NULL;
    	socket_node_t *data_ptr_temp = NULL;
    	pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;
	
	openlog(NULL, 0, LOG_USER);
	
	// Check for -d parameter
	if ((argc == 2) && (strcmp(argv[1], "-d") == 0))
	{
		printf("RUNNING DAEMON\n");
        	run_as_daemon = 1;
        	syslog(LOG_INFO, "Running aesdsocket as daemon(background)");
    	}
    	
    	// Register signal handlers for SIGINT and SIGTERM
    	struct sigaction sa;
    	sigemptyset(&sa.sa_mask);
    	sa.sa_flags = 0;
    	sa.sa_handler = signal_handler;
    
    	if (sigaction(SIGINT, &sa, NULL) != SUCCESS)
    	{
        	syslog(LOG_ERR, "ERROR: Failed to register SIGINT");
        	return FAILURE;
    	}
    	if (sigaction(SIGTERM, &sa, NULL) != SUCCESS)
    	{
        	syslog(LOG_ERR, "ERROR: Failed to register SIGTERM");
        	return FAILURE;
    	}
    	syslog(LOG_INFO, "Signal Handler registered");
    	
    	SLIST_HEAD(socket_head, socket_node) head;
    	SLIST_INIT(&head);
    	
        // Create a socket
        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd == FAILURE) 
        {
        	syslog(LOG_ERR, "ERROR: Failed to create socket");
        	return FAILURE;
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
        	status = FAILURE;
        	goto exit;
    	}
    	syslog(LOG_INFO, "Address returned from getaddrinfo");  	
    	  
    	// Allow for reuse of port 9000
    	int reuse_opt = 1;
    	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &reuse_opt, sizeof(int)) == FAILURE) 
    	{
        	syslog(LOG_ERR, "ERROR: Failed to setsockopt");
        	if (server_addr_info != NULL)
        	{
            		freeaddrinfo(server_addr_info);
        	}
        	status = FAILURE;
        	goto exit;
    	}
    	syslog(LOG_INFO, "Set port reuse option");
	
	// Bind socket and port
    	if (bind(sock_fd, server_addr_info->ai_addr, server_addr_info->ai_addrlen) != SUCCESS)
    	{
        	syslog(LOG_PERROR, "ERROR: Failed to bind");
        	if (server_addr_info != NULL)
        	{
            		freeaddrinfo(server_addr_info);
        	}
        	status = FAILURE;
        	goto exit;
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
        	if(run_as_daemon_func() != SUCCESS)
        	{
        		syslog(LOG_ERR, "ERROR: Failed to run as a daemon");
        		status = FAILURE;
        		goto exit;
        	}
    	}
	
	// Listen on Socket
	if (listen(sock_fd, 10) == -1) 
	{
        	syslog(LOG_ERR, "ERROR: Failed to listen");
        	status = FAILURE;
        	goto exit;
    	}
	
#if (USE_AESD_CHAR_DEVICE == 0)	
	// Node for timestamp thread
    	data_ptr = (socket_node_t *)malloc(sizeof(socket_node_t));
    	if (data_ptr == NULL)
    	{
        	syslog(LOG_ERR, "ERROR: Failed to malloc");
        	status = FAILURE;
        	goto exit;
    	}
	
	data_ptr->thread_complete = false;
    	data_ptr->thread_mutex = &thread_mutex;
    	// Thread for timestamp
    	if (pthread_create(&data_ptr->thread_id, NULL, timestamp_thread, data_ptr) != SUCCESS)
    	{
        	syslog(LOG_ERR, "ERROR: Failed to Create timer thread");
        	free(data_ptr);
        	data_ptr = NULL;
        	status = FAILURE;
        	goto exit;
    	} 
    	SLIST_INSERT_HEAD(&head, data_ptr, node_count);
#endif	
    	
	while(!exit_flag)
	{
        	struct sockaddr_in client_addr;
        	socklen_t client_addr_len = sizeof(client_addr);
        	int accepted_fd = accept(sock_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        	if (accepted_fd == FAILURE) 
        	{
            		syslog(LOG_ERR, "ERROR: Failed to accept");
        	}
        	else
        	{
        		syslog(LOG_INFO, "connection accepted: %d",accepted_fd);
        		// Log accepted connection
        		// converts binary ip address to string format
        		
        		if (inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN) == NULL)
        		{
        			syslog(LOG_ERR, "ERROR: Failed to get ip");	
        		}
        		syslog(LOG_INFO, "Accepted connection from %s", client_ip);
        		
        		// Creating socket node for each connection
            		data_ptr = (socket_node_t *)malloc(sizeof(socket_node_t));
            		if (data_ptr == NULL)
            		{
                		syslog(LOG_ERR, "ERROR: Failed to malloc");
                		status = FAILURE;
                		goto exit;
            		}
            		
            		data_ptr->accepted_fd = accepted_fd;
            		data_ptr->thread_complete = false;
            		data_ptr->thread_mutex = &thread_mutex;
            		// Create thread for each connection
            		if (SUCCESS != pthread_create(&data_ptr->thread_id, NULL, data_thread, data_ptr))
            		{
                		syslog(LOG_ERR, "ERROR: Failed to create connection thread");
                		free(data_ptr);
                		data_ptr = NULL;
                		status = FAILURE;
                		goto exit;
            		} 
            		SLIST_INSERT_HEAD(&head, data_ptr, node_count);
            		
        	}
        	
        	// If thread exited, join thread and remove from linkedlist
        	data_ptr = NULL;
        	SLIST_FOREACH_SAFE(data_ptr, &head, node_count, data_ptr_temp)
        	{
            		if (data_ptr->thread_complete == true)
            		{
                		pthread_join(data_ptr->thread_id, NULL);
                		SLIST_REMOVE(&head, data_ptr, socket_node, node_count);
                		free(data_ptr);
                		data_ptr = NULL;
            		}
        	}
        	
	}
	
	exit:
    		close_n_exit();
    		
    		while (!SLIST_EMPTY(&head))
    		{
        		data_ptr = SLIST_FIRST(&head);
        		SLIST_REMOVE_HEAD(&head, node_count);
        		pthread_join(data_ptr->thread_id, NULL);
        		free(data_ptr);
        		data_ptr = NULL;
    		}
    		pthread_mutex_destroy(&thread_mutex);
    		printf("EXITING PROCESS\n");
    return status;       	
        	
}



void signal_handler(int signo)
{
 	if ((signo == SIGINT) || (signo == SIGTERM))
 	{
 		exit_flag = 1;
 		syslog(LOG_DEBUG, "Caught signal, exiting");
 	}
 	printf("FOUND SIGNAL!!!!!!!\n");
}


void close_n_exit(void) 
{
 	// Close open sockets
 	if (sock_fd >= 0) 
 	{
 		syslog(LOG_INFO, "Closing sock_fd: %d", sock_fd);
 		close(sock_fd);
 		syslog(LOG_INFO, "Closed sock_fd: %d", sock_fd);
 	}

 	// Delete the file
 	#if (USE_AESD_CHAR_DEVICE == 0)
 	remove(FILENAME);
 	#endif
	
 	// Close syslog
 	syslog(LOG_INFO, "Closing syslog");
 	closelog();

}

int run_as_daemon_func() 
{
    	pid_t pid, sid;

    	// Fork the parent process
    	fflush(stdout);
    	pid = fork();

    	// Error occurred during fork
    	if (pid < 0) 
    	{
        	syslog(LOG_ERR, "ERROR: Failed to fork");
        	return FAILURE;
    	}

    	// Terminate parent process on successful fork
    	else if (pid > 0) 
    	{
    		syslog(LOG_INFO, "Terminating Parent");
        	exit(SUCCESS);
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
        		return FAILURE;
    		}

    		// Change working directory
    		if ((chdir("/")) < 0) 
    		{
        		syslog(LOG_ERR, "ERROR: Failed to chdir");
        		return FAILURE;
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
            		return FAILURE;       
        	}
        	if (dup2(fd, STDIN_FILENO)  == -1)
        	{
            		syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
            		close(fd);
            		return FAILURE;    
        	}
        	if (dup2(fd, STDOUT_FILENO)  == -1)
        	{
            		syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
            		close(fd);
            		return FAILURE;    
        	}
        	if (dup2(fd, STDERR_FILENO)  == -1)
        	{
            		syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
            		close(fd);
            		return FAILURE;    
        	}
        	close(fd);
	}
	return SUCCESS;	
}

