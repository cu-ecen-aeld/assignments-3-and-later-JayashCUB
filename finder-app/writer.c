#include <stdio.h>
#include <string.h>

#include <syslog.h>	 // Header file for logging

#include <sys/types.h>  // Header files for open syscall
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>     // Header files for write syscall

#include <errno.h>	 // Header file for errno


/* Brief - function to write a string into a file
*  params - pointer to file location and the data to be written
*  retunrs - 0 on success
*/
int writer_function(char *writefile, char *writestr)
{
	//check if arguments empty
	if (strlen(writefile) == 0 | strlen(writestr) == 0)
	{
		syslog(LOG_ERR,"Empty Arguments");
		closelog();
		return 1;
	}
	
	syslog(LOG_INFO,"Function Arguments OKAY");
	
	
	// open() syscall -> Open file / create new file to write string
	// Flags- O_RDWR,O_CREAT,O_TRUNC to read write, create if not existing
	// and truncate to zero length
	// Mode- S_IRWXU, S_IRWXG, S_IROTH - User and group can rwx and others read only
	int fd;
	fd = open(writefile,O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IROTH);
	
	if (fd == -1)
	{
		perror("Error encountered:");
		syslog(LOG_ERR,"Error creating or opening file");
		closelog();
		return 1;
	}
	
	syslog(LOG_INFO,"file opened/created sucessfully");
	
	
	// write() syscall -> write str to file
	ssize_t bytes_written;
	size_t len = strlen(writestr);
	bytes_written = write(fd,writestr,len);
	
	if (bytes_written == -1)
	{
		perror("Error encountered:");
		syslog(LOG_ERR,"Error in writing string");
		closelog();
		return 1;
	}
	else if (bytes_written != len)
	{
		perror("Error encountered:");
		syslog(LOG_ERR,"Partial write");
		closelog();
		return 1;
	}
	
	close(fd);
	syslog(LOG_INFO,"writer_function successfull");
	closelog();
	return 0;	
}

int main(int argc, char *argv[])
{
	// Open log with default ident - program name,
	// Included PID option and with LOG_USER facility
	openlog(NULL,LOG_PID,LOG_USER);
		
	// Arguments check
	if(argc != 3)
	{
		syslog(LOG_ERR,"Invalid Number of Arguments");
		if(argc < 3)
		{
			syslog(LOG_ERR,"Too FEW Argumnets");	
		}
		else
		{
			syslog(LOG_ERR,"Too many Argumnets");	
		}
		syslog(LOG_ERR,"Enter two argumnets: writefile and writestr");
		closelog();
		return 1;
	}
	
	syslog(LOG_INFO,"Arguments OKAY");
	
	
	// Getting the Argumnets
	char *writefile = argv[1];
	char *writestr = argv[2];

	// Functin call to write string to file
	int success;
	success = writer_function(writefile,writestr);

	if (success != 0)
	{
		syslog(LOG_ERR,"Could not write the String");
		closelog();
		return 1;
	}
	
	
	syslog(LOG_INFO,"String Write is SUccessful");
	closelog();
	return 0;
}
