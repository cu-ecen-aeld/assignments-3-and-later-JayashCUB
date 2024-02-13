#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    
    int wait_to_obtain_in_sec = thread_func_args->wait_to_obtain_ms / 1000;
    int wait_to_release_in_sec = thread_func_args->wait_to_release_ms / 1000;

    sleep(wait_to_obtain_in_sec);	//wiat before obtaining mutex
    
    // Obtain Mutex
    int mutex_lock = pthread_mutex_lock(thread_func_args->mutex);
    if(mutex_lock != 0)
    {
    	//error in mutex lock
    	ERROR_LOG("Failed to lock Mutex");
    	return thread_param;
    }
    
    sleep(wait_to_release_in_sec);	//wait while having mutex
	
    // Give Mutex
    int mutex_unlock = pthread_mutex_unlock(thread_func_args->mutex);
    if(mutex_unlock != 0)
    {
    	//error in mutex unlock
    	ERROR_LOG("Failed to unlock Mutex");
    	return thread_param;
    }

    thread_func_args->thread_complete_success = true;
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
     
    //Allocate memory for thread data 
    struct thread_data* thread_data_args = (struct thread_data*)malloc(sizeof(struct thread_data));
    if (thread_data_args == NULL) 
    {
        ERROR_LOG("Failed to allocate memory for thread_data.");
        return false;
    }
    
    thread_data_args->mutex = mutex;
    thread_data_args->wait_to_obtain_ms = wait_to_obtain_ms;
    thread_data_args->wait_to_release_ms = wait_to_release_ms;
    thread_data_args->thread_complete_success = false;    
    
    int result = pthread_create(thread, NULL, threadfunc, (void*)thread_data_args);
    if (result != 0) 
    {
        ERROR_LOG("Failed to create thread");
        // Free the allocated memory
        free(thread_data_args);
        return false;
    }
     
    return true;
}

