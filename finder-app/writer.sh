#!/bin/bash

#Course- AESD
#Author - Jayash Arun Raulkar



# Check number of arguments correctness
if [ $# -eq 2 ]
then
	echo "write.sh args are okay"
else
	echo "Invalid args"
	if [ $# -eq 0 ]
	then
		echo "Give full path and data"
	elif [ $# -eq 1 ]
	then
		echo "too less arguments"	
	else
		echo "too many arguments"
	fi
	exit 1
fi



# Get arguments in variables
writefile=$1
writestr=$2



# Check if argument is empty string
if [ -z $writefile ]
then
    echo "Empty writefile argument"
    exit 1
fi

if [ -z $writestr ]
then
    echo "Empty writestr argument>"
    exit 1
fi



# Extracting directory path from aurgument
# This part generated using ChatGPT 
# Prompt: "how to extract directory from file path"
filepath=$( dirname $writefile )

# Create directory path if it doesn't exist
mkdir -p $filepath

# Creating the file with the required data and use redirection to overwrite
echo $writestr > $writefile



# Check if the file creation was successful
if [ $? -ne 0 ]
then
    echo "Could not create the file"
    exit 1
fi


echo "File created successfully"
exit 0

