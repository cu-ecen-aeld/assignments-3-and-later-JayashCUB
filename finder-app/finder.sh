#!/bin/bash

#Course- AESD
#Author - Jayash Arun Raulkar

# Check number of arguments correctness
if [ $# -eq 2 ]
then
	echo "finder.sh args are okay"
else
	echo "Invalid args"
	if [ $# -eq 0 ]
	then
		echo "Give directory and searchWord"
	elif [ $# -eq 1 ]
	then
		echo "too less arguments"	
	else
		echo "too many arguments"
	fi
	exit 1
fi



# Get arguments in variables
filesdir=$1
searchstr=$2



# Check if argument is empty string
if [ -z $filesdir ]
then
    echo "Empty filesdir argument"
    exit 1
fi

if [ -z $searchstr ]
then
    echo "Empty searchstr argument"
    exit 1
fi



# Check if directory exists or not
if [ -d $filesdir ]
then
	echo "directory exists"
else
	echo "diretory doesn't exists"
	exit 1
fi

# Getting count of files and sub-directories
# This part generated using ChatGPT 
# Prompt: "how to count output of ls command"
X=$( ls $filesdir | wc -l )


# Getting matching lines count
# This part generated using ChatGPT 
# Prompt: "how to find number of matching lines found in a directory"
Y=$( grep -r "$searchstr" $filesdir | wc -l )



echo "The number of files are $X and the number of matching lines are $Y"
exit 0
