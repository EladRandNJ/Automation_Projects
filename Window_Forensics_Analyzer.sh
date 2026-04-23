#!/bin/bash

	#3.2 Save all the results into a report (name, files extracted, etc.).
	exec > >(tee Report.txt) 2>&1 	#Exports all shell output into "Report.txt"
				#"exec" is done to create a sub shell session of all the output of this session and immendiately close after its done.
				
				

#1.1 Check the current user; exit if not ‘root’  +

function ROOT_CHECK(){	 #In order to execute the rest of the program, we must require Root permissions. This Function will check that we execute the SH file with Root permissions. If we didn't execute the SH file with Root permissions it will ask us for password and give us Root privileges.
		
		
		echo "------------------------------------"
		figlet "Pre-Check: Root status" 
		echo "------------------------------------"
		
		if [ "$EUID" -ne 0 ]; #$UID is a variable for use ID,-ne is "not equal to", User ID of root is 0
			then 
				echo "(FAILURE) You are not root, exiting ..."
				echo -e "(WARNING) Hint: Run this script with sudo or as root."
				exit 1 #exit 1, exits as an error
			else
				echo -e "(SUCCESS) You are root, continuing!"
				sleep 0.5
		fi		
}      
ROOT_CHECK

		
function START() {

		echo "------------------------------------"
		figlet "Welcome to the Memory Analyzer File" 
		echo "------------------------------------"

	#1.2 Allow the user to specify the filename; check if the file exists +
	function File_Choice() {
		
		read -p  $'(INPUT) Enter a memory file to examine: \n' MEM
		
		
		if [ ! -f "$MEM" ]; 
			then
				echo "(FAILURE) File '$MEM' does not exist, exiting ..."
				exit 1 #"exit 1" means the script will exit due to failure
			else
				echo "(SUCCESS) File '$MEM' exists"
		fi
	}
	File_Choice
	
	#1.3 Create a function to install the forensics tools if missing. +
	function Tool_Check() {
		
		echo "------------------------------------"
		figlet "TOOL CHECK" 
		echo "------------------------------------"
		echo
		
		Tool_List=( #list of the tools that must be installed

			foremost 
			binwalk 
			bulk_extractor  
			strings
		)
		
		#Starting a for loop, storing all the tool names in the tool variable
		for tool in "${Tool_List[@]}"; #@ takes all the elements in the list
		
			do
				if ! command -v $tool &> /dev/null; # ! is a negation it only proceeds if its a failure. command -v checks if commands exists
			then
			echo
			echo "(FAILURE/INSTALLING) $tool not found, installing..."
			apt-get install -y "$tool"
			echo
		else
			TOOL_PATH=$(command -v "$tool")
			echo
			echo "(SUCCESS) $tool is installed at $TOOL_PATH"
			echo
		fi
		
	done
	}
	Tool_Check
	
	
		#1.5 Data should be saved into a directory
	function saving_into_folder() { #Done before 1.4 because we create the folders that we send the carved data into
		
		echo "------------------------------------"
		figlet "Creating Memory folder" 
		echo "------------------------------------"
		echo
		
		#Creating the directory:
		
		X=memdata
		rm -rf $X  #Removes any previous versions or duplicates
		mkdir $X #Creates it again after deleting it
		
		echo "(PROGRESS)Generating a Memory Analysis Report: "
		sleep 0.5
		echo "(FILE)Memory file: $MEM"
		sleep 0.5
		echo "(SUCCESS)Generated on: $(TZ=Israel date)"
		sleep 0.5
		
		#Checking the folder exists:
		
		if [ -d $X ] #-d means if it exists and is a directory
		then
			echo "(SUCCESS) Folder '$X' exists"
			sleep 0.5
			else 
			echo "(FAILURE) Folder '$X' does not exist, exiting..."
			exit 1
		fi	
		}
		saving_into_folder
	
	
	#1.4 Use different carvers to automatically extract data
	function carving_into_folders() { #We extract information out of the memory files
		
		echo "------------------------------------"
		figlet "CARVING" 
		echo "------------------------------------"
		echo
		
			#Making extraction:
		echo
		echo "(OPERATING)Carving data using foremost..."
		echo
		mkdir -p $X/foremost
		foremost $MEM -o $X/foremost
		
			#Confirmation
		
				if [ -d "$X/foremost" ] #Checks if file exists
				then
					echo
					echo "(SUCCESS) file '$X/foremost' exists"
					else
					echo "(FAILURE) file '$X/foremost' does not exist"
				fi
			
			#Making extraction:
		echo
		echo "(OPERATING)Carving data using binwalk"
		echo
		mkdir -p $X/binwalk
		binwalk  -e -C $X/binwalk --run-as=root $MEM #-e extract -C extracts into a directory
		
			#Confirmation
		
			if [ -d "$X/binwalk" ] #Checks if file exists
				then
					echo
					echo "(SUCCESS) file '$X/binwalk' exists"
				else
					echo "(FAILURE) file '$X/binwalk' does not exist"
			fi
		
			#Making extraction:
		echo
		echo "(OPERATING)carving data using bulk_extractor"
		echo
		mkdir -p $DIR/bulki
		bulk_extractor $MEM -o $X/bulki	
				
				#Confirmation	
			if [ -d "$X/bulki" ] #Checks if file exists
				then
					echo
					echo "(SUCCESS) file '$X/bulki' exists"
				else
					echo "(FAILURE) file '$X/bulki' does not exist"
			fi
		
	}
	carving_into_folders

	
	#1.6 Attempt to extract network traffic; if found, display to the user the location and size.
	function finding_network() {
		
		echo "------------------------------------"
		figlet "Network Traffic" 
		echo "------------------------------------"
		echo
		
		if [ -f $X/bulki/packets.pcap ] #if there are pcap packets extracted
			then
				echo "(SUCCESS)A network file was found" 
				echo
				
				NETFILE=$(find -type f -name "packets.pcap") 
				
				
				echo "(FILE LOCATION)Network file path: [$NETFILE]" 
				echo
				
				NET_FILE_SIZE=$(find -type f -name "packets.pcap" -exec ls {} -l -h \; | awk '{print $5}') #-exec ls . awk extracts the size columns
				
				echo "(FILE SIZE) Network file size: $NET_FILE_SIZE" 
				echo
		else
				echo "(FAILURE) No network file was found"
				echo
		fi		
	}
	finding_network	

		#1.7 Check for human-readable (exe files, passwords, usernames, etc.).
	function STRINGS() { 		
		
		echo "------------------------------------"
		figlet "Searching for keywords" 
		echo "------------------------------------"
		echo
		
		STR_CHAR="password username http dll .exe ssh token @"
		mkdir -p $X/strings
		echo "(OPERATING) Searching $MEM memory file for human readable patterns ..."
	
		for i in $STR_CHAR
		do
			echo "(OPERATING) Strings containing  $i"  #Saves it in a file
			strings $MEM | grep -i $i >$X/strings/$i #Saves it in a file
		done			
		
	}	
	STRINGS

}	
START



function MEM(){
	
		echo "------------------------------------"
		figlet "volatility analysis" 
		echo "------------------------------------"
		echo
		
	#2.1 Check if the file can be analyzed in Volatility; if yes, run Volatility.
		echo "(PERFORMING)Checking if $MEM can be analyzed in Volatility"
		if [ -z  "$(./vol -f $MEM imageinfo 2>&1 | grep "No suggestion")" ]
		
		then
		
	#2.2 Find the memory profile and save it into a variable.
		
			echo "(SUCCESS)$MEM file can be Analyzed in Volatility"
			echo "(OPERATING)Examining $MEM file in Volatility"
			M=$(./vol -f $MEM imageinfo  2>&1  | grep Suggested | awk '{print $4}' | sed 's/,//g')
			echo "(FOLDER CREATED)Memory file profile:[$M]"
			
	#2.3 Display the running processes.
	#2.4 Display network connections.
	#2.5 Attempt to extract registry information. 
		
			V="pslist pstree hivelist userassist netscan"
			
			for i in $V
				do 
					echo "(OPERATING)Analyzing $i"
					mkdir -p $X/vol
					./vol -f $MEM --profile=$M $i >$X/vol/$i 2>&1 
				done	
		
		else
		
			echo "(FAILURE)$MEM file cannot be Analyzed in Volatility"
			
		fi
}		
MEM





#3. Results

function RESULTS() {
	#3.1 Display general statistics (time of analysis, number of found files, etc.).
	function STAT() {
		
		echo "------------------------------------"
		figlet "GENERAL STATISTICS" 
		echo "------------------------------------"
		echo 
		
		echo "(OPERATING) General Statistics of $MEM file Analysis: "
		echo
		echo "(DATA) Memory Analysis Date: $(date)" 
		echo
		TOTAL_DIR=$(find memdata -type d  | wc -l) #Checks how many directories are in the memdata
		echo
		echo "(DATA) Total number of directories: [$TOTAL_DIR]"
		echo
		TOTAL_FILES=$(find memdata -type f  | wc -l) #Checks how many files are in the memdump
		echo "(DATA) Number of files extracted:[$TOTAL_FILES]" 
		echo
	}	
STAT
	function DSPLY() {
						

		
	#3.3 Zip the extracted files and the report file.
	
		echo "------------------------------------"
		figlet "ZIPPING" 
		echo "------------------------------------"
		echo 
		
		echo "(OPERATING)Compressing memdata directory ..."
		zip -r memdata.zip memdata 1>/dev/null
		
		echo "(OPERATING)Compressing Report file ..."
		zip -r Report.zip Report.txt 1>/dev/null
		
		echo -e "(LOCATION) Compressed file details: \n$(find . -type f -name "*\.zip" -exec ls  {} -lh  \; | awk '{print "[Filename:]",$9, "[Size:]",$5}')" #-lh is for revealing the size of the file saved #Fix it make it more clear
		

	}	
	
	DSPLY

}
RESULTS
