# finger-user-enum
"This tool is designed as a username enumeration tool primarily targeting the default Solaris finger service. 
It also provides support for relaying queries through another finger server. 
It is a Python 3 replica of the original Perl script developed by Pentestmonkey."


Usage: finger-user-enum.pl [options] (-u username|-U users.txt) (-t host|-T ips.txt)
options are:
-m n Maximum number of resolver processes (default: 5)
-u user Check if user exists on remote system
-U file File of usernames to check via finger service
-t host Server host running finger service
-T file File of hostnames running the finger service
-r host Relay. Intermediate server which allows relaying of finger requests.
-p port TCP port on which finger service runs (default: 79)
-d Debugging output
-s n Wait a maximum of n seconds for reply (default: 5)
-v Verbose
-h This help message

