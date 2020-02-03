# Simple-Web-Bash

Simple web bash on C for school project.
Supports:  
        - Multiple client connections  
        - Simple commands with arguments (for example ls -l)  
        - Piped command. Limited to one pipe (for example ls -l | wc -l)  
        - Output redirection (for example ls -al > test.txt)  
        - Exit, history and cd commands are supported  

Compilation:  

```
gcc client.c -o client_executable
gcc server.c -o server_executable
```  

Usage:  

```
./server_executable port_number
```

```
./client_executable server_ip port_number
```
