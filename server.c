#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <wait.h>
#include <fcntl.h>
#include <sys/prctl.h>

#define MAX_BUFFER_SIZE 1024
#define HASH_PASSWORD "1234"

#define UNAUTHORIZED_CODE "_@302"
#define UNAUTHORIZED_CODE_LEN 5
#define AUTHORIZATION_MESSAGE "Access granted"
#define AUTHORIZATION_MESSAGE_LEN 14

// Global var for server directory
// Used by history_write & history_read to 
// create/read/write history file
char server_dir[MAX_BUFFER_SIZE];

void error(const char *msg) {
    perror(msg);
    exit(1);
}

// Handler for SIGINT
void sigint_signal_handler (int signum) {
    printf("Caught signal %d\nAborting...\n", signum);
    exit(signum);
}

// Signal handler used to notify main process that a child(client) exited
void chil_signal_handler () {
    int pid;
    char s_pid[12];
    char file_path[1024];

    pid = waitpid(-1, NULL, 0);
    sprintf(s_pid, "%d",pid);

    // Create path to history file
    sprintf(file_path, "%s/%s",server_dir, s_pid);

    // Try to remove history file
    if (remove(file_path) == 0) {
        printf("Deleted history file: %s\n", s_pid);
    }
}

// Function to parse spaces and '\n'
#define TOK_BUFSIZE 64
#define TOK_DELIM " \n"
char **space_parse(char *buffer_in)
{
    int bufsize = TOK_BUFSIZE, position = 0;
    char **tokens = malloc(bufsize * sizeof(char*));
    char *token;

    if (!tokens) {
        printf("Error in allocating");
        exit(EXIT_FAILURE);
    }

    token = strtok(buffer_in, TOK_DELIM);
    while (token != NULL) {
        tokens[position] = token;
        position++;

        // Alocate more memory if necessary
        if (position >= bufsize) {
            bufsize += TOK_BUFSIZE;
            tokens = realloc(tokens, bufsize * sizeof(char*));
            if (!tokens) {
                printf("Error in malloc");
                exit(EXIT_FAILURE);
            }
        }

        token = strtok(NULL, TOK_DELIM);
    }
    // Add null at the end of the array
    tokens[position] = NULL;
    return tokens;
}

// Function for finding special characters in command
int special_char_parse(char* input_buffer, char** stripped_buffer, char *special_char) {
    int i;

    for (i = 0; i < 2; i++) {
        /*If there is a special character stripped buffer will contain on [0] left part of command
         * an on [1] right part of command separated by special char*/
        stripped_buffer[i] = strsep(&input_buffer, special_char);
        if (stripped_buffer[i] == NULL)
            break;
    }

    if (stripped_buffer[1] == NULL)
        return 0; // returns zero if no special char is found.
    else {
        return 1;
    }
}

// Function used to save commands from client to a file
// If file doesnt exists it will be created.
// The name of file will be the PID of the process that serves the client
void write_history(char *buffer) {
    FILE *fptr;
    int pid;
    char s_pid[12];
    char file_path[1024];

    if (strcmp(buffer,"\n") != 0) {
        pid = getpid();
        sprintf(s_pid, "%d",pid);

        // Create path to save file to
        sprintf(file_path, "%s/%s",server_dir, s_pid);

        fptr = fopen(file_path, "a");
        if (fptr == NULL) {
            error("Error in opening/creating file");
        }
        fprintf(fptr, "%s", buffer);
        fclose(fptr);
    }
}

// Function used to read history file and write it to give fd
void read_history(int pid, const int *fd) {
    FILE *fptr;
    char output_buffer[MAX_BUFFER_SIZE];
    char s_pid[12];
    char file_path[1024];

    sprintf(s_pid, "%d",pid);

    // Create path to file
    sprintf(file_path, "%s/%s",server_dir, s_pid);

    bzero(output_buffer, MAX_BUFFER_SIZE);

    fptr = fopen(file_path, "r");
    if (fptr == NULL) {
        error("Error in opening/creating file");
    }
    fseek(fptr, 0, SEEK_END);
    long fsize = ftell(fptr);
    fseek(fptr, 0, SEEK_SET);

    // Read whole file and store it to buffer
    fread(output_buffer, 1, fsize, fptr);
    fclose(fptr);

    write(*fd, output_buffer, MAX_BUFFER_SIZE - 1);
}

// Function to execute builtin commands
int exec_built_in_commands(char** parsed, const int *sockfd, int *status)
{
    int no_of_cmds = 3, i, switch_buittin_cmds = 0, pid;
    char* list_of_builtin_cmds[no_of_cmds];
    char output_buffer[MAX_BUFFER_SIZE];

    list_of_builtin_cmds[0] = "cd";
    list_of_builtin_cmds[1] = "help";
    list_of_builtin_cmds[2] = "history";

    for (i = 0; i < no_of_cmds; i++) {
        if (strcmp(parsed[0], list_of_builtin_cmds[i]) == 0) {
            switch_buittin_cmds = i + 1;
            break;
        }
    }

    bzero(output_buffer, MAX_BUFFER_SIZE);
    switch (switch_buittin_cmds) {
        case 1:
            // Change dir and show current dir to client
            if (chdir(parsed[1]) != 0) { // Check for error in cd
                strcpy(output_buffer, "cd: no such file or directory");
                write(*sockfd, output_buffer, MAX_BUFFER_SIZE - 1);
                *status = EXIT_FAILURE;
                return 0;
            }
            getcwd(output_buffer, MAX_BUFFER_SIZE);
            write(*sockfd, output_buffer, MAX_BUFFER_SIZE - 1);
            *status = EXIT_FAILURE;
            return 0;
        case 2:
            strcpy(output_buffer, "No help provided! Good luck with that...:)");
            write(*sockfd, output_buffer, 42);
            *status = EXIT_SUCCESS;
            return 0;
        case 3:
            pid = getpid();
            read_history(pid, sockfd);
            *status = EXIT_SUCCESS;
            return 0;
        default:
            break;
    }

    return 1;
}

// Function used to execute simple commands with or without parameters
char* exec_simple_command(char** tokens, int *status) {
    char buffer_out[MAX_BUFFER_SIZE];
    int pid;
    int p[2];

    if (pipe(p) < 0) {
        error("Error in pipe");
    }
    // Execute command and redirect stdout & stderr to pipe
    if ((pid = fork()) == -1) {
        error("Error in fork");
    } else if (pid == 0) { // Child
        close(p[0]);
        dup2(p[1], STDOUT_FILENO);
        dup2(p[1], STDERR_FILENO);

        if (execvp(tokens[0], tokens) == -1) {
            printf("Command not found: %s\n", tokens[0]);
        }
        exit(1);

    } else { // Father
        close(p[1]);
        bzero(buffer_out, MAX_BUFFER_SIZE);
        waitpid(pid, status, WUNTRACED);
        read(p[0], buffer_out, MAX_BUFFER_SIZE - 1);
        close(p[0]);
        return strdup(buffer_out);
    }
}

// Function used to execute commands with pipes
char* exec_piped_command(char **stripped_buffer, int *status) {
    int chil_pipe_fd[2];
    int father_pipe_fd[2];
    int pid1, pid2;
    char output_buffer[MAX_BUFFER_SIZE];
    char **tokens;
    char **pipe_tokens;

    bzero(output_buffer, MAX_BUFFER_SIZE);

    tokens = space_parse(stripped_buffer[0]);
    pipe_tokens = space_parse(stripped_buffer[1]);

    // Pipe for two child process
    if (pipe(chil_pipe_fd) < 0) {
        error("Error in pipe");
    }

    // Pipe for second child and father process
    if (pipe(father_pipe_fd) < 0) {
        error("Error in pipe");
    }

    if ((pid1 = fork()) < 0) {
        error("Error in fork");
    }

    if (pid1 == 0) {
        // Child 1
        // This child needs only write end of chil_pipe_fd
        close(chil_pipe_fd[0]);
        // This child doesn't need father_pipe_fd at all
        close(father_pipe_fd[0]);
        

        // Redirect STDOUT to chil_pipe_fd
        dup2(chil_pipe_fd[1], STDOUT_FILENO);
        // Redirect STDERR to father_pipe_fd
        dup2(father_pipe_fd[1], STDERR_FILENO);
        close(chil_pipe_fd[1]);
        close(father_pipe_fd[1]);
        if (execvp(tokens[0], tokens) == -1) {
            fprintf(stderr, "Command not found: %s\n", tokens[0]);
            exit(1);
        }
    } else if (pid1 > 0) {
        // Father
        // Create another child process
        if ((pid2 = fork()) < 0) {
            error("Error in fork");
        }

        if (pid2 == 0) {
            // Child 2
            // This child needs only read end of chil_pipe_fd
            close(chil_pipe_fd[1]);
            // This child needs only write end of father_pipe_fd
            close(father_pipe_fd[0]);

            // Redirect input to chil_pipe_fd
            dup2(chil_pipe_fd[0], STDIN_FILENO);
            close(chil_pipe_fd[0]);

            //Redirect output to father_pipe_fd
            dup2(father_pipe_fd[1], STDOUT_FILENO);
            dup2(father_pipe_fd[1], STDERR_FILENO);
            close(father_pipe_fd[1]);

            if (execvp(pipe_tokens[0], pipe_tokens) == -1) {
                printf("Command not found: %s\n", pipe_tokens[0]);
                exit(1);
            }
        } else if (pid2 > 0) {
            // Father doesn't need chil_pipe_fd at all
            close(chil_pipe_fd[0]);
            close(chil_pipe_fd[1]);

            //Father doesn't need write end father_pipe_fd
            close(father_pipe_fd[1]);

            waitpid(pid1, status, 0);
            waitpid(pid2, NULL, 0);

            // Read from pipe
            read(father_pipe_fd[0], output_buffer, MAX_BUFFER_SIZE - 1);
            close(father_pipe_fd[0]);
            return strdup(output_buffer);
        }
    }
}

// Function to process input. Checks if input has redirection symbol, pipe symbol,
// if its a simple command or if it is empty 
int process_input(char* input_buffer, char** parsed_input) {
    int piped = 0;
    int redirected = 0;
    int flag;
    char *pipe = "|";
    char *redirect = ">";

    // Check for redirection in input
    redirected = special_char_parse(input_buffer, parsed_input, redirect);
    if (redirected) {
        flag = 0; // 0 indicates we have an input with redirection
    } else {
        // Check for pipe in input
        piped = special_char_parse(input_buffer, parsed_input, pipe);
        if (piped) {
            flag = 1; // 1 indicates we have an input with pipe
        } else if (strcmp(input_buffer, "\n") != 0){
            flag = 2; // 2 indicates we have input with simple command + params or builtin command
        } else {
            flag = -1; // Empty command
        }
    }
    return flag;
}

// Function to execute redirection commands
void exec_redirection_command (char **redir_buffer, const int *sockfd) {
    // Redir_buffer on [0] contains command and on [1] contains output file
    int fd;
    int *fdpt = &fd;
    int exec_flag;
    int *status, exit_status;
    char *stripped_buffer[2];
    char **tokens, **output_file;
    char client_message[100];
    char *out_buffer;

    //Remove spaces and /n from file name
    output_file = space_parse(redir_buffer[1]);
    fd = open(output_file[0], O_CREAT | O_RDWR, 0666);
    if(fd < 0) {
        error("Error creating/opening file");
        exit(1);
    }

    // Check if command is piped or simple/built-in command.
    exec_flag = process_input(redir_buffer[0], stripped_buffer);
    if (exec_flag == 1) {
        out_buffer = exec_piped_command(stripped_buffer, status);
    } else if (exec_flag == 2) {
        tokens = space_parse(redir_buffer[0]);
        if ((exec_built_in_commands(tokens, fdpt, status)) == 1) { // Try to execute command as builtin. If built_in returns 1
            out_buffer = exec_simple_command(tokens, status);      // then command is not built-in
        }
    }
    exit_status = WEXITSTATUS(*status);

    // Check for errors
    if (exit_status != 0) {
        close(fd);
        sprintf(client_message,"Command not found");
        write(*sockfd, client_message, 99);
    } else {
        write(fd, out_buffer, MAX_BUFFER_SIZE - 1);
        close(fd);
        sprintf(client_message,"File %s created", output_file[0]);
        write(*sockfd, client_message, MAX_BUFFER_SIZE - 1);
    }
}


void shell_fun(const int *sockfd, char *buffer_in) {
    char *stripped_buffer[2];
    char *buffer_out;
    char **tokens;
    int exec_flag, *status;

    exec_flag = process_input(buffer_in, stripped_buffer);
    if (exec_flag == 0) {
        exec_redirection_command(stripped_buffer, sockfd);
        // write(*sockfd, buffer_out, MAX_BUFFER_SIZE - 1);
    } else if (exec_flag == 1) {
        buffer_out = exec_piped_command(stripped_buffer, status);
        write(*sockfd, buffer_out, MAX_BUFFER_SIZE - 1);
    } else if (exec_flag == 2) {
        tokens = space_parse(buffer_in);
        if ((exec_built_in_commands(tokens, sockfd, status)) == 1) { // Try to execute command as builtin. If built_in returns 1
            buffer_out = exec_simple_command(tokens, status);            // then command is not built-in
            write(*sockfd, buffer_out, MAX_BUFFER_SIZE - 1);
        }
    } else {
        write(*sockfd, "\n", 2);
    }
    
}

int authorize_client(char *buffer) {
    char **pwd;

    pwd = space_parse(buffer);
    if (strcmp(pwd[0], HASH_PASSWORD) == 0) {
        printf("Client authorized\n");
        return 1;
    } else {
        printf("Unauthorized user detected. Shutting down connection\n");
        return 0;
    }
}

int main(int arg, char *argv[]) {

    // Save server dir as destination for history file
    getcwd(server_dir, MAX_BUFFER_SIZE);

    // Register signal and signal handler
    signal(SIGINT, sigint_signal_handler);

    // Register signal and signal handler for child
    signal(SIGCHLD, chil_signal_handler);

    int sockfd, newsockfd, portno, authorization_token;
    socklen_t clilen;
    char buffer[MAX_BUFFER_SIZE];
    struct sockaddr_in serv_addr, cli_addr;
    int n, pid;
    char str[INET_ADDRSTRLEN];

    if (arg < 2) {
        fprintf(stderr, "No port provide\n");
        exit(1);
    }    

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        error("ERROR opening socket");
    }

    // Server socket info
    bzero((char*)&serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if (bind(sockfd,(struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0 ) {
        error("ERROR on binding");
    }

    printf("Listening for connections...\n");
    listen(sockfd, 5);

    for (;;) {
        clilen = sizeof(cli_addr);
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

        if (newsockfd < 0) {
            error("ERROR on accept");
            exit(1);
        }
        fprintf(stdout, "Accepted connection\n");

        // Create child process for new client
        if ((pid = fork()) == -1) {
            close(newsockfd);
            error("ERROR in fork");
            exit(1);
        } else if (pid > 1){ //Father
            close(newsockfd);
        } else if (pid == 0) { // Child

            // If parent process terminates child is notified with SIGHUP signal
            // and terminates
            prctl(PR_SET_PDEATHSIG, SIGHUP);

            if (inet_ntop(AF_INET, &cli_addr.sin_addr, str, INET_ADDRSTRLEN) == NULL) {
                fprintf(stderr, "Could not convert byte to address\n");
            }

            fprintf(stdout, "Client address: %s\n", str);

            //Authorize client
            n = read(newsockfd, buffer, MAX_BUFFER_SIZE - 1);
            if (n < 0) {
                error("ERROR reading from socket");
            } 

            // Check client pin for granting access
            authorization_token = authorize_client(buffer);
            if (!authorization_token) {
                write(newsockfd, UNAUTHORIZED_CODE, UNAUTHORIZED_CODE_LEN);
                close(newsockfd);
                exit(0);
            } else {
                write(newsockfd,AUTHORIZATION_MESSAGE, AUTHORIZATION_MESSAGE_LEN);
            }

            for (;;) {

                bzero(buffer, MAX_BUFFER_SIZE);
                n = read(newsockfd, buffer, MAX_BUFFER_SIZE - 1);
                if (n < 0) {
                    error("ERROR reading from socket1");
                } else if (n == 0) { // Check if client closed connection
                    printf("Client disconnected\n");
                    close(newsockfd); // Close socket
                    exit(0);
                }
                printf("Executing command: %s\n", buffer);
                // Write command to history file
                write_history(buffer);
                // Exec command
                shell_fun(&newsockfd, buffer);
            }
        }
    }
} 
