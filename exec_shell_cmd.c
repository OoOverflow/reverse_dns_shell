#include"header.h"

int exec_shell_cmd(char *cmd_string,char *buf,int buf_len)
{
        int res;
        int pipefd[2];
        pid_t cpid;
        FILE *fp;

        res = pipe(pipefd);
        if (res == -1) {
                exit(EXIT_FAILURE);
        }

        cpid = fork();
        if (cpid == -1) {
                close(pipefd[0]);
                close(pipefd[1]);
                exit(EXIT_FAILURE);
        }else if (cpid == 0) {
                close(pipefd[0]);
                if (pipefd[1] != STDERR_FILENO) {
                        dup2(pipefd[1],STDERR_FILENO);
                }
                if (pipefd[1] != STDOUT_FILENO) {
                        dup2(pipefd[1],STDOUT_FILENO);
                        close(pipefd[1]);
                }
                res = execlp("/bin/bash","bash","-c",cmd_string,(char *)0);
                if (res < 0) {
                        _exit(EXIT_FAILURE);
                }
                _exit(EXIT_SUCCESS);

        }else{
                close(pipefd[1]);
                res = 0;
                fp = fdopen(pipefd[0],"r");
                res += fread(buf,1,buf_len,fp);
                close(pipefd[0]);
                return res;
        }
}

