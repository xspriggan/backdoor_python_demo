#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>

#define MASK "bash"
int main(int argc,int *argv[])
{
        prctl(PR_SET_NAME, MASK, 0,0);
        setuid(0);
        setgid(0);
        if (execl("././victim.py",0)<0)
        puts("execl error...\n");

}
