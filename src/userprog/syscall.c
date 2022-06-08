#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "filesys/file.h"
#include <string.h>

static void syscall_handler (struct intr_frame *);
void check_address(void *addr);
void get_argument(void *esp, int *arg, int count);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
tid_t exec (const char *cmd_line);
int wait (tid_t tid);
int open (const char *file);
int filesize(int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
bool sys_isdir(int fd);
bool sys_chdir(const char *dir);
bool sys_mkdir(const char *dir);
bool sys_readdir(int fd, char *name);
uint32_t sys_inumber(int fd);
void sigaction (int signum, void (*handler));
void sendsig (int pid, int signum);

void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int arg[3];
  check_address((void *)f->esp);
  int syscall_number = *(int *)f->esp;
  switch (syscall_number)
  {
    case SYS_HALT:
      halt();
      break;

    case SYS_EXIT:
      get_argument(f->esp,arg,1);
      exit(arg[0]);
      break;

    case SYS_CREATE:
      get_argument(f->esp,arg,2);
      check_address((void *)arg[0]);
      f->eax = create((const char *)arg[0],arg[1]);
      break;

    case SYS_REMOVE:
      get_argument(f->esp,arg,1);
      check_address((void *)arg[0]);
      f->eax = remove((const char *)arg[0]);
      break;

    case SYS_EXEC:
      get_argument(f->esp, arg, 1);
      check_address((void *)arg[0]);
      f->eax = exec ((const char *)arg[0]);
      break;

    case SYS_WAIT:
      get_argument(f->esp, arg, 1);
      f->eax = wait((tid_t)arg[0]);
      break;			

    case SYS_OPEN:
      get_argument(f->esp,arg,1);
      check_address((void *)arg[0]);
      f->eax = open((const char *)arg[0]);
      break;

    case SYS_FILESIZE:	
      get_argument(f->esp,arg,1);
      f->eax = filesize((int)arg[0]);
      break;
			
    case SYS_READ:
      get_argument(f->esp,arg,3);
      check_address((void *)arg[1]);
      f->eax = read((int)arg[0],(void *)arg[1],(unsigned)arg[2]);
      break;
			
    case SYS_WRITE:
      get_argument(f->esp,arg,3);
      check_address((void *)arg[1]);
      f->eax = write((int)arg[0],(void *)arg[1],(unsigned)arg[2]);
      break;

    case SYS_SEEK:
      get_argument(f->esp,arg,2);
      seek((int)arg[0],(unsigned)arg[1]);
      break;

    case SYS_TELL:
      get_argument(f->esp,arg,1);
      f->eax = tell((int)arg[0]);
      break;

    case SYS_CLOSE:
      get_argument(f->esp,arg,1);
      close((int)arg[0]);
      break;

    case SYS_SIGACTION:
      get_argument(f->esp, arg, 2);
      check_address((void *)arg[1]);
      sigaction((int)arg[0], (void *)arg[1]);
      break;

    case SYS_SENDSIG:
      get_argument(f->esp, arg, 2);
      sendsig((int)arg[0], (int)arg[1]);
      break;

    case SYS_ISDIR:
      get_argument(f->esp, arg, 1);
      f->eax = sys_isdir((int)arg[0]);
      break;
      
    case SYS_CHDIR:
      get_argument(f->esp, arg, 1);
      check_address((void *)arg[0]);
      f->eax = sys_chdir((const char*)arg[0]);
      break;
      
    case SYS_MKDIR:
      get_argument(f->esp, arg, 1);
      check_address((void *)arg[0]);
      f->eax = sys_mkdir((const char*)arg[0]);
      break;
    case SYS_READDIR:
      get_argument(f->esp, arg, 2);
      check_address((void *)arg[1]);
      f->eax = sys_readdir((int)arg[0],(char *)arg[1]);
      break;

    case SYS_INUMBER:
      get_argument(f->esp, arg, 1);
      f->eax = sys_inumber((int)arg[0]);
      break;

    case SYS_YIELD:
      thread_yield();
      break;

    default:
      thread_exit();
      break;
  }	
}

void check_address(void *addr)
{
  if((unsigned)addr >= 0xc0000000 || (unsigned)addr <= 0x8048000)
    exit(-1);
}

void get_argument(void *esp, int *arg, int count)
{
  int i;
  for(i=0;i<count;i++)
    {
      check_address((void *)esp+4+4*i);
      arg[i] = *(int *)(esp+4+4*i);	
    }
}

void halt(void)
{
  shutdown_power_off();
}

void exit(int status)
{
  struct thread *cur = thread_current();
  cur->exit_status = status;
  printf("%s: exit(%d)\n",cur->name,status);
  thread_exit();
}

bool create(const char *file, unsigned initial_size)
{
  return filesys_create(file,initial_size);
}

bool remove(const char *file)
{
  return filesys_remove(file);
}
tid_t exec (const char *cmd_line)
{
  int tid;
  struct thread *cp;
  tid = process_execute (cmd_line);
  cp = get_child_process (tid);
  sema_down (&cp->load_sema);

  if(cp == NULL)
    return -1;

  if (cp->is_load == false)
    return -1;
  else
    return tid;
}

int wait (tid_t tid)
{
  return process_wait (tid);
}

int open(const char *file)
{
  if(file == NULL || strlen(file)==0)
    return -1;
  struct file *f = filesys_open(file);
  if(f==NULL)
    return -1;
  if(strcmp(file,thread_current()->name)==0)
    file_deny_write(f);
  int fd=process_add_file(f);
  if(fd ==128)
    return -1;
  return fd;
}

int filesize(int fd)
{
  struct file *f = process_get_file(fd);
  if(f == NULL)
    return -1;
  return file_length(f);
}

int read(int fd, void *buffer,unsigned size)
{
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if(fd==0)
    {
      *(uint8_t *)buffer = input_getc();
      lock_release(&filesys_lock);
      return size;
    }
  else
    {
      if(f==NULL)
        {
          lock_release(&filesys_lock);
          return -1;
        }
      int sizes=file_read(f,buffer,size);
      lock_release(&filesys_lock);
      return sizes;
    }
}

int write(int fd,void *buffer,unsigned size)
{
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  struct inode *inode;
  if(fd == 1)
    {
      putbuf(buffer,size);
      lock_release(&filesys_lock);
      return size;
    }
  else
    {
      if(f==NULL)
        {
	  lock_release(&filesys_lock);
	  return -1;
	}
      inode = file_get_inode(f);
      if(inode_is_dir(inode))
        {
          lock_release(&filesys_lock);
          return -1;
        }   
      int sizes = file_write(f,buffer,size);
      lock_release(&filesys_lock);
      return sizes;
    }
}

void seek(int fd, unsigned position)
{
  struct file *f = process_get_file(fd);
  if(f==NULL)
    return;
  file_seek(f,position);
}

unsigned tell(int fd)
{
  struct file *f = process_get_file(fd);
  return file_tell(f);
}

void close(int fd)
{
  process_close_file(fd);
}

bool
sys_isdir(int fd)
{
  /* Given FD, get file using process_get_file() and check
     it is directory or not using inode_is_dir(). */
  struct file *file;
  file = process_get_file (fd);
  if (file == NULL)
    return false;
  return inode_is_dir (file_get_inode (file));
}

bool
sys_chdir(const char *dir)
{
  /* Change current directory to DIR. */
  struct file *file= filesys_open(dir);
  if(file != NULL)
    {
      dir_close(thread_current()->dir);
      thread_current()->dir = dir_open(file_get_inode(file));
      return true;
    }
  return false;
}

bool
sys_mkdir(const char *dir)
{
  /* Make directory to DIR usign filesys_create_dir(). */
  if(dir == NULL || strlen(dir) == 0)
    return false;
  return filesys_create_dir(dir);
}

bool
sys_readdir(int fd, char *name)
{
  struct file* file;
  struct dir *dir;
  bool result;
  file = process_get_file (fd);
  /* If FILE is not directory fail. */
  if (!inode_is_dir(file_get_inode (file)))
    return false;

  dir = (struct dir *)file;
  /* Read directory entry and save to NAME
     without "." and "..". */
  result = dir_readdir (dir, name);
  while (strcmp (name, ".") == 0 || strcmp (name, "..") == 0)
    {
      if (result == false) break;
      result = dir_readdir (dir, name);
    }
  return result;
}

uint32_t
sys_inumber(int fd)
{
  /* Given FD get file and return block number of file's. */
  struct file* file;
  file = process_get_file (fd);
  if (file == NULL)
    return -1;
  return inode_get_inumber (file_get_inode (file));
}

void sigaction (int signum, void (*handler))
{
  struct thread *cur = thread_current();

  cur->handler[signum - 1] = handler;
}

void sendsig (int pid, int signum)
{
  struct thread *t;
  t = find_tid (pid);

  if (t == NULL)
    return;

  if (t->handler[signum - 1] != NULL)
    printf("Signum: %d, Action: %p\n", signum, t->handler[signum - 1]);
}
