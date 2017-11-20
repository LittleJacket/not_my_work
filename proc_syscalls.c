#include <types.h>
#include <kern/errno.h>
#include <kern/unistd.h>
#include <kern/wait.h>
#include <lib.h>
#include <mips/trapframe.h>
#include <syscall.h>
#include <current.h>
#include <proc.h>
#include <thread.h>
#include <addrspace.h>
#include <copyinout.h>
#include <synch.h>
#include <array.h>
#include <limits.h>
#include <test.h>
#include <kern/fcntl.h>
#include <vfs.h>
  /* this implementation of sys__exit does not do anything with the exit code */
  /* this needs to be fixed to get exit() and waitpid() working properly */

void sys__exit(int exitcode, bool safe) {

  lock_acquire(procTableLock);
  struct procTable *pt1 = getPT(curproc->pid);

  if (pt1->ppid != PROC_NO_PID) {
    pt1->state = PROC_ZOMBIE;
    if(safe){
     pt1->exitCode = _MKWAIT_EXIT(exitcode);  
    }
    else {
      pt1->exitCode = _MKWAIT_SIG(exitcode);
    }
    cv_broadcast(waitCV, procTableLock);
  }
  else {
    pt1->state = PROC_EXITED;
    array_add(reusePIDs, &pt1->pid, NULL);
  }
  for (unsigned int i = 0; i < array_num(allProcs); i++)
  {
    struct procTable *cur = array_get(allProcs,i);
    if((cur->ppid == pt1->pid) && (cur->state == PROC_ZOMBIE)) {
      cur->state = PROC_EXITED;
      cur->ppid = PROC_NO_PID;
      array_add(reusePIDs, &cur->pid, NULL);
    }
  }

  lock_release(procTableLock);



  struct addrspace *as;
  struct proc *p = curproc;
  /* for now, just include this to keep the compiler from complaining about
     an unused variable */
  (void)exitcode;

  DEBUG(DB_SYSCALL,"Syscall: _exit(%d)\n",exitcode);

  KASSERT(curproc->p_addrspace != NULL);
  as_deactivate();
  /*
   * clear p_addrspace before calling as_destroy. Otherwise if
   * as_destroy sleeps (which is quite possible) when we
   * come back we'll be calling as_activate on a
   * half-destroyed address space. This tends to be
   * messily fatal.
   */
  as = curproc_setas(NULL);
  as_destroy(as);

  /* detach this thread from its process */
  /* note: curproc cannot be used after this call */
  proc_remthread(curthread);

  /* if this is the last user process in the system, proc_destroy()
     will wake up the kernel menu thread */
  proc_destroy(p);
  
  thread_exit();
  /* thread_exit() does not return, so we should never get here */
  panic("return from thread_exit in sys_exit\n");


}

/*
Fork system call. 
ctf-> current trap frame
retval -> child proc PID
child Prod returns value via enter_forked_process
*/

int sys_fork(struct trapframe *ctf, pid_t *retval) {
  struct proc *curProc = curproc;
  struct proc *newProc = proc_create_runprogram(curProc->p_name);

  struct procTable *pt1 = getPT(newProc->pid);
  pt1->ppid = curProc->pid;

  if(newProc == NULL) {
    DEBUG(DB_SYSCALL, "sys_fork_error: Wasn't able to make new process.\n");
    return ENPROC;
  }
  DEBUG(DB_SYSCALL, "sys_fork: New process created.\n");

  as_copy(curproc_getas(), &(newProc->p_addrspace));

  if(newProc->p_addrspace == NULL) {
    DEBUG(DB_SYSCALL, "sys_fork_error: Couldn't make addrspace for new process.\n");
    proc_destroy(newProc);
    return ENOMEM;
  }

  DEBUG(DB_SYSCALL, "New addrspace created.\n");

  struct trapframe *ntf = kmalloc(sizeof(struct trapframe));

  if (ntf == NULL)
  {
    DEBUG(DB_SYSCALL, "sys_fork_error: Couldn't create trapframe for new process.\n");
    proc_destroy(newProc);
    return ENOMEM;
  }

  //newProc->pid = curProc->pid++; 
  memcpy(ntf,ctf, sizeof(struct trapframe));
  DEBUG(DB_SYSCALL, "sys_fork: Created new trap frame\n");

  int err = thread_fork(curthread->t_name, newProc, &enter_forked_process, ntf, 1);
  if(err) {
    proc_destroy(newProc);
    kfree(ntf);
    ntf = NULL;
    return err;
  }
  DEBUG(DB_SYSCALL, "sys: fork created successfully\n");
  //kfree(ntf);
  //array_add(&curProc->procChildren, newProc, NULL);

  *retval = newProc->pid;
  return 0;
}
/* stub handler for getpid() system call                */
int
sys_getpid(pid_t *retval)
{
  *retval = curproc->pid;
  return(0);
}

/* stub handler for waitpid() system call                */

int
sys_waitpid(pid_t pid,
	    userptr_t status,
	    int options,
	    pid_t *retval)
{

  int exitstatus;
  int result = 0;
  lock_acquire(procTableLock);
  struct procTable *pt1 = getPT(pid);
  

  struct proc *parent = curproc;
  
  if(pt1 == NULL) {
    result = ESRCH;
  }
  else if(parent->pid != pt1->ppid) {
    result = ECHILD;
  }

  if(result){
    lock_release(procTableLock);
    return(result);
  }

  if (options != 0) {
    return(EINVAL);
  }


  while(pt1->state == PROC_RUNNING) {
    cv_wait(waitCV, procTableLock);
  }

  /* for now, just pretend the exitstatus is 0 */
  exitstatus = pt1->exitCode;
  lock_release(procTableLock);
  result = copyout((void *)&exitstatus,status,sizeof(int));
  if (result) {
    return(result);
  }
  *retval = pid;
  return(0);
}

int sys_execv(char * progname, char ** args){
  //runprogram.c 
  if(progname == NULL)
    return EFAULT;
  int argc = 0;
  //(void) args;
  struct addrspace *as;
  struct addrspace *newas;
  struct vnode *v;
  vaddr_t entrypoint, stackptr;
  int result;

  // save program on heap
  size_t programLen = strlen(progname) + 1;
  char *newProgram = kmalloc(sizeof(char *) * programLen);
  result = copyinstr((userptr_t)progname, newProgram, programLen, NULL);
  
  if(newProgram == NULL)
    return (ENOMEM);

  if(result)
    return result;

  while(args[argc] != NULL){
    if(strlen(args[argc]) > 1024)
      return (E2BIG);
    argc++;
  }

  if(argc > 64)
    return E2BIG;


  char **newArgs = kmalloc((argc + 1) * sizeof(char));
  for (int i = 0; i < argc; i++)
  {
    newArgs[i] = kmalloc((strlen(args[i]) + 1) * sizeof(char));
    result = copyinstr((userptr_t) args[i], newArgs[i], strlen(args[i]) + 1, NULL);
    if(result)
      return result;
  }

  newArgs[argc] = NULL;

  /* Open the file. */
  char *progn;
  progn = kstrdup(progname);
  result = vfs_open(progn, O_RDONLY, 0, &v);
  kfree(progn);
  if (result) {
    return result;
  }

  /* Create a new address space. */
  newas = as_create();
  //as = as_create();
  if (newas ==NULL) {
    vfs_close(v);
    return ENOMEM;
  }

  /* Switch to it and activate it. */
  curproc_setas(newas);
  as_activate();

  /* Load the executable. */
  result = load_elf(v, &entrypoint);
  if (result) {
    /* p_addrspace will go away when curproc is destroyed */
    vfs_close(v);
    curproc_setas(as);
    return result;
  }

  /* Done with the file now. */
  vfs_close(v);

  /* Define the user stack in the address space */
  result = as_define_stack(newas, &stackptr);
  if (result) {
    /* p_addrspace will go away when curproc is destroyed */
    curproc_setas(as);
    return result;
  }

  while((stackptr % 8) != 0)
    stackptr--;

  vaddr_t argptr[argc + 1];
  for (int i = argc - 1; i >= 0; i--)
  {
    stackptr -= strlen(newArgs[i]) + 1;
    result = copyoutstr(newArgs[i], (userptr_t)stackptr, strlen(newArgs[i]) + 1, NULL);
    if(result)
      return result;
    argptr[i] = stackptr;
  }

  while((stackptr % 4) != 0)
    stackptr--;

  argptr[argc]=0;

  for (int i = argc; i >= 0; i--)
  {
    stackptr -= ROUNDUP(sizeof(vaddr_t), 4);
    result = copyout(&argptr[i], (userptr_t)stackptr, sizeof(vaddr_t));
    if(result)
      return result;
  }

  as_destroy(as);

  //kfree(newArgs);
  //kfree(newProgram);
  /* Warp to user mode. */
  enter_new_process(argc /*argc*/, (userptr_t) stackptr /*userspace addr of argv*/,
        stackptr, entrypoint);
  
  /* enter_new_process does not return. */
  panic("enter_new_process returned\n");
  return EINVAL;

}
