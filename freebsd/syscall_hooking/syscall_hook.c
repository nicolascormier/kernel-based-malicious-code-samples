/* Syscall hooking
 *
 * reference:
 *  http://www.freebsd.org/doc/en/books/arch-handbook/driverbasics-kld.html
 *  
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>

static sy_call_t* old_syscall = NULL;

static int exit_hook(struct thread* td, void* syscall_args)
{
	(void) uprintf(":o)");
  
	return old_syscall(td, syscall_args);
}

static int module_handler(struct module* module, int cmd, void* arg)
{
	int error = 0;
	switch (cmd)
  {
    case MOD_LOAD:
      old_syscall = sysent[SYS_exit].sy_call;
      sysent[SYS_exit].sy_call = (sy_call_t*) exit_hook;
      break;
      
    case MOD_UNLOAD:
      sysent[SYS_exit].sy_call = old_syscall;
      break;
      
    default:
      error = EOPNOTSUPP;
      break;
	}
  
	return error;
}

static moduledata_t syscall_hook_mod = { "syscall_hook", module_handler, NULL };

DECLARE_MODULE(syscall_hook, syscall_hook_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
