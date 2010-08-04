/* IDT hooking
 *
 *		0      Divide by zero
 *		1      Single step
 *		2      Non-maskable  (NMI)
 *		3      Breakpoint
 *		4      Overflow trap
 *		5      BOUND range exceeded (186,286,386)
 *		6      Invalid opcode (186,286,386)
 *		7      Coprocessor not available (286,386)
 *		8      Double fault exception (286,386)
 *		9      Coprocessor segment overrun (286,386)
 *		A      Invalid task state segment (286,386)
 *		B      Segment not present (286,386)
 *		C      Stack exception (286,386)
 *		D      General protection exception (286,386)
 *		E      Page fault (286,386)
 *		F      Reserved
 *		10     Coprocessor error (286,386)
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

struct idt_reg
{
  unsigned limit:16;
  unsigned base_low:16;
  unsigned base_high:16;
} __attribute__((packed));

struct idt_entry
{
  unsigned offset_low:16;
  unsigned selector:16;
  unsigned access:16;
  unsigned offset_high:16;
} __attribute__((packed));

static void* old_handler = NULL;

static void my_handler_func(void)
{
  //uprintf(":o)"); // FreeBSD does not like uprintf calls inside intr handlers... 
                    // Well I can understand why :o)
  __asm__ volatile ("jmp *%0": "=m" (old_handler));
}

static int module_handler(struct module* module, int cmd, void* arg)
{
  const int target = 0;
  struct idt_reg reg;
  struct idt_entry* idt = NULL;
	int error = 0;
	switch (cmd)
  {
    case MOD_LOAD:
      __asm__ volatile ("sidt %0": "=m" (reg));
      idt = (struct idt_entry*) ((reg.base_high << 16 ) + reg.base_low);
      old_handler = (void*) ((idt[target].offset_high << 16) + idt[target].offset_low);
      char* new_handler = (char*) my_handler_func;
      new_handler += 3; // Jump the prologue
      __asm__ volatile ("cli");
      idt[target].offset_high = (unsigned short) (((unsigned long) new_handler) >> 16);
      idt[target].offset_low  = (unsigned short) (((unsigned long) new_handler) & 0x0000FFFF);
      __asm__ volatile ("sti");
      break;
      
    case MOD_UNLOAD:
      __asm__ volatile ("sidt %0": "=m" (reg));
      idt = (struct idt_entry*) ((reg.base_high << 16 ) + reg.base_low);
      __asm__ volatile ("cli");
      idt[target].offset_high = (unsigned short) (((unsigned long) old_handler) >> 16);
      idt[target].offset_low  = (unsigned short) (((unsigned long) old_handler) & 0x0000FFFF);
      __asm__ volatile ("sti");
      break;
            
    default:
      error = EOPNOTSUPP;
      break;
	}
  
	return error;
}

static moduledata_t idt_hook_mod = { "idt_hook", module_handler, NULL };

DECLARE_MODULE(idt_hook, idt_hook_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
