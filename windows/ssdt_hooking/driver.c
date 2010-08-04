/* SsdtHooking
 *
 * reference:
 *  http://www.blackhat.com/presentations/bh-usa-06/BH-US-06-Silberman.pdf
 *  Rootkits, Hoglind
 */

#include <ntddk.h>

#define SYSCALL(_function) KeServiceDescriptorTable.ServiceTableBase[*(PULONG)((PUCHAR)_function+1)] 

/* Typedef
 */
#pragma pack(1)
typedef struct ServiceDescriptorEntry
  {
    unsigned int *ServiceTableBase;
    unsigned int *ServiceCounterTableBase; //Used only in checked build
    unsigned int NumberOfServices;
    unsigned char *ParamTableBase;
  } SSDT_Entry;
#pragma pack()

typedef NTSTATUS (*ZWTERMINATEPROCESS)(IN HANDLE ProcessHandle OPTIONAL, IN NTSTATUS ExitStatus); 

/* Forward declarations
 */
__declspec(dllimport)  SSDT_Entry KeServiceDescriptorTable;
NTSYSAPI NTSTATUS NTAPI ZwTerminateProcess(IN HANDLE ProcessHandle OPTIONAL, IN NTSTATUS ExitStatus); 

/* Globals
 */
static ZWTERMINATEPROCESS OldZwTerminateProcess;

/* Our new handler
 */
NTSTATUS Hook(IN HANDLE ProcessHandle OPTIONAL, IN NTSTATUS ExitStatus)   
{   
  DbgPrint(":o)");  
  return(OldZwTerminateProcess)(ProcessHandle, ExitStatus);   
}

VOID DriverUnload(PDRIVER_OBJECT driverObject)
{
  DbgPrint("DriverUnload ...");
  /* Unhook TerminateProcess system call
   */
  __asm
  {
    cli;	/* Disable intrs */
  }
  /* Use the CR0 trick to by pass SSDT protection
   * Set CR0 WP bit to 0
   */
  __asm
  {
    push eax
    mov eax, CR0
    and eax, 0FFFEFFFFh
    mov CR0, eax
    pop eax
  }
  (ZWTERMINATEPROCESS)(SYSCALL(ZwTerminateProcess)) = OldZwTerminateProcess;
  /* Set CR0 WP bit to 1
   */
  __asm
  {
    push eax
    mov eax, CR0
    or eax, NOT 0FFFEFFFFh
    mov CR0, eax
    pop eax
  }
  __asm
  {
    sti; /* Enable intrs */
  }
}

NTSTATUS	DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
  DbgPrint("DriverEntry ...");
  driverObject->DriverUnload = DriverUnload; 
  /* Hook TerminateProcess system call
   */
  OldZwTerminateProcess = (ZWTERMINATEPROCESS)(SYSCALL(ZwTerminateProcess));
  __asm
  {
    cli;	/* Disable intrs */
  }  
  /* Use the CR0 trick to by pass SSDT protection
   * Set CR0 WP bit to 0
   */
  __asm
  {
    push eax
    mov eax, CR0
    and eax, 0FFFEFFFFh
    mov CR0, eax
    pop eax
  }
  (ZWTERMINATEPROCESS)(SYSCALL(ZwTerminateProcess)) = Hook;
  /* Set CR0 WP bit to 1
   */
  __asm
  {
    push eax
    mov eax, CR0
    or eax, NOT 0FFFEFFFFh
    mov CR0, eax
    pop eax
  }
  __asm
  {
    sti; /* Enable intrs */
  }
  return STATUS_SUCCESS;
}
