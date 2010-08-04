/*
 *	IdtHooking
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
 */	

#include <ntddk.h>
#include <windef.h> /* MakeLong */

/* Typedef
 */
#pragma pack(1)
typedef struct _IDT_REG
{
	WORD	Limit;
	WORD	BaseLow;
	WORD	BaseHigh;
} IDT_REG, *PIDT_REG;

typedef struct _IDT_ENTRY
{
	WORD	OffsetLow;
	WORD	Selector;
	WORD	Access;
	WORD	OffsetHigh;
} IDT_ENTRY, *PIDT_ENTRY;
#pragma pack()

/* Globals
 */
static PDWORD	realISR = 0x0; /* Real handler address */

/* Our new handler
 */
__declspec(naked) Hook(void)
{
	DbgPrint(":o)");
	__asm
	{
		jmp	realISR; /* call the real handler */
	}
}

void	HookIDT(WORD intrNum) /* Patch IDT */
{
	IDT_REG			idtReg;
	PIDT_ENTRY	idtEntries;

	/* Look for the IDT
	*/
  __asm
	{
		sidt	idtReg;
	}
	idtEntries = (PIDT_ENTRY) MAKELONG(idtReg.BaseLow, idtReg.BaseHigh); /* IDT Address */
	/* Save the real handler
   */
	realISR = (PDWORD) MAKELONG(idtEntries[intrNum].OffsetLow, idtEntries[intrNum].OffsetHigh); /* Save real handler */
	/* Patch the IDT
   */
	__asm
	{
		cli;	/* Disable intrs */
	}
	idtEntries[intrNum].OffsetLow = LOWORD(Hook);
	idtEntries[intrNum].OffsetHigh = HIWORD(Hook);
	__asm
	{
		sti; /* Enable intrs */
	}
	DbgPrint("IDT entry 0x%x hooked, old handler = 0x%x", intrNum, realISR);
}

void UnHookIDT(WORD intrNum) /* Unpatch IDT */
{
	IDT_REG			idtReg;
	PIDT_ENTRY	idtEntries;

	__asm
	{
		sidt	idtReg;
	}
	idtEntries = (PIDT_ENTRY) MAKELONG(idtReg.BaseLow, idtReg.BaseHigh); // IDT Address
	__asm
	{
		cli;
	}
	idtEntries[intrNum].OffsetLow = LOWORD(realISR);
	idtEntries[intrNum].OffsetHigh = HIWORD(realISR);
	__asm
	{
		sti;
	}
	DbgPrint("IDT entry 0x%x restored", intrNum);
}

VOID 		DriverUnload(PDRIVER_OBJECT driverObject)
{
	DbgPrint("DriverUnload ...");
	UnHookIDT(0x0);
}

NTSTATUS	DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
	DbgPrint("DriverEntry ...");
	driverObject->DriverUnload = DriverUnload; 
	HookIDT(0x0);
	return STATUS_SUCCESS;
}
