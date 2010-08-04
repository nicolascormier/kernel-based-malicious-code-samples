#pragma once

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <aclapi.h>
#include <stdio.h>

typedef DWORD* NTSTATUS;

typedef struct _UNICODE_STRING 
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

#define INIT_UNICODE_STRING(_var,_buffer) \
        UNICODE_STRING _var = {           \
        sizeof (_buffer) - sizeof (WORD), \
        sizeof (_buffer),                 \
        _buffer }

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;


