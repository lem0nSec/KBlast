/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once


#include "../globals.hpp"


typedef struct _PROCESS_PRIVILEGES
{
    UCHAR Present[8];
    UCHAR Enabled[8];
    UCHAR EnabledByDefault[8];

} PROCESS_PRIVILEGES, * PPROCESS_PRIVILEGES;

typedef struct _EX_FAST_REF {
    PVOID Value;
} EX_FAST_REF, * PEX_FAST_REF;

typedef struct _KLBR_TOKEN_PRIV {
    ULONG processId;
    BOOL IsEnable;
} KLBR_TOKEN_PRIV, * PKLBR_TOKEN_PRIV;

typedef struct _KLBR_TOKEN {
    ULONG processId;
    ULONG targetProcessId;
    BOOL IsSteal;
} KLBR_TOKEN, * PKLBR_TOKEN;


/* These structs should be implemented to fix the 'restore' functionality
typedef struct _TOKEN_PTR {
    HANDLE processID;
    PVOID pTokenRestore;
} TOKEN_PTR, * PTOKEN_PTR;

typedef struct _TOKEN_PTR_STORAGE {
    ULONG count;
    TOKEN_PTR tokenPtr[5]
} TOKEN_PTR_STORAGE, *PTOKEN_PTR_STORAGE;
*/