/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once


#include "../globals.hpp"


typedef enum _PRIVILEGES_ACTION {

    PRIVILEGES_ENABLEALL,
    PRIVILEGES_DISABLEALL,
    // PRIVILEGES_RESTOREALL todo

} PRIVILEGES_ACTION;


typedef struct _PROCESS_PRIVILEGES
{
    UCHAR Present[8];
    UCHAR Enabled[8];
    UCHAR EnabledByDefault[8];

} PROCESS_PRIVILEGES, * PPROCESS_PRIVILEGES;

typedef struct _EX_FAST_REF {

    PVOID Value;

} EX_FAST_REF, * PEX_FAST_REF;