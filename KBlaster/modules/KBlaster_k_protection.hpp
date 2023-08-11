/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once


#include "../globals.hpp"


typedef enum _PROTECTION_OPTION {

    PROTECTION_WINTCB,
    PROTECTION_LSA,
    PROTECTION_ANTIMALWARE,
    PROTECTION_NONE

} PROTECTION_OPTION;

typedef struct _PS_PROTECTION
{
    UCHAR Type : 3;
    UCHAR Audit : 1;    // Reserved
    UCHAR Signer : 4;

} PS_PROTECTION, * PPS_PROTECTION;

typedef struct _PROCESS_PROTECTION_INFO
{
    UCHAR SignatureLevel;
    UCHAR SectionSignatureLevel;
    PS_PROTECTION Protection;

} PROCESS_PROTECTION_INFO, * PPROCESS_PROTECTION_INFO;