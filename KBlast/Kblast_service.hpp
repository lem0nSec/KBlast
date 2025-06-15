/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include "globals.hpp"

BOOL Kblast_service_RunService(_In_ LPCWSTR lpServiceName, _In_ LPCWSTR lpBinaryPath, _Inout_ LPSC_HANDLE lphService);
BOOL Kblast_service_DeleteService(_In_ SC_HANDLE hService);