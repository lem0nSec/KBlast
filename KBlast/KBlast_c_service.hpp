/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include "globals.hpp"

typedef enum _SERVICE_ACTION {

	SERVICE_CHECK,
	SERVICE_CREATE_AND_LOAD,
	SERVICE_UNLOAD_AND_DELETE,
	SERVICE_BINARY_RUN,
	SERVICE_BINARY_STOP

} SERVICE_ACTION;

// official service error codes
#define SERVICE_ERROR_GENERIC (ERROR_ACCESS_DENIED | ERROR_CIRCULAR_DEPENDENCY | ERROR_DUPLICATE_SERVICE_NAME | ERROR_INVALID_HANDLE | ERROR_INVALID_NAME | ERROR_INVALID_PARAMETER | ERROR_INVALID_SERVICE_ACCOUNT | ERROR_SERVICE_EXISTS | ERROR_SERVICE_MARKED_FOR_DELETE)

// KBlast service/driver status error codes - This should be changed to an enum
#define KBLAST_D_SUCCESS			1
#define KBLAST_D_FAILED				0
#define KBLAST_S_SUCCESS			2
#define KBLAST_S_FAILED				3
#define KBLAST_SD_SUCCESS			4
#define KBLAST_SD_FAILED			5
#define KBLAST_SD_EXIST				10
#define KBLAST_BINARY_NOT_FOUND		11
#define KBLAST_BINARY_ERROR_GENERIC	12

BOOL KBlast_c_ServiceManagement(IN SERVICE_ACTION sAction, IN OPTIONAL LPCWSTR lpBinaryPath, OUT OPTIONAL SERVICE_STATUS_PROCESS* sInfoBuffer);
DWORD KBlast_c_ServiceInitialize(IN OPTIONAL SERVICE_ACTION sAction);