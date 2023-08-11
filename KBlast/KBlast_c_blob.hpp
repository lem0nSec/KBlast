/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include "globals.hpp"
#include "driver/KBlast_c_device_dispatch.hpp"


typedef enum _KBLAST_USERLAND_BLOB_DO {

	BLOB_SAVE,
	BLOB_DELETE,
	//BLOB_EXECUTE,
	BLOB_INFO,
	BLOB_WRITE,
	BLOB_READ

} KBLAST_USERLAND_BLOB_DO;


typedef struct _KBLAST_USERLAND_BLOBS_CONTAINER {

	BYTE* blob;
	DWORD szBlob;
	BOOL isFull;

} KBLAST_USERLAND_BLOBS_CONTAINER, * PKBLAST_USERLAND_BLOBS_CONTAINER;


typedef struct _KBLAST_USERLAND_BLOBS {

	KBLAST_USERLAND_BLOBS_CONTAINER container1;
	KBLAST_USERLAND_BLOBS_CONTAINER container2;
	KBLAST_USERLAND_BLOBS_CONTAINER container3;

} KBLAST_USERLAND_BLOBS, * PKBLAST_USERLAND_BLOBS;


BOOL KBlast_c_blob_manage(IN OPTIONAL LPCSTR strBlob, IN OPTIONAL char* containerNumber, OUT OPTIONAL PKBLAST_MEMORY_BUFFER pBuf, IN KBLAST_USERLAND_BLOB_DO action);