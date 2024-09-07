/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlast_c_blob.hpp"



KBLAST_USERLAND_BLOBS blobs = { 0 };

void KBlast_c_blob_info(PKBLAST_USERLAND_BLOBS_CONTAINER container)
{
	BOOL status = FALSE;
	DWORD i = 0;

	PRINT_INFO(L"Current blob size is %d\n", container->szBlob);
	wprintf(L"[ binary blob ] : ");
	for (i = 0; i <= container->szBlob; i++)
	{
		if (i == container->szBlob)
		{
			wprintf(L"\n");
			break;
		}
		wprintf(L"%02x ", *(PBYTE)((DWORD_PTR)container->blob + i));
	}
}


BOOL KBlast_c_blob_manage(IN OPTIONAL LPCSTR strBlob, IN OPTIONAL int containerNumber, OUT OPTIONAL PKBLAST_MEMORY_BUFFER pBuf, IN KBLAST_USERLAND_BLOB_DO action)
{
	BOOL status = FALSE;
	DWORD dwReturningFlags = 0;
	DWORD szBlob = 0;
	DWORD pcbBinary = 0;
	PKBLAST_USERLAND_BLOBS_CONTAINER tBlob = 0;
	int n = 0;

	BYTE* test = 0;

	switch (action)
	{
	case BLOB_SAVE:
		if (blobs.container1.isFull == FALSE)
		{
			tBlob = &blobs.container1;
			n = 1;
		}
		else if (blobs.container2.isFull == FALSE)
		{
			tBlob = &blobs.container2;
			n = 2;
		}
		else if (blobs.container3.isFull == FALSE)
		{
			tBlob = &blobs.container3;
			n = 3;
		}
		else
		{
			PRINT_WARNING(L"Blob containers are all full.\n");
			break;
		}
		
		szBlob = (DWORD)strlen(strBlob);
		pcbBinary = szBlob;
		tBlob->blob = (BYTE*)LocalAlloc(LPTR, (SIZE_T)szBlob);
		if (tBlob != 0)
		{
			status = CryptStringToBinaryA(strBlob, szBlob, CRYPT_STRING_HEX, tBlob->blob, &pcbBinary, NULL, NULL);
			tBlob->isFull = status;
			if (status == TRUE)
			{
				tBlob->szBlob = szBlob / 2; // szBlob should be divided by 2 because it is initially equal to the size of the string, where each character is actually a byte.
				PRINT_SUCCESS(L"Blob saved in local container %d.\n", n);
				n = 0;
			}
			else
			{
				PRINT_WARNING(L"Invalid input.\n");
			}
			break;
		}

	case BLOB_DELETE:
		n = containerNumber;
		if (n != 0)
		{
			switch (n)
			{
			case 1:
				tBlob = &blobs.container1;
				break;

			case 2:
				tBlob = &blobs.container2;
				break;

			case 3:
				tBlob = &blobs.container3;
				break;

			default:
				PRINT_WARNING(L"Container %d does not exist.\n", n);
				break;
			}

			if (tBlob != 0)
			{
				if (tBlob->isFull == TRUE)
				{
					LocalFree(tBlob->blob);
					tBlob->szBlob = 0;
					tBlob->isFull = FALSE;
					status = TRUE;
					if (status == TRUE)
					{
						PRINT_SUCCESS(L"Container %d cleared.\n", n);
					}
					break;
				}
				else
				{
					PRINT_WARNING(L"Container %d is empty.\n", n);
					break;
				}
			}
		}

	case BLOB_INFO:
		n = containerNumber;
		if (n != 0)
		{
			switch (n)
			{
			case 1:
				tBlob = &blobs.container1;
				break;

			case 2:
				tBlob = &blobs.container2;
				break;

			case 3:
				tBlob = &blobs.container3;
				break;

			default:
				PRINT_WARNING(L"Container %d does not exist.\n", n);
				break;
			}

			if (tBlob != 0)
			{
				status = TRUE;
				if (tBlob->isFull == FALSE)
				{
					PRINT_WARNING(L"Container %d is empty.\n", n);
				}
				else
				{
					KBlast_c_blob_info(tBlob);
				}
			}
		}
		break;

	case BLOB_WRITE:
		n = containerNumber;
		if (n != 0)
		{
			switch (n)
			{
			case 1:
				tBlob = &blobs.container1;
				break;

			case 2:
				tBlob = &blobs.container2;
				break;

			case 3:
				tBlob = &blobs.container3;
				break;

			default:
				PRINT_WARNING(L"Container %d does not exist.\n", n);
				break;
			}

			if (tBlob != 0)
			{
				if (tBlob->isFull == TRUE)
				{	
					if (tBlob->szBlob <= sizeof((pBuf)->buffer))
					{
						RtlCopyMemory((pBuf)->buffer, tBlob->blob, sizeof((pBuf)->buffer));
						pBuf->size = tBlob->szBlob;
						pBuf->ptr = (PVOID)strBlob;
						if ((PVOID)pBuf->ptr != 0)
						{
							status = TRUE;
						}
					}
					else
					{
						PRINT_WARNING(L"Blob buffer is too large.\n");
						LocalFree(pBuf);
					}
				}
				else
				{
					PRINT_WARNING(L"Blob buffer empty.\n");
				}
			}
		}
		break;

	
	case BLOB_READ:
		if (blobs.container1.isFull == FALSE)
		{
			tBlob = &blobs.container1;
			n = 1;
		}
		else if (blobs.container2.isFull == FALSE)
		{
			tBlob = &blobs.container2;
			n = 2;
		}
		else if (blobs.container3.isFull == FALSE)
		{
			tBlob = &blobs.container3;
			n = 3;
		}
		else
		{
			PRINT_WARNING(L"Blob containers are all full.\n");
			break;
		}

		if (tBlob != 0)
		{
			tBlob->blob = (BYTE*)LocalAlloc(LPTR, pBuf->size);
			if (tBlob->blob != 0)
			{
				tBlob->szBlob = (DWORD)pBuf->size;
				RtlCopyMemory(tBlob->blob, pBuf->buffer, tBlob->szBlob);
				tBlob->isFull = TRUE;
				PRINT_SUCCESS(L"Blob saved in container %d\n", n);
			}
		}
		break;
			
	default:
		break;
	}

	return status;

}