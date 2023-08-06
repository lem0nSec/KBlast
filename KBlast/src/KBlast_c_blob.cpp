#include "KBlast_c_blob.hpp"



KBLAST_USERLAND_BLOBS blobs = { 0 };

void KBlast_c_blob_info(PKBLAST_USERLAND_BLOBS_CONTAINER container)
{
	BOOL status = FALSE;
	DWORD i = 0;

	wprintf(L"[ binary blob ] : ");
	for (i = 0; i <= container->szBlob; i++)
	{
		if (i == container->szBlob)
		{
			wprintf(L"\n");
			break;
		}
		wprintf(L"%02x ", *(BYTE*)(BYTE*)((DWORD_PTR)container->blob + i));
	}
}


BOOL KBlast_c_blob_manage(IN OPTIONAL LPCSTR strBlob, IN OPTIONAL char* containerNumber, IN KBLAST_USERLAND_BLOB_DO action)
{
	BOOL status = FALSE;
	DWORD szBlob = (DWORD)strlen(strBlob);
	DWORD pcbBinary = szBlob;
	DWORD dwReturningFlags = 0;
	PKBLAST_USERLAND_BLOBS_CONTAINER tBlob = 0;
	int n = 0;

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
			wprintf(L"[!] Blob containers are all full.\n");
			break;
		}

		tBlob->blob = (BYTE*)LocalAlloc(LPTR, (SIZE_T)szBlob);
		if (tBlob != 0)
		{
			status = CryptStringToBinaryA(strBlob, szBlob, CRYPT_STRING_HEX, tBlob->blob, &pcbBinary, NULL, NULL);
			tBlob->isFull = status;
			if (status == TRUE)
			{
				tBlob->szBlob = szBlob;
				wprintf(L"[+] Blob saved in local container %d.\n", n);
				n = 0;
			}
			else
			{
				wprintf(L"[!] Invalid input.\n");
			}
			break;
		}

	case BLOB_DELETE:
		n = atoi(containerNumber);
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
				wprintf(L"[!] %d container does not exist.\n", n);
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
						wprintf(L"[+] Container %d cleared.\n", n);
					}
					break;
				}
				else
				{
					wprintf(L"[!] Container %d is empty.\n", n);
					break;
				}
			}
		}

	case BLOB_INFO:
		n = atoi(containerNumber);
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
				wprintf(L"[!] Container %d does not exist.\n", n);
				break;
			}

			if (tBlob != 0)
			{
				status = TRUE;
				if (tBlob->isFull == FALSE)
				{
					wprintf(L"[!] Container %d is empty.\n", n);
				}
				else
				{
					KBlast_c_blob_info(tBlob);
					break;
				}
			}
		}

	default:
		break;
	}

	return status;

}