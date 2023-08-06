#include "KBlaster_k_utils.hpp"


WINDOWS_VERSION KBlast_GetWindowsVersion()
{
	NTSTATUS status = 0;
	WINDOWS_VERSION iVersion = WINDOWS_UNSUPPORTED;
	RTL_OSVERSIONINFOW RtlOSVersion = { 0 };
	RtlOSVersion.dwOSVersionInfoSize = sizeof(RtlOSVersion);

	status = RtlGetVersion(&RtlOSVersion);
	if (status != STATUS_SUCCESS)
	{
		DbgPrint("[-] RtlGetVersion failed.\n");
		return WINDOWS_UNSUPPORTED;
	}

	if (RtlOSVersion.dwMajorVersion != 10)
	{
		DbgPrint("[-] Windows version is too old.\n");
		return WINDOWS_UNSUPPORTED;
	}


	switch (RtlOSVersion.dwBuildNumber)
	{
	case 14393:
		iVersion = WINDOWS_REDSTONE_1;
		break;

	case 15063:
		iVersion = WINDOWS_REDSTONE_2;
		break;

	case 16299:
		iVersion = WINDOWS_REDSTONE_3;
		break;

	case 17134:
		iVersion = WINDOWS_REDSTONE_4;
		break;

	case 17763:
		iVersion = WINDOWS_REDSTONE_5;
		break;

	case 18362:
		iVersion = WINDOWS_19H1;
		break;

	case 18363:
		iVersion = WINDOWS_19H2;
		break;

	case 19041:
		iVersion = WINDOWS_20H1;
		break;

	case 19042:
		iVersion = WINDOWS_20H2;
		break;

	case 19043:
		iVersion = WINDOWS_21H1;
		break;

	case 19044:
		iVersion = WINDOWS_21H2;
		break;

	case 19045:
		iVersion = WINDOWS_22H2;
		break;

	default:
		iVersion = WINDOWS_UNSUPPORTED;
		break;
	}

	return iVersion;

}