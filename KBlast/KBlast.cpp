/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlast.hpp"


HANDLE g_KblasterDevice					= 0;
RTL_OSVERSIONINFOW g_OsVersionInfo		= { 0 };
SYSTEM_INFO g_SystemInfo				= { 0 };
const wchar_t* g_Architecture			= OSARCH_UNKNOWN;
BOOL l_SignalSelfTermination			= FALSE;

#if defined(__x86_64__) || defined(_M_X64)
const wchar_t* g_KblastArchitecture = OSARCH_X64;
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
const wchar_t* g_KblastArchitecture = OSARCH_X86;
#else
const wchar_t* g_KblastArchitecture = OSARCH_UNKNOWN;
#endif


KBL_COMMAND KblStandardCmd[]{
	{L"help",			L"Show this help",						Kblast_main_std_Help},
	{L"quit",			L"Quit KBlast",							Kblast_main_std_Exit},
	{L"clear",			L"Clear the screen",					Kblast_main_std_ClearConsole},
	{L"pid",			L"Show current pid",					Kblast_main_std_Pid},
	{L"time",			L"Display system time",					Kblast_main_std_Time},
	{L"version",		L"Display system version information",	Kblast_main_std_Version},
	{L"!",				L"Execute system command",				Kblast_main_std_System}
	//{L"whoami",			L"Display current token information",	Kblast_main_std_Whoami}
};

KBL_COMMAND KblModuleCmd[]{
	{L"protection",		L"Commands - ' protection ' ( process protection interactions )",		Kblast_device_IoctlProtection},
	{L"token",			L"Commands - ' token ' ( token manipulation interactions )",			Kblast_device_IoctlToken},
	{L"callback",		L"Commands - ' callback ' ( kernel callbacks interactions )",			Kblast_device_IoctlCallback},
	{L"misc",			L"Commands - ' misc ' ( misc functionalities. )",						Kblast_device_IoctlMisc},
	{L"process",		L"Commands - ' process ' ( process manipulation interactions )",		Kblast_device_IoctlProcess}
	//{L"blob",			L"Commands - ' blob ' ( blob & containers interactions )",				Kblast_device_IoctlBlob}
};


static
inline
BOOL Kblast_main_std_Help(int argc, wchar_t* input)
{
	SIZE_T i = 0;

	for (i = 0; i < KBL_COMM_ELEMS(KblStandardCmd); i++) {
		wprintf(L"%30s\t-\t%s\n",
			KblStandardCmd[i].lpCommand,
			KblStandardCmd[i].lpDescription);
	}

	return TRUE;
}

static
inline
BOOL Kblast_main_std_Exit(int argc, wchar_t* input)
{
	l_SignalSelfTermination = TRUE;

	wprintf(L"Bye!\n");

	return l_SignalSelfTermination;
}

static
inline
BOOL Kblast_main_std_ClearConsole(int argc, wchar_t* input)
{
	system("cls");

	return TRUE;
}

static
inline
BOOL Kblast_main_std_Pid(int argc, wchar_t* input)
{
	wprintf(L"Current Process Id: %d\n", GetCurrentProcessId());

	return TRUE;
}

static
inline
BOOL Kblast_main_std_Time(int argc, wchar_t* input)
{
	SYSTEMTIME SystemTime = { 0 };
	
	GetSystemTime(&SystemTime);
	wprintf(L"System time is : %d:%d:%d - %d/%d/%d\n", 
		SystemTime.wHour, 
		SystemTime.wMinute, 
		SystemTime.wSecond, 
		SystemTime.wMonth, 
		SystemTime.wDay, 
		SystemTime.wYear);

	return TRUE;
}

static
inline
BOOL Kblast_main_std_Version(int argc, wchar_t* input)
{
	wprintf(L"Microsoft Windows NT %d.%d OS Build %d ( OS Arch %s ) ( Kblast arch %s )\n", 
		g_OsVersionInfo.dwMajorVersion, 
		g_OsVersionInfo.dwMinorVersion, g_OsVersionInfo.dwBuildNumber, 
		g_Architecture, // fix here
		g_KblastArchitecture);
	
	return TRUE;
}

static
inline
BOOL Kblast_main_std_System(int argc, wchar_t* input)
{
	BOOL status = FALSE;
	ANSI_STRING AnsiString = { 0 };
	UNICODE_STRING UnicodeString = { 0 };

	RtlInitUnicodeString(&UnicodeString, input);

	if (!Kblast_string_CreateAnsiStringFromUnicodeString(&UnicodeString, &AnsiString)) {
		goto Exit;
	}

	system((const char*)(DWORD_PTR)AnsiString.Buffer + 1);

	status = TRUE;

Exit:
	if (AnsiString.Buffer) {
		Kblast_string_FreeAnsiString(&AnsiString);
	}

	return status;
}


static
inline
BOOL Kblast_main_Shutdown()
{
	CloseHandle(g_KblasterDevice);
	return Kblast_service_DeleteService(g_KblasterService);
}

static
BOOL Kblast_main_DispatchCommand(_In_ wchar_t* input)
{
	BOOL status = FALSE;
	BOOL standard = FALSE;
	BOOL modules = FALSE;
	DWORD index = 0;
	int argc = 0;

	if (!input) {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto Exit;
	}

	standard = Kblast_string_CommandSearch(input, KblStandardCmd, KBL_COMM_ELEMS(KblStandardCmd), &index);
	modules = Kblast_string_CommandSearch(input, KblModuleCmd, KBL_COMM_ELEMS(KblModuleCmd), &index);
	if (!standard && !modules) {
		SetLastError(ERROR_INVALID_COMMAND_LINE);
		goto Exit;
	}

	if (!CommandLineToArgvW(input, &argc)) {
		goto Exit;
	}

	if (standard) {
		status = KblStandardCmd[index].Function(argc, input);
	}
	
	if (modules) {
		status = KblModuleCmd[index].Function(argc, input);
	}
	
	
Exit:
	
	return status;
}


static
void Kblast_main_StartConsole()
{
	wchar_t input[MAX_PATH] = { 0 };

	SetConsoleTitle(L"Kblast");

	wprintf(
		L"    __ __ ____  __           __\n"
		L"   / //_// __ )/ /___ ______/ /_\t| KBlast client - OS Build #%d - Major version #%d\n"
		L"  / ,<  / __  / / __ `/ ___/ __/\t| Architecture : %s\n"
		L" / /| |/ /_/ / / /_/ (__  ) /_\t\t| Website : https://www.github.com/lem0nSec/KBlast\n"
		L"/_/ |_/_____/_/\\__,_/____/\\__/\t\t| Author  : < lem0nSec_@world:~$ >\n"
		L"------------------------------------------------------->>>\n",
		g_OsVersionInfo.dwBuildNumber, g_OsVersionInfo.dwMajorVersion, g_KblastArchitecture
	);

	while (1) {
		wprintf(L"\n" L"[KBlast] --> ");
		fgetws(input, ARRAYSIZE(input), stdin); fflush(stdin);
		Kblast_string_AdjustInputCommandString(input);
		Kblast_main_DispatchCommand(input);
		if (l_SignalSelfTermination) {
			break;
		}
	}

	return;
}

static
BOOL Kblast_main_Initialize()
{
	BOOL status = FALSE;
	PRTLGETVERSION RtlGetVersion = 0;
	HMODULE hNtdll = 0;
	DWORD dwRequiredLength = 0;
	wchar_t lpPath[MAX_PATH] = { 0 };


	dwRequiredLength = GetFullPathName(L"Kblaster.sys", MAX_PATH, lpPath, NULL);
	if (!dwRequiredLength) {
		goto Exit;
	}

	if (!Kblast_process_CheckTokenIntegrityLevel(GetCurrentProcess(), SECURITY_MANDATORY_HIGH_RID)) {
		PRINT_ERR_FULL("Insufficient privileges");
		goto Exit;
	}

	if (!Kblast_service_RunService(L"Kblaster", lpPath, &g_KblasterService)) {
		PRINT_ERR_FULL("Service install failure");
		goto Exit;
	}

	g_KblasterDevice = CreateFile(
		L"\\\\.\\KBlaster",
		FILE_ANY_ACCESS,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_SYSTEM,
		0
	);
	if (g_KblasterDevice == INVALID_HANDLE_VALUE ||
		!g_KblasterDevice) {
		PRINT_ERR_FULL(L"Device opening failure");
		g_KblasterDevice = 0;
		goto Exit;
	}

	hNtdll = GetModuleHandle(L"ntdll.dll");
	if (!hNtdll) {
		goto Exit;
	}

	RtlGetVersion = reinterpret_cast<PRTLGETVERSION>(GetProcAddress(hNtdll, "RtlGetVersion"));
	if (!RtlGetVersion) {
		goto Exit;
	}

	if (!NT_SUCCESS(RtlGetVersion(&g_OsVersionInfo))) {
		goto Exit;
	}

	GetSystemInfo(&g_SystemInfo);

	switch (g_SystemInfo.wProcessorArchitecture)
	{
	case PROCESSOR_ARCHITECTURE_AMD64:
		g_Architecture = OSARCH_X64;
		break;

	case PROCESSOR_ARCHITECTURE_INTEL:
		g_Architecture = OSARCH_X86;
		break;

	case PROCESSOR_ARCHITECTURE_ARM:
		g_Architecture = OSARCH_ARM;
		break;

	case PROCESSOR_ARCHITECTURE_ARM64:
		g_Architecture = OSARCH_ARM64;
		break;

	case PROCESSOR_ARCHITECTURE_IA64:
		g_Architecture = OSARCH_IA64;
		break;

	case PROCESSOR_ARCHITECTURE_UNKNOWN:
		g_Architecture = OSARCH_UNKNOWN;
		break;

	default:
		//SetLastError()
		goto Exit;
	}

	status = TRUE;

Exit:
	if (!status &&
		(g_KblasterService ||
			g_KblasterDevice)) {
		Kblast_main_Shutdown();
	}

	return status;
}


int wmain(int argc, wchar_t* argv[])
{

	if (!Kblast_main_Initialize()) {
		goto Exit;
	}

	Kblast_main_StartConsole();

	Kblast_main_Shutdown();

Exit:

	return 1;
}
