/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "Kblast_process.hpp"


BOOL Kblast_process_GetProcessIdByNameLazy(
	_In_ const wchar_t* ProcessName,
	_Inout_ PDWORD processId)
{
	BOOL status = FALSE;

	DWORD result = 0;
	HANDLE hSnap = 0;
	PROCESSENTRY32W ProcessEntry = { 0 };

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		goto Exit;
	}

	ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32First(hSnap, &ProcessEntry)) {
		goto Exit;
	}

	while (Process32Next(hSnap, &ProcessEntry)) {
		if (!_wcsicmp(ProcessEntry.szExeFile, ProcessName)) {
			*processId = ProcessEntry.th32ProcessID;

			status = TRUE;
			break;
		}
	}

	if (!status) {
		SetLastError(ERROR_NOT_FOUND);
	}

	SecureZeroMemory(&ProcessEntry, sizeof(PROCESSENTRY32W));


Exit:
	if (hSnap) {
		CloseHandle(hSnap);
	}

	return status;
}


BOOL Kblast_process_GetActiveProcesses(
	_In_opt_ LPDWORD pProcessIds, 
	_In_ DWORD dwLength, 
	_Inout_ PDWORD pNumberOfProcessIds)
{
	BOOL status = FALSE;

	HANDLE hSnap = 0;
	PROCESSENTRY32W ProcessEntry = { 0 };
	DWORD dwProcesses = 0;


	if (!pNumberOfProcessIds) {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto Exit;
	}

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		goto Exit;
	}

	ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32First(hSnap, &ProcessEntry)) {
		goto Exit;
	}

	while (Process32Next(hSnap, &ProcessEntry)) {
		dwProcesses++;
	}

	*pNumberOfProcessIds = dwProcesses;

	if (dwLength < dwProcesses * sizeof(DWORD) ||
		!pProcessIds) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		goto Exit;
	}

	if (!Process32First(hSnap, &ProcessEntry)) {
		goto Exit;
	}

	dwProcesses = 0;

	while (Process32Next(hSnap, &ProcessEntry)) {
		pProcessIds[dwProcesses] = ProcessEntry.th32ProcessID;
		dwProcesses++;
	}

	status = TRUE;

Exit:
	return status;
}


void Kblast_process_ReleaseProcessInformation(
	_In_ PKBL_PROCESS_INFORMATION pProcessInformation)
{
	BOOL status = FALSE;

	if (pProcessInformation) {
		if (pProcessInformation->ImageFileName.Buffer) {
			LocalFree(pProcessInformation->ImageFileName.Buffer);
		}
		if (pProcessInformation->ReferencedDomain.Buffer) {
			LocalFree(pProcessInformation->ReferencedDomain.Buffer);
		}
		SecureZeroMemory(pProcessInformation, sizeof(KBL_PROCESS_INFORMATION));
	}

	return;
}


BOOL Kblast_process_AcquireProcessInformation(
	_In_ DWORD processId, 
	_Inout_ PKBL_PROCESS_INFORMATION pProcessInformation,
	_In_ DWORD dwLength)
{
	BOOL status = FALSE;

	HANDLE hProcess = 0;
	HANDLE hToken = 0;
	PROCESS_PROTECTION_LEVEL_INFORMATION ProcessProtection = { 0 };
	DWORD dwReturnLength = 0;
	DWORD cchName = 0;
	DWORD cchReferencedDomainName = 0;
	PTOKEN_OWNER pTokenOwner = 0;
	SID_NAME_USE SidNameUse;
	LPWSTR pName = 0;
	LPWSTR pReferencedDomainName = 0;


	if (!pProcessInformation ||
		!processId ||
		dwLength < sizeof(KBL_PROCESS_INFORMATION)) {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto Exit;
	}

	pProcessInformation->processId = processId;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
	if (!hProcess ||
		hProcess == INVALID_HANDLE_VALUE) {
		goto Exit;
	}

	if (!GetProcessInformation(hProcess, ProcessProtectionLevelInfo, &ProcessProtection, sizeof(PROCESS_PROTECTION_LEVEL_INFORMATION)) ||
		!ProcessProtection.ProtectionLevel) {
		goto Exit;
	}

	pProcessInformation->ProtectionLevel = ProcessProtection.ProtectionLevel;

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken) ||
		hToken == INVALID_HANDLE_VALUE ||
		!hToken) {
		goto Exit;
	}

	if (!GetTokenInformation(hToken, TokenOwner, NULL, 0, &dwReturnLength) ||
		!dwReturnLength) {
		goto Exit;
	}

	pTokenOwner = static_cast<PTOKEN_OWNER>(LocalAlloc(LPTR, dwReturnLength));
	if (!pTokenOwner) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		goto Exit;
	}

	if (!GetTokenInformation(hToken, TokenOwner, pTokenOwner, dwReturnLength, &dwReturnLength)) {
		goto Exit;
	}
	
	if (!LookupAccountSid(NULL, pTokenOwner->Owner, NULL, &cchName, NULL, &cchReferencedDomainName, &SidNameUse) ||
		!cchName ||
		!cchReferencedDomainName) {
		goto Exit;
	}

	pName = static_cast<LPWSTR>(LocalAlloc(LPTR, cchName));
	pReferencedDomainName = static_cast<LPWSTR>(LocalAlloc(LPTR, cchReferencedDomainName));
	if (!pName ||
		!pReferencedDomainName) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		goto Exit;
	}

	if (!LookupAccountSid(NULL, pTokenOwner->Owner, pName, &cchName, pReferencedDomainName, &cchReferencedDomainName, &SidNameUse)) {
		goto Exit;
	}

	// Not sure if the Buffer field is allocated by RtlInitUnicodeString
	// or it's just making the struct point to the pName and pReferencedDomainName here.
	// If this is the case, I can't free those buffers here. That's why we have
	// Kblast_process_ReleaseProcessInformation
	RtlInitUnicodeString(&pProcessInformation->Account, pName);
	RtlInitUnicodeString(&pProcessInformation->ReferencedDomain, pReferencedDomainName);

	status = TRUE;

Exit:
	if (hToken) {
		CloseHandle(hToken);
	}
	if (hProcess) {
		CloseHandle(hProcess);
	}
	if (pTokenOwner) {
		LocalFree(pTokenOwner);
	}
	if (!status && pName) {
		LocalFree(pName);
	}
	if (!status && pReferencedDomainName) {
		LocalFree(pReferencedDomainName);
	}

	return status;
}

BOOL Kblast_process_GetDeviceDriverBaseAddress(
	_In_ const wchar_t* DeviceDriverName, 
	_Inout_ LPVOID *BaseAddress)
{
	BOOL status = FALSE;
	LPVOID pArrayBaseAddresses = 0;
	LPVOID pCurrentBaseAddress = 0;
	LPWSTR lpBaseName = 0;
	DWORD dwNeeded = 0;
	DWORD iterator = 0;


	if (!EnumDeviceDrivers(NULL, 0, &dwNeeded) ||
		!dwNeeded) {
		goto Exit;
	}

	pArrayBaseAddresses = static_cast<LPVOID>(LocalAlloc(LPTR, dwNeeded));
	if (!pArrayBaseAddresses) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		goto Exit;
	}

	if (!EnumDeviceDrivers((LPVOID*)pArrayBaseAddresses, dwNeeded, &dwNeeded)) {
		goto Exit;
	}

	lpBaseName = static_cast<LPWSTR>(LocalAlloc(LPTR, MAX_PATH));
	if (!lpBaseName) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		goto Exit;
	}

	for (iterator; iterator < dwNeeded / sizeof(LPVOID); iterator += sizeof(LPVOID)) {
		pCurrentBaseAddress = *(LPVOID*)(static_cast<PBYTE>(pArrayBaseAddresses) + iterator);
		if (!GetDeviceDriverBaseName(pCurrentBaseAddress, lpBaseName, MAX_PATH)) {
			goto Exit;
		}

		if (!_wcsicmp(lpBaseName, DeviceDriverName)) {
			*BaseAddress = pCurrentBaseAddress;

			status = TRUE;
			break;
		}
	}


Exit:
	if (lpBaseName) {
		LocalFree(lpBaseName);
	}
	if (pArrayBaseAddresses) {
		LocalFree(pArrayBaseAddresses);
	}

	return status;

}


DWORD Kblast_process_CheckTokenIntegrityLevel(
	_In_ HANDLE hProcess,
	_In_ DWORD dwRequestedIntegrity)
{
	BOOL status = FALSE;
	HANDLE hToken = 0;
	DWORD dwReturnLength = 0;
	PTOKEN_MANDATORY_LABEL pTokenIntegrity = NULL;
	UCHAR sidSubAuthCount = 0;
	DWORD dwIntegrityLevel = 0;

	
	status = OpenProcessToken(hProcess, TOKEN_QUERY, &hToken); 
	if (!status) {
		goto Exit;
	}

	GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwReturnLength);
	if (!dwReturnLength) {
		goto Exit;
	}

	pTokenIntegrity = static_cast<PTOKEN_MANDATORY_LABEL>(LocalAlloc(LPTR, dwReturnLength));
	if (!pTokenIntegrity) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		goto Exit;
	}

	status = GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIntegrity, dwReturnLength, &dwReturnLength);
	if (!status) {
		goto Exit;
	}

	sidSubAuthCount = *GetSidSubAuthorityCount(pTokenIntegrity->Label.Sid);
	if (GetLastError() != ERROR_SUCCESS) {
		goto Exit;
	}

	dwIntegrityLevel = *GetSidSubAuthority(pTokenIntegrity->Label.Sid, sidSubAuthCount - 1);
	if (GetLastError() != ERROR_SUCCESS) {
		goto Exit;
	}

	if (dwIntegrityLevel >= dwRequestedIntegrity) {
		status = TRUE;
	}


Exit:
	if (pTokenIntegrity) {
		LocalFree(pTokenIntegrity);
	}
	if (hToken) {
		CloseHandle(hToken);
	}

	return status;
}


BOOL Kblast_process_SetTokenPrivilege(
	_In_ HANDLE hProcess, 
	_In_ LPCWSTR Privilege, 
	_In_ BOOL isEnable)
{
	BOOL status = FALSE;
	HANDLE hToken = 0;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };
	PRIVILEGE_SET PrivilegeSet = { 0 };
	LUID luid = { 0 };


	if (!LookupPrivilegeValueW(NULL, Privilege, &luid)) {
		goto Exit;
	}

	if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken)) {
		goto Exit;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Luid = luid;
	
	if (isEnable) {
		TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else {
		TokenPrivileges.Privileges[0].Attributes = 0;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		goto Exit;
	}

	PrivilegeSet.PrivilegeCount = 1;
	PrivilegeSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
	PrivilegeSet.Privilege[0].Luid = luid;
	PrivilegeSet.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!PrivilegeCheck(hToken, &PrivilegeSet, &status)) {
		goto Exit;
	}

Exit:
	if (hToken) {
		CloseHandle(hToken);
	}

	return status;
}
