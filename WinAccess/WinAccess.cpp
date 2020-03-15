// BSIT laboratory work - 1

//		The criteria ::
// - Dynamic loaded library (Windows functions) 
// - Without functions from WinApi
// - Win 7 \\ Win 10

//		What to do ::

//		View Registеred ::
// V - Users	
// V - Groups
// V - SID 
// - Privilleges
//		Must change ::
// - Users
// - Groups
// - Privilleges

#include "LibHeader.h"


//int getPrivil(LPWSTR username, HMODULE advModule, PSID pSID) {
//	NTSTATUS Status = 0;
//	LSA_HANDLE hPolicy = NULL;
//	LSA_OBJECT_ATTRIBUTES ObjAttr = { 0 };
//	PLSA_UNICODE_STRING pPrivs = NULL; // инициализация опять же
//	ULONG cPrivs = 0;
//	DWORD cchDisplayName = 0;
//	CHAR szPrivilegeName[256];
//	DWORD dwLanguageId = 0;
//	if (advModule != NULL)
//	{
//		//printf("Privilleges :: ");
//		//
//		//PROC_LsaOpenPolicy _LsaOpenPolicy = (PROC_LsaOpenPolicy)GetProcAddress(advModule, "LsaOpenPolicy");
//
//		//ObjAttr.Length = sizeof(ObjAttr);
//		//Status = _LsaOpenPolicy(NULL,
//		//	&ObjAttr,
//		//	(POLICY_TRUST_ADMIN | POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT),
//		//	&hPolicy);
//
//		//if (_LsaEnumerateAccountRights != NULL)
//		//{
//
//		//	NTSTATUS result = _LsaEnumerateAccountRights(hPolicy, pSID, &pPrivs, &cPrivs);
//
//		//	if (cPrivs == 0)
//		//		printf("None;");
//		//	else {
//		//		for (int i = 0; i < cPrivs; i++)
//		//			printf("%S; ", pPrivs[i].Buffer);
//		//	}
//
//		//	printf("\n");
//		//	if (result != FALSE)
//		//	{
//		//		
//		//		// API Call Successful
//		//	}
//		//}
//
//		PROC_LookupPrivilegeDisplayNameW _LookupPrivilegeDisplayNameW = (PROC_LookupPrivilegeDisplayNameW)GetProcAddress(advModule, "LookupPrivilegeDisplayNameW");
//		PROC_GetNamedSecurityInfoW _GetNamedSecurityInfoW = (PROC_GetNamedSecurityInfoW)GetProcAddress(advModule, "GetNamedSecurityInfoW");
//
//		/* Checks for Privilege and returns True or False. */
//		LUID luid;
//		PRIVILEGE_SET privs;
//		HANDLE hProcess;
//		HANDLE hToken;
//		hProcess = GetCurrentProcess();
//		if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return FALSE;
//		if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;
//		privs.PrivilegeCount = 1;
//		privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
//		privs.Privilege[0].Luid = luid;
//		privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
//		BOOL bResult;
//		PrivilegeCheck(hToken, &privs, &bResult);
//		return bResult;
//
//
//
//
//
//		//if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
//		//	return 1;
//		//}
//
//		//GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwLength);
//
//		//pTokenPrivileges = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, dwLength);
//		//if (pTokenPrivileges == NULL) {
//		//	CloseHandle(hToken);
//		//	return 1;
//		//}
//
//		//GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwLength, &dwLength);
//
//
//		//for (i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
//
//		//	dwLength = sizeof(szPrivilegeName) / sizeof(szPrivilegeName[0]);
//
//		//	LookupPrivilegeNameA(NULL,
//		//		&pTokenPrivileges->Privileges[i].Luid,
//		//		szPrivilegeName,
//		//		&dwLength);
//
//		//	dwLength = sizeof(szDisplayName) / sizeof(szPrivilegeName[0]);
//
//		//	LookupPrivilegeDisplayNameA(NULL,
//		//		szPrivilegeName,
//		//		szDisplayName,
//		//		&dwLength,
//		//		&dwLanguageId);
//
//		//	puts("----------------------------------------------------------------------");
//		//	printf("PrivilegeName: %s\n", szPrivilegeName);
//		//	printf("DisplayName: %s\n", szDisplayName);
//		//	printf("Enable: %s\n\n", pTokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED ? "True" : "False");
//		//}
//
//		//CloseHandle(hToken);
//		//LocalFree(pTokenPrivileges);
//
//	
//	
//	}
//}


int ShowObjRights(LSA_HANDLE lsahPolicyHandle, PSID AccountSid, HMODULE advHandle)
{
	PLSA_UNICODE_STRING rights;
	ULONG rights_count;
	if (advHandle != NULL)
	{
		PROC_LsaEnumerateAccountRights _LsaEnumerateAccountRights = (PROC_LsaEnumerateAccountRights)GetProcAddress(advHandle, "LsaEnumerateAccountRights");
		NET_API_STATUS nStatus = _LsaEnumerateAccountRights(lsahPolicyHandle, AccountSid, &rights, &rights_count);
		//printf("Code from lsaenum :: %d\n", nStatus);
		if (!(nStatus == NERR_Success || nStatus == 0xC0000034)) {
			fprintf(stderr, "A system error has occurred: %u\n", nStatus);
			return -1;
		}
		printf(("There are %d rights"), rights_count);
		for (int i = 0; i < rights_count; i++)
		{
			printf("\n* %S", rights->Buffer);
			rights++;
		}
		printf(("\n"), rights_count);
	}
	else {
		printf("Error in privilege getting\n");
		return -1;
	}

	//PROC_LsaEnumerateAccountRights _LsaEnumerateAccountRights = (PROC_LsaEnumerateAccountRights)GetProcAddress(advHandle, "LsaEnumerateAccountRights");

	//rights = (PLSA_UNICODE_STRING)0xdeadbeaf;
	//rights_count = 0xcafecafe;

	//NET_API_STATUS nStatus = _LsaEnumerateAccountRights(lsahPolicyHandle, AccountSid, &rights, &rights_count);
	//printf("Code from lsaenum :: 0x%x\n", nStatus);

	//printf("Privilleges :: ");
	//if (rights_count != 0) {
	//	printf("\n");
	//	for (ULONG i = 0; i < rights_count; i++) {
	//		PWSTR pBuf = new WCHAR[rights[i].MaximumLength];
	//		wcsncpy(pBuf, rights[i].Buffer, rights[i].Length);
	//		printf("%d :: %S\n", i + 1, pBuf);
	//		delete[] pBuf;
	//	}
	//}
	//else
	//	printf("None\n");

	//printf("\n");
	//HANDLE Token = NULL;
	//HMODULE hModule = LoadLibrary(("WtsApi32.dll"));
	//if (hModule != NULL)
	//{
	//	PROC_WTSQueryUserToken _WTSQueryUserToken = (PROC_WTSQueryUserToken)GetProcAddress(hModule, "WTSQueryUserToken");
	//	if (_WTSQueryUserToken != NULL)
	//	{
	//		// TODO: Set Parameter Values
	//		BOOL result = _WTSQueryUserToken(
	//			(ULONG)AccountSid,
	//			&Token
	//		);

	//		if (result != FALSE)
	//		{
	//			printf("Reruend res :: 0x%x\n", Token);
	//		}
	//	}
	//	FreeLibrary(hModule);
	//}
	//return 0;
}



PSID getSid(LPWSTR username, LSA_HANDLE lsahPolicyHandle, HMODULE advHandle, HMODULE kernHandle) {
	LPWSTR domain = NULL;
	DWORD size = 0, dom_size = 0;
	SID_NAME_USE peUse;
	PSID  psid = NULL;
	UINT ret_val = ERROR_FUNCTION_FAILED;
	PROC_LookupAccountNameW _LookupAccountNameW = (PROC_LookupAccountNameW)GetProcAddress(advHandle, "LookupAccountNameW");
	PROC_HeapAlloc _HeapAlloc = (PROC_HeapAlloc)GetProcAddress(kernHandle, "HeapAlloc");
	PROC_GetProcessHeap _GetProcessHeap = (PROC_GetProcessHeap)GetProcAddress(kernHandle, "GetProcessHeap");
	PROC_HeapFree _HeapFree = (PROC_HeapFree)GetProcAddress(kernHandle, "HeapFree");

	// TODO: Set Parameter Values
	_LookupAccountNameW(NULL, (LPCSTR)username, NULL, &size, NULL, &dom_size, &peUse);

	psid = (PSID)_HeapAlloc(GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		size);

	domain = (LPWSTR)_HeapAlloc(GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		dom_size * sizeof(WCHAR));


	if (!psid || !domain)
	{
		return (PSID)-1;
		
	}

	ret_val = _LookupAccountNameW(NULL, (LPCSTR)username, psid, &size, (LPTSTR)domain, &dom_size, &peUse);
	if (!ret_val) return PSID(-1);

	//printf("SID :: %s\n", sid_str);

	//_HeapFree(_GetProcessHeap(),
	//	0,
	//	psid);

	_HeapFree(_GetProcessHeap(),
		0,
		domain);

	return psid;
}


//
//PSID getspisjsid(PWSTR ObjName, LSA_HANDLE lsahPolicyHandle, HMODULE advHandle) {
//	NET_API_STATUS nStatus;
//	LSA_UNICODE_STRING name;
//	PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains;
//	PLSA_TRANSLATED_SID2 SID;
//	name.Buffer = ObjName;
//	name.Length = wcslen(ObjName) * sizeof(WCHAR);
//	name.MaximumLength = (wcslen(ObjName) + 1) * sizeof(WCHAR);
//	PROC_LsaLookupNames2 _LsaLookupNames2 = (PROC_LsaLookupNames2)GetProcAddress(advHandle, "LsaLookupNames2");
//	if (_LsaLookupNames2 != NULL)
//	{
//
//		nStatus = _LsaLookupNames2(lsahPolicyHandle, 0x80000000, 1, &name, &ReferencedDomains, &SID);
//		if (nStatus != NERR_Success)
//		{
//			// An error occurred. Display it as a win32 error code.
//			wprintf(L"OpenPolicy returned %lu\n", nStatus);
//			return NULL;
//		}
//	}
//	else
//	{
//		printf("Error in get function pointer 0x%x", _LsaLookupNames2);
//	}
//
//	PROC_LsaEnumerateAccountRights _LsaEnumerateAccountRights = (PROC_LsaEnumerateAccountRights)GetProcAddress(advHandle, "LsaEnumerateAccountRights");
//	PLSA_UNICODE_STRING rights;
//	ULONG rights_count;
//	rights = (PLSA_UNICODE_STRING)0xdeadbeaf;
//	rights_count = 0xcafecafe;
//
//	nStatus = _LsaEnumerateAccountRights(lsahPolicyHandle, SID->Sid, &rights, &rights_count);
//	printf("Code from lsaenum :: 0x%x\n", nStatus);
//
//	printf("Privilleges :: ");
//	if (rights_count != 0) {
//		printf("\n");
//		for (ULONG i = 0; i < rights_count; i++) {
//			PWSTR pBuf = new WCHAR[rights[i].MaximumLength];
//			wcsncpy(pBuf, rights[i].Buffer, rights[i].Length);
//			printf("%d :: %S\n", i + 1, pBuf);
//			delete[] pBuf;
//		}
//	}
//	else
//		printf("None\n");
//
//	printf("\n");
//
//	return SID->Sid;
//}



void outUsers() {
	// API Prototype for Netapi32.dll!NetUserEnum
	HMODULE netHandle = LoadLibrary(("Netapi32.dll"));
	HMODULE advHandle = LoadLibrary(("Advapi32.dll"));
	HMODULE kernHandle = LoadLibrary(("Kernel32.dll"));

	if (netHandle == NULL || advHandle == NULL || kernHandle == NULL) {
		printf("Error in loading library\n");
		exit(-1);
	}

	
	DWORD entries;
	DWORD guent;
	DWORD entRead;
	DWORD guentread;
	_USER_INFO_1 * pUserBuf = new USER_INFO_1[20];
	_LOCALGROUP_INFO_0  * pGroupBuf = new _LOCALGROUP_INFO_0[255];
	_LOCALGROUP_USERS_INFO_0 * puGroupBuf = new LOCALGROUP_USERS_INFO_0[50];
	PSID Sid;
	LPTSTR sid_str;
	LSA_HANDLE lsahPolicyHandle = NULL;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
	NET_API_STATUS usrRes;
	NET_API_STATUS grRes;
	NET_API_STATUS gruRes;
	NET_API_STATUS status;

	if (netHandle != NULL)
	{
		PROC_NetUserEnum _NetUserEnum = (PROC_NetUserEnum)GetProcAddress(netHandle, "NetUserEnum");
		PROC_NetLocalGroupEnum _NetLocalGroupEnum = (PROC_NetLocalGroupEnum)GetProcAddress(netHandle, "NetLocalGroupEnum");
		PROC_NetUserGetLocalGroups _NetUserGetLocalGroups = (PROC_NetUserGetLocalGroups)GetProcAddress(netHandle, "NetUserGetLocalGroups");
		PROC_ConvertSidToStringSidA _ConvertSidToStringSidA = (PROC_ConvertSidToStringSidA)GetProcAddress(advHandle, "ConvertSidToStringSidA");
		PROC_LsaOpenPolicy _LsaOpenPolicy = (PROC_LsaOpenPolicy)GetProcAddress(advHandle, "LsaOpenPolicy");

		usrRes = _LsaOpenPolicy(
			NULL,
			&ObjectAttributes,
			POLICY_LOOKUP_NAMES,
			&lsahPolicyHandle
		);
		if (usrRes == NERR_Success)
			fwprintf(stderr, L"Successfully obtain policy\n");
		else {
			fprintf(stderr, "A system error has occurred: %d\n", usrRes);
			return;
		}


		if (_NetUserEnum != NULL && _NetLocalGroupEnum != NULL)
		{
			// TODO: Set Parameter Values
			usrRes = _NetUserEnum(
				NULL,
				1, // this attribute to change structure fields 
				0,
				(LPBYTE*)&pUserBuf,
				MAX_PREFERRED_LENGTH,
				/*out*/&entRead,
				/*out*/&entries,
				/*out resumehandle*/ NULL
			);

			
			if (usrRes == NERR_Success)
			{
				printf("\tList of users in system :: \n");
				for (int i = 0;i!=entries; i++) {
					if (pUserBuf[i].usri1_name == NULL) break;
					gruRes = _NetUserGetLocalGroups(
						NULL,
						pUserBuf[i].usri1_name,
						0,
						LG_INCLUDE_INDIRECT,
						(LPBYTE*)&puGroupBuf,
						MAX_PREFERRED_LENGTH,
						&guent,
						&guentread
					);



					printf("User :: %S\n", pUserBuf[i].usri1_name);
					if (guentread == 0)
						printf("None;");
					for (int j = 0; j < guentread; j++) {
						if (puGroupBuf[j].lgrui0_name != NULL) {
							printf("%S; ", puGroupBuf[j].lgrui0_name);
							Sid = getSid(puGroupBuf[j].lgrui0_name, lsahPolicyHandle, advHandle, kernHandle);
							_ConvertSidToStringSidA(Sid, &sid_str);
							printf(" || group SID :: %s\n", sid_str);
							ShowObjRights(lsahPolicyHandle, Sid, advHandle);
						}
					}
					//getPrivil(pUserBuf[i].usri1_name, advHandle);

					Sid = getSid(pUserBuf[i].usri1_name, lsahPolicyHandle, advHandle,kernHandle);
					_ConvertSidToStringSidA(Sid, &sid_str);
					printf("user SID :: %s\n", sid_str);
					ShowObjRights(lsahPolicyHandle,Sid,advHandle);
					if (usrRes)
						printf("Get sid error with code :: %d", usrRes);
					printf("\n\n");
				}
			}
			entRead = 0;
			entries = 0;
			grRes = _NetLocalGroupEnum(
				NULL,
				0,
				(LPBYTE*)&pGroupBuf,
				MAX_PREFERRED_LENGTH,
				/*out*/&entRead,
				/*out*/&entries,
				NULL
			);

			if (grRes == NERR_Success) {
				printf("\tList of groups in system :: \n");
				for (int i = 0; i != entries; i++) {
					if (pGroupBuf[i].lgrpi0_name == NULL) break;
					Sid = getSid(pGroupBuf[i].lgrpi0_name, lsahPolicyHandle, advHandle, kernHandle);
					_ConvertSidToStringSidA(Sid, &sid_str);
					printf("group SID :: %s\t", sid_str);
					printf("%S\n", pGroupBuf[i].lgrpi0_name);
				}
			}

		}

	}
	delete[] pUserBuf;
	delete[] puGroupBuf;
	delete[] pGroupBuf;
	FreeLibrary(netHandle);
	FreeLibrary(advHandle);
	FreeLibrary(kernHandle);
}


int main(void)
{
	setlocale(LC_ALL, "Russian");
	outUsers();
	system("pause");
    return 0;
}
