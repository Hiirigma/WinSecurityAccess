// BSIT laboratory work - 1

//		The criteria ::
// - Dynamic loaded library (Windows functions) 
// - Without functions from WinApi
// - Win 7 \\ Win 10

//		What to do ::

//		View Registåred ::
// V - Users	
// V - Groups
// V - SID g
// V - SID u
// V - Privilleges

//		Must change ::
// - Users
// - Groups
// - Privilleges

#include "LibHeader.h"

int ShowObjRights(LSA_HANDLE lsahPolicyHandle, PSID AccountSid, HMODULE advHandle)
{
	PLSA_UNICODE_STRING rights;
	ULONG rights_count;
	LSA_ENUMERATION_INFORMATION *buf;
	ULONG count = 0;
	PROC_LsaEnumerateAccountsWithUserRight _LsaEnumerateAccountsWithUserRight = (PROC_LsaEnumerateAccountsWithUserRight)GetProcAddress(advHandle, "LsaEnumerateAccountsWithUserRight");
	_LsaEnumerateAccountsWithUserRight(lsahPolicyHandle,NULL, (void**)&buf,&count);
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

	_HeapFree(_GetProcessHeap(),
		0,
		domain);

	return psid;
}


DWORD outGroup(LPCWSTR user_name, HMODULE netHandle, LOCALGROUP_USERS_INFO_0 *puGroupBuf) {
	NET_API_STATUS gruRes;
	
	PROC_NetUserGetLocalGroups _NetUserGetLocalGroups = (PROC_NetUserGetLocalGroups)GetProcAddress(netHandle, "NetUserGetLocalGroups");
	DWORD guent;
	DWORD guentread;
	_LOCALGROUP_USERS_INFO_0 *locpuGroupBuf = new LOCALGROUP_USERS_INFO_0[50];
	gruRes = _NetUserGetLocalGroups(
		NULL,
		user_name,
		0,
		LG_INCLUDE_INDIRECT,
		(LPBYTE*)&locpuGroupBuf,
		MAX_PREFERRED_LENGTH,
		&guent,
		&guentread
	);
	if (guentread != 0){
		memcpy(puGroupBuf, locpuGroupBuf, 50 * sizeof(*locpuGroupBuf));
		delete[] locpuGroupBuf;
	}
	return guentread;

}


void outUsers(HMODULE netHandle, HMODULE advHandle, HMODULE kernHandle) {


	if (netHandle == NULL || advHandle == NULL || kernHandle == NULL) {
		printf("Error in loading library\n");
		exit(-1);
	}

	DWORD entries;	
	DWORD entRead;
	_USER_INFO_1 * pUserBuf = new USER_INFO_1[20];
	_LOCALGROUP_INFO_0  * pGroupBuf = new _LOCALGROUP_INFO_0[255];
	LOCALGROUP_USERS_INFO_0 puGroupBuf[50]; 
	PSID Sid;
	LPTSTR sid_str;
	LSA_HANDLE lsahPolicyHandle = NULL;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
	NET_API_STATUS usrRes;
	NET_API_STATUS grRes;
	NET_API_STATUS status;

		PROC_NetUserEnum _NetUserEnum = (PROC_NetUserEnum)GetProcAddress(netHandle, "NetUserEnum");
		PROC_NetLocalGroupEnum _NetLocalGroupEnum = (PROC_NetLocalGroupEnum)GetProcAddress(netHandle, "NetLocalGroupEnum");
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
					printf("User :: %S\n", pUserBuf[i].usri1_name);


					usrRes = outGroup(pUserBuf[i].usri1_name, netHandle, puGroupBuf);
					if (!usrRes) {
						printf("None;");
					}
					else {
						//printf("\n");
						for (int j = 0; j < usrRes; j++) {
							if (puGroupBuf[j].lgrui0_name != NULL) {
								printf("%S; ", puGroupBuf[j].lgrui0_name);
								Sid = getSid(puGroupBuf[j].lgrui0_name, lsahPolicyHandle, advHandle, kernHandle);
								_ConvertSidToStringSidA(Sid, &sid_str);
								printf(" || group SID :: %s\n", sid_str);
								ShowObjRights(lsahPolicyHandle, Sid, advHandle);
							}
						}

					}

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
					wprintf(L"%S\n", pGroupBuf[i].lgrpi0_name);
				}
			}

		}
	delete[] pUserBuf;
	delete[] pGroupBuf;
}

void addUser(HMODULE netHandle, HMODULE advHandle, HMODULE kernHandle) {
	USER_INFO_1 ui;
	DWORD dwLevel = 1;
	DWORD dwError = 0;
	wchar_t user_name[50];
	wchar_t password[50];
	NET_API_STATUS nStatus;

	//
	// Set up the USER_INFO_1 structure.
	//  USER_PRIV_USER: name identifies a user, 
	//    rather than an administrator or a guest.
	//  UF_SCRIPT: required 
	//
	printf("Input username :: ");
	scanf("%ls", &user_name);
	ui.usri1_name = user_name;
	printf("Input password :: ");
	scanf("%ls", &password);
	ui.usri1_password = password;
	ui.usri1_priv = USER_PRIV_USER;
	ui.usri1_home_dir = NULL;
	ui.usri1_comment = NULL;
	ui.usri1_flags = UF_SCRIPT;
	ui.usri1_script_path = NULL;
	//
	// Call the NetUserAdd function, specifying level 1.
	//
	PROC_NetUserAdd _NetUserAdd = (PROC_NetUserAdd)GetProcAddress(netHandle, "NetUserAdd");
	if (_NetUserAdd != NULL)
	{
		// TODO: Set Parameter Values
		nStatus = _NetUserAdd(
			user_name,
			dwLevel,
			(LPBYTE)&ui,
			&dwError);
	}
		
	//
	// If the call succeeds, inform the user.
	//
	if (nStatus == NERR_Success)
		fwprintf(stderr, L"User %s has been successfully added on %s\n",
			password, user_name);
	//
	// Otherwise, print the system error.
	//
	else
		fprintf(stderr, "A system error has occurred: 0x%x\n", nStatus);
}


int main(void)
{
	// API Prototype for Netapi32.dll!NetUserEnum
	HMODULE netHandle = LoadLibrary(("Netapi32.dll"));
	HMODULE advHandle = LoadLibrary(("Advapi32.dll"));
	HMODULE kernHandle = LoadLibrary(("Kernel32.dll"));
	char mode = 0;
	printf("Select program mode (0 - out users/group/privilege); (1 - change u/g/p):: ");
	scanf("%d",&mode);
	switch (mode) {
	case 0: outUsers(netHandle, advHandle, kernHandle); break;
	case 1: addUser(netHandle, advHandle, kernHandle); break;
	}

	setlocale(LC_ALL, "Russian");


	

	FreeLibrary(netHandle);
	FreeLibrary(advHandle);
	FreeLibrary(kernHandle);

	system("pause");
    return 0;
}
