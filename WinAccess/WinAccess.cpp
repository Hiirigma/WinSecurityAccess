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
// V - Users add
// V - Users delete
// V - Groups add
// V - Groups delete
// V - Privilleges add
// V - Privilleges delete

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
			printf("A system error has occurred: %u\n", nStatus);
			return -1;
		}
		printf(("There are %d rights"), rights_count);
		for (int i = 0; i < rights_count; i++)
		{
			printf("\n%d - %S", i+1, rights->Buffer);
			rights++;
		}
		printf(("\n"), rights_count);
	}
	else {
		printf("Error in privilege getting\n");
		return -1;
	}

}

int getObjRights(LSA_HANDLE lsahPolicyHandle, PSID AccountSid, HMODULE advHandle, PWSTR *buffer)
{
	PLSA_UNICODE_STRING rights;
	ULONG rights_count;
	LSA_ENUMERATION_INFORMATION *buf;
	ULONG count = 0;
	PROC_LsaEnumerateAccountsWithUserRight _LsaEnumerateAccountsWithUserRight = (PROC_LsaEnumerateAccountsWithUserRight)GetProcAddress(advHandle, "LsaEnumerateAccountsWithUserRight");
	_LsaEnumerateAccountsWithUserRight(lsahPolicyHandle, NULL, (void**)&buf, &count);
	if (advHandle != NULL)
	{
		PROC_LsaEnumerateAccountRights _LsaEnumerateAccountRights = (PROC_LsaEnumerateAccountRights)GetProcAddress(advHandle, "LsaEnumerateAccountRights");
		NET_API_STATUS nStatus = _LsaEnumerateAccountRights(lsahPolicyHandle, AccountSid, &rights, &rights_count);
		//printf("Code from lsaenum :: %d\n", nStatus);
		if (!(nStatus == NERR_Success || nStatus == 0xC0000034)) {
			printf("A system error has occurred: %u\n", nStatus);
			return -1;
		}
		printf(("There are %d rights"), rights_count);
		for (int i = 0; i < rights_count; i++)
		{
			buffer[i] = rights->Buffer;
			printf("\n%d - %S", i + 1, rights->Buffer);
			rights++;
		}
		printf(("\n"), rights_count);
	}
	else {
		printf("Error in privilege getting\n");
		return -1;
	}
	return rights_count;
}


PSID getSid(LPWSTR username, HMODULE advHandle, HMODULE kernHandle) {
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
		PROC_LsaClose _LsaClose = (PROC_LsaClose)GetProcAddress(advHandle, "LsaClose");
		usrRes = _LsaOpenPolicy(
			NULL,
			&ObjectAttributes,
			POLICY_LOOKUP_NAMES,
			&lsahPolicyHandle
		);
		if (usrRes == NERR_Success)
			printf("Successfully obtain policy\n");
		else {
			printf("A system error has occurred: %d\n", usrRes);
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
						printf("None;\n");
					}
					else {
						//printf("\n");
						for (int j = 0; j < usrRes; j++) {
							if (puGroupBuf[j].lgrui0_name != NULL) {
								printf("%S; ", puGroupBuf[j].lgrui0_name);
								Sid = getSid(puGroupBuf[j].lgrui0_name, advHandle, kernHandle);
								_ConvertSidToStringSidA(Sid, &sid_str);
								printf(" || group SID :: %s\n", sid_str);
								ShowObjRights(lsahPolicyHandle, Sid, advHandle);
							}
						}

					}

					Sid = getSid(pUserBuf[i].usri1_name, advHandle,kernHandle);
					_ConvertSidToStringSidA(Sid, &sid_str);
					printf("user SID :: %s\n", sid_str);
					ShowObjRights(lsahPolicyHandle,Sid,advHandle);
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
					Sid = getSid(pGroupBuf[i].lgrpi0_name, advHandle, kernHandle);
					_ConvertSidToStringSidA(Sid, &sid_str);
					printf("group SID :: %s\t", sid_str);
					wprintf(L"%ls\n", pGroupBuf[i].lgrpi0_name);
				}
			}

		}
	delete[] pUserBuf;
	delete[] pGroupBuf;
	_LsaClose(lsahPolicyHandle);
}

int addUser(HMODULE netHandle, HMODULE advHandle, HMODULE kernHandle) {
	USER_INFO_1               user_info;
	NET_API_STATUS            err = 0;
	DWORD                     parm_err = 0;
	wchar_t lpszUser[50];
	wchar_t lpszPassword[50];

	// Set up the USER_INFO_1 structure. 
	printf("Input username :: ");
	wscanf(L"%s", lpszUser);
	printf("Input password :: ");
	wscanf(L"%s", lpszPassword);

	user_info.usri1_name = (LPWSTR)lpszUser;
	user_info.usri1_password = (LPWSTR)lpszPassword;
	user_info.usri1_priv = USER_PRIV_USER;
	user_info.usri1_home_dir = (LPWSTR)"";
	user_info.usri1_comment = NULL;
	user_info.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD;;
	user_info.usri1_script_path = NULL;
	PROC_NetUserAdd _NetUserAdd = (PROC_NetUserAdd)GetProcAddress(netHandle, "NetUserAdd");
	if (_NetUserAdd != NULL)
	{

		err = _NetUserAdd(NULL,        // PDC name 
			1,                    // level 
			(LPBYTE)&user_info,  // input buffer 
			&parm_err);          // parameter in error 

		switch (err)
		{
		case 0:
			printf("User successfully created.\n");
			break;
		case NERR_UserExists:
			printf("User already exists.\n");
			err = 0;
			break;
		case ERROR_INVALID_PARAMETER:
			printf("Invalid parameter error adding user; parameter index = %d\n",
				parm_err);
			return(err);
		default:
			printf("Error adding user: %d\n", err);
			return(err);
		}

	}
}


int delUser(HMODULE netHandle, HMODULE advHandle, HMODULE kernHandle) {
	// Source Code
	wchar_t lpszUser[50];
	if (netHandle != NULL)
	{
		PROC_NetUserDel _NetUserDel = (PROC_NetUserDel)GetProcAddress(netHandle, "NetUserDel");
		if (_NetUserDel != NULL)
		{
			printf("Input user name :: ");
			wscanf(L"%s", lpszUser);
			// TODO: Set Parameter Values
			NET_API_STATUS result = _NetUserDel(
				NULL,
				lpszUser
			);

			if (result == NERR_Success)
			{
				printf("User successfully deleted.\n");
				return 0;
				// API Call Successful
			}
			else {
				printf("Function error with code %d.\n", result);
				return 1;
			}
		}
	}

}

int addGroup(HMODULE netHandle, HMODULE advHandle, HMODULE kernHandle) {
		DWORD	parm_err = 0;
		DWORD dwLevel = 0;
		wchar_t lpszGroup[50];
		_LOCALGROUP_INFO_0 l_group;
		PROC_NetLocalGroupAdd _NetLocalGroupAdd = (PROC_NetLocalGroupAdd)GetProcAddress(netHandle, "NetLocalGroupAdd");
		if (_NetLocalGroupAdd != NULL)
		{
			printf("Input group name :: ");
			wscanf(L"%s", lpszGroup);
			l_group.lgrpi0_name = lpszGroup;
			// TODO: Set Parameter Values
			NET_API_STATUS result = _NetLocalGroupAdd(
				NULL,
				dwLevel,
				(LPBYTE)&l_group,
				&parm_err
			);

			if (result == NERR_Success)
			{
				printf("Group added sucessfuly\n");
			}
			else
			{
				printf("Error in addign group :: %d\n", result);
			}
		}
	return 0;
}


int delGroup(HMODULE netHandle, HMODULE advHandle, HMODULE kernHandle) {
	wchar_t lpszGroup[50];
	PROC_NetLocalGroupDel _NetLocalGroupDel = (PROC_NetLocalGroupDel)GetProcAddress(netHandle, "NetLocalGroupDel");
		if (_NetLocalGroupDel != NULL)
		{
			printf("Input group name :: ");
			wscanf(L"%s", lpszGroup);
			// TODO: Set Parameter Values
			NET_API_STATUS result = _NetLocalGroupDel(
				NULL,
				lpszGroup
			);

			if (result == NERR_Success)
			{
				printf("Success delete group\n");
			}
			else {
				printf("Error while deleting group :: %d\n", result);

			}
		}

	return 0;
}


void AddMembersInGroup(HMODULE advHandle, HMODULE kernHandle, HMODULE netHandle)
{
	PROC_NetLocalGroupAddMembers _NetLocalGroupAddMembers = (PROC_NetLocalGroupAddMembers)GetProcAddress(netHandle, "NetLocalGroupAddMembers");
	PROC_LsaOpenPolicy _LsaOpenPolicy = (PROC_LsaOpenPolicy)GetProcAddress(advHandle, "LsaOpenPolicy");
	PROC_LsaClose _LsaClose = (PROC_LsaClose)GetProcAddress(advHandle, "LsaClose");
	NET_API_STATUS nStatus;
	LOCALGROUP_MEMBERS_INFO_0 pBuf;
	LSA_HANDLE lsahPolicyHandle = NULL;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	wchar_t username[50] = { 0 };
	wchar_t groupname[50] = { 0 };
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
	nStatus = _LsaOpenPolicy(
		NULL,
		&ObjectAttributes,
		POLICY_ALL_ACCESS,
		&lsahPolicyHandle
	);
	if (nStatus == NERR_Success)
		printf("Successfully obtain policy\n");
	else {
		printf("Error while added user in group :: %d\n", nStatus);
		return;
	}
	printf("Enter the user name:\n");
	wscanf(L"%s", username);
	PSID AccountSid = getSid(username, advHandle, kernHandle);
	if (AccountSid == NULL) {
		printf("Error while delete user from group :: SID is NULL\n");
		return;
	}
	pBuf.lgrmi0_sid = AccountSid;
	printf("Enter the group name:\n");
	wscanf(L"%s", groupname);
	nStatus = _NetLocalGroupAddMembers(NULL,
		groupname,
		0,
		(LPBYTE)&pBuf,
		1);
	if (nStatus == NERR_Success)
		printf("Successfully added member\n");
	else {
		printf("Error while delete user from group :: %d\n", nStatus);
		return;
	}
	_LsaClose(lsahPolicyHandle);
}


void DelMembersInGroup(HMODULE advHandle, HMODULE kernHandle, HMODULE netHandle)
{
	PROC_NetLocalGroupDelMembers _NetLocalGroupDelMembers = (PROC_NetLocalGroupDelMembers)GetProcAddress(netHandle, "NetLocalGroupDelMembers");
	PROC_LsaOpenPolicy _LsaOpenPolicy = (PROC_LsaOpenPolicy)GetProcAddress(advHandle, "LsaOpenPolicy");
	PROC_LsaClose _LsaClose = (PROC_LsaClose)GetProcAddress(advHandle, "LsaClose");
	NET_API_STATUS nStatus;
	LOCALGROUP_MEMBERS_INFO_0 pBuf;
	LSA_HANDLE lsahPolicyHandle = NULL;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	wchar_t username[50] = { 0 };
	wchar_t groupname[50] = { 0 };
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
	nStatus = _LsaOpenPolicy(
		NULL,
		&ObjectAttributes,
		POLICY_ALL_ACCESS,
		&lsahPolicyHandle
	);
	if (nStatus == NERR_Success)
		printf("Successfully obtain policy\n");
	else {
		printf("A system error has occurred: %d\n", nStatus);
		return;
	}
	
	printf("Enter username :: ");
	wscanf(L"%s", username);
	PSID AccountSid = getSid(username,advHandle,kernHandle);
	if (AccountSid == NULL)
		return;
	pBuf.lgrmi0_sid = AccountSid;
	
	printf("Enter the user name :: ");
	wscanf(L"%s", groupname);
	nStatus = _NetLocalGroupDelMembers(NULL,
		groupname,
		0,
		(LPBYTE)&pBuf,
		1);
	if (nStatus == NERR_Success)
		printf("Successfully deleted member\n");
	else {
		printf("A system error has occurred :: %d\n", nStatus);
		return;
	}
	_LsaClose(lsahPolicyHandle);
}




void AddLogonRights(HMODULE advHandle, HMODULE kernHandle, HMODULE netHandle)
{

	PROC_LsaOpenPolicy _LsaOpenPolicy = (PROC_LsaOpenPolicy)GetProcAddress(advHandle, "LsaOpenPolicy");
	PROC_LsaAddAccountRights _LsaAddAccountRights = (PROC_LsaAddAccountRights)GetProcAddress(advHandle, "LsaAddAccountRights");
	PROC_LsaClose _LsaClose = (PROC_LsaClose)GetProcAddress(advHandle, "LsaClose");
	NET_API_STATUS nStatus;
	LSA_HANDLE lsahPolicyHandle = NULL;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	LSA_UNICODE_STRING UserRights;
	wchar_t username[50] = { 0 };
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
	nStatus = _LsaOpenPolicy(
		NULL,
		&ObjectAttributes,
		POLICY_ALL_ACCESS,
		&lsahPolicyHandle
	);
	if (nStatus == NERR_Success)
		printf("Successfully obtain policy\n");
	else {
		printf("A system error has occurred :: %d\n", nStatus);
		return;
	}
	
	printf("Enter the user name:\n");
	wscanf(L"%s", username);
	PSID AccountSid = getSid(username, advHandle,kernHandle);
	if (AccountSid == NULL) {
		printf("Error while delete user from group :: SID is NULL\n");
		return;
	}

	UserRights.Buffer = L"SeShutdownPrivilege";
	UserRights.Length = strlen(SE_SHUTDOWN_NAME) * sizeof(wchar_t);
	UserRights.MaximumLength = (strlen(SE_SHUTDOWN_NAME) + 1) * sizeof(wchar_t);

	ULONG CountOfRights = 1;
	nStatus = _LsaAddAccountRights(lsahPolicyHandle,
		AccountSid,
		&UserRights,
		CountOfRights);
	if (nStatus == NERR_Success)
		printf("Successfully added shutdown right\n");
	else {
		printf("A system error has occurred: %d\n", nStatus);
		return;
	}
	_LsaClose(lsahPolicyHandle);
}


void DelLogonRights(HMODULE advHandle, HMODULE kernHandle, HMODULE netHandle)
{

	PROC_LsaOpenPolicy _LsaOpenPolicy = (PROC_LsaOpenPolicy)GetProcAddress(advHandle, "LsaOpenPolicy");
	PROC_LsaRemoveAccountRights _LsaRemoveAccountRights = (PROC_LsaRemoveAccountRights)GetProcAddress(advHandle, "LsaRemoveAccountRights");
	PROC_LsaClose _LsaClose = (PROC_LsaClose)GetProcAddress(advHandle, "LsaClose");
	NET_API_STATUS nStatus;
	ULONG CountOfRights = 1;
	LSA_HANDLE lsahPolicyHandle = NULL;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	wchar_t username[50] = { 0 };
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
	nStatus = _LsaOpenPolicy(
		NULL,
		&ObjectAttributes,
		POLICY_ALL_ACCESS,
		&lsahPolicyHandle
	);
	if (nStatus == NERR_Success)
		printf("Successfully obtain policy\n");
	else {
		printf("A system error has occurred :: %d\n", nStatus);
		return;
	}
	printf("Enter the user name:\n");
	wscanf(L"%s", username);
	PSID AccountSid = getSid(username,advHandle,kernHandle);

	if (AccountSid == NULL) {
		printf("Error while delete user from group :: SID is NULL\n");
		return;
	}

	LSA_UNICODE_STRING UserRights;
	UserRights.Buffer = L"SeShutdownPrivilege";
	UserRights.Length = strlen(SE_SHUTDOWN_NAME) * sizeof(wchar_t);
	UserRights.MaximumLength = (strlen(SE_SHUTDOWN_NAME) + 1) * sizeof(wchar_t);

	nStatus = _LsaRemoveAccountRights(lsahPolicyHandle,
		AccountSid,
		FALSE,
		&UserRights,
		CountOfRights);
	if (nStatus == NERR_Success)
		printf("Successfully deleted shutdown right\n");
	else {
		printf("A system error has occurred :: %d\n", nStatus);
		return;
	}
	_LsaClose(lsahPolicyHandle);
}




void AddRights(HMODULE advHandle, HMODULE kernHandle, HMODULE netHandle)
{
	wchar_t privil[][50] = {
		L"SeCreateTokenPrivilege",
		L"SeAssignPrimaryTokenPrivilege",
		L"SeLockMemoryPrivilege",
		L"SeIncreaseQuotaPrivilege",
		L"SeUnsolicitedInputPrivilege",
		L"SeMachineAccountPrivilege",
		L"SeTcbPrivilege",
		L"SeSecurityPrivilege",
		L"SeTakeOwnershipPrivilege",
		L"SeLoadDriverPrivilege",
		L"SeSystemProfilePrivilege",
		L"SeSystemtimePrivilege",
		L"SeProfileSingleProcessPrivilege",
		L"SeIncreaseBasePriorityPrivilege",
		L"SeCreatePagefilePrivilege",
		L"SeCreatePermanentPrivilege",
		L"SeBackupPrivilege",
		L"SeRestorePrivilege",
		L"SeShutdownPrivilege",
		L"SeDebugPrivilege",
		L"SeAuditPrivilege",
		L"SeSystemEnvironmentPrivilege",
		L"SeChangeNotifyPrivilege",
		L"SeRemoteShutdownPrivilege",
		L"SeUndockPrivilege",
		L"SeSyncAgentPrivilege",
		L"SeEnableDelegationPrivilege",
		L"SeManageVolumePrivilege",
		L"SeImpersonatePrivilege",
		L"SeCreateGlobalPrivilege",
		L"SeTrustedCredManAccessPrivilege",
		L"SeRelabelPrivilege",
		L"SeIncreaseWorkingSetPrivilege",
		L"SeTimeZonePrivilege",
		L"SeCreateSymbolicLinkPrivilege",
		L"SeServiceLogonRight",
		L"SeInteractiveLogonRight",
		L"SeNetworkLogonRight",
		L"SeBatchLogonRight",
		L"SeRemoteInteractiveLogonRight",
		L"SeDenyInteractiveLogonRight"
	};

	PROC_LsaOpenPolicy _LsaOpenPolicy = (PROC_LsaOpenPolicy)GetProcAddress(advHandle, "LsaOpenPolicy");
	PROC_LsaAddAccountRights _LsaAddAccountRights = (PROC_LsaAddAccountRights)GetProcAddress(advHandle, "LsaAddAccountRights");
	PROC_LsaClose _LsaClose = (PROC_LsaClose)GetProcAddress(advHandle, "LsaClose");
	ULONG CountOfRights = 1;
	NET_API_STATUS nStatus;
	LSA_HANDLE lsahPolicyHandle = NULL;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	LSA_UNICODE_STRING UserRights;
	wchar_t username[50] = { 0 };
	int mode = 0;
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
	nStatus = _LsaOpenPolicy(
		NULL,
		&ObjectAttributes,
		POLICY_ALL_ACCESS,
		&lsahPolicyHandle
	);
	if (nStatus == NERR_Success)
		printf("Successfully obtain policy\n");
	else {
		printf("A system error has occurred :: %d\n", nStatus);
		return;
	}
	
	printf("Enter the user name or group name ::\n");
	wscanf(L"%s", username);
	PSID AccountSid = getSid(username, advHandle, kernHandle);
	if (AccountSid == NULL) {
		printf("Error while delete user from group :: SID is NULL\n");
		return;
	}

	printf("Choose privilege to add :: \n");
	for (int i = 0; i != 41; i++) printf("%d - %ls\n", i + 1, privil[i]);

	do {
		scanf("%d", &mode);
		mode--;
		if (mode > 41)continue;
		if (mode == -1)break;
		
		UserRights.Buffer = privil[mode];
		UserRights.Length = wcslen(privil[mode]) * sizeof(wchar_t);
		UserRights.MaximumLength = (wcslen(privil[mode]) + 1) * sizeof(wchar_t);
		nStatus = _LsaAddAccountRights(lsahPolicyHandle,
			AccountSid,
			&UserRights,
			CountOfRights);
		if (nStatus == NERR_Success)
			printf("Successfully added shutdown right\n");
		else {
			printf("A system error has occurred :: %d\n", nStatus);
			return;
		}

	} while (mode);


	_LsaClose(lsahPolicyHandle);
}


void DelRights(HMODULE advHandle, HMODULE kernHandle, HMODULE netHandle)
{

	PROC_LsaOpenPolicy _LsaOpenPolicy = (PROC_LsaOpenPolicy)GetProcAddress(advHandle, "LsaOpenPolicy");
	PROC_LsaRemoveAccountRights _LsaRemoveAccountRights = (PROC_LsaRemoveAccountRights)GetProcAddress(advHandle, "LsaRemoveAccountRights");
	PROC_LsaClose _LsaClose = (PROC_LsaClose)GetProcAddress(advHandle, "LsaClose");
	NET_API_STATUS nStatus;
	ULONG CountOfRights = 1;
	LSA_HANDLE lsahPolicyHandle = NULL;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	LSA_UNICODE_STRING UserRights;
	wchar_t username[50] = { 0 };
	PWSTR buffer_privil[50];
	LOCALGROUP_USERS_INFO_0 puGroupBuf[50];
	int mode = 0, ret_mode = 0;
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
	nStatus = _LsaOpenPolicy(
		NULL,
		&ObjectAttributes,
		POLICY_ALL_ACCESS,
		&lsahPolicyHandle
	);
	if (nStatus == NERR_Success)
		printf("Successfully obtain policy\n");
	else {
		printf("A system error has occurred :: %d\n", nStatus);
		return;
	}
	printf("Enter the user name or group name ::\n");
	wscanf(L"%s", username);
	PSID AccountSid = getSid(username, advHandle, kernHandle);

	if (AccountSid == NULL) {
		printf("Error while delete user from group :: SID is NULL\n");
		return;
	} 


	printf("Choose privilege to add :: \n");

	do{
		ret_mode = getObjRights(lsahPolicyHandle, AccountSid, advHandle, buffer_privil);
		scanf("%d", &mode);
		if (mode <= 0 || mode > ret_mode) break;
		UserRights.Buffer = buffer_privil[mode-1];
		UserRights.Length = wcslen(buffer_privil[mode-1]) * sizeof(wchar_t);
		UserRights.MaximumLength = (wcslen(buffer_privil[mode-1]) + 1) * sizeof(wchar_t);
		nStatus = _LsaRemoveAccountRights(lsahPolicyHandle,
			AccountSid,
			FALSE,
			&UserRights,
			CountOfRights);
		if (nStatus == NERR_Success) {
			printf("Successfully deleted shutdown right\n");
			memset(buffer_privil, 0, sizeof(buffer_privil));
		}
		else {
			printf("A system error has occurred: %d\n", nStatus);
			return;
		}

	} while (mode > 0);

	_LsaClose(lsahPolicyHandle);
}



int main(void)
{
	setlocale(LC_ALL, "Russian");
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	HMODULE netHandle = LoadLibrary(("Netapi32.dll"));
	HMODULE advHandle = LoadLibrary(("Advapi32.dll"));
	HMODULE kernHandle = LoadLibrary(("Kernel32.dll"));
	int mode = 0;
AGN:
	printf("Select program mode ::\n");
	printf("0 :: Show all info\n");
	printf("1 :: Add user\n");
	printf("2 :: Del user\n");
	printf("3 :: Add group\n");
	printf("4 :: Del group\n");
	printf("5 :: Add user to group\n"); 
	printf("6 :: Del user from group\n");
	printf("7 :: Add privilege to user\n");
	printf("8 :: Delete privilege from user\n");

	scanf("%d",&mode);
	switch (mode) {
		case 0: outUsers(netHandle, advHandle, kernHandle); break;
		case 1: addUser(netHandle, advHandle, kernHandle); break;
		case 2: delUser(netHandle, advHandle, kernHandle); break;
		case 3: addGroup(netHandle, advHandle, kernHandle); break;
		case 4: delGroup(netHandle, advHandle, kernHandle); break;
		case 5: AddMembersInGroup(advHandle, kernHandle, netHandle); break;
		case 6: DelMembersInGroup(advHandle, kernHandle, netHandle); break;
		//case 7: AddLogonRights(advHandle, kernHandle, netHandle); break;
		//case 8: DelLogonRights(advHandle, kernHandle, netHandle); break;
		case 7: AddRights(advHandle, kernHandle, netHandle); break;
		case 8: DelRights(advHandle, kernHandle, netHandle); break;


	}
	printf("Would you like to exit :: 0 or 1\n");
	scanf("%d", &mode);
	printf("\n");
	if (mode == 1) {
		FreeLibrary(netHandle);
		FreeLibrary(advHandle);
		FreeLibrary(kernHandle);
		system("pause");
		return 0;
	}
	else {
		goto AGN;
	}

	return 0;
}
