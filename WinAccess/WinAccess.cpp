#include "LibHeader.h" 

// MBKS laboratory work - 6

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

// V - Owners
// V - file info
// V - dir info
// V - add attributes for user to ACL for file and directory
// V - Users add
// V - Users delete
// V - Groups add
// V - Groups delete
// V - Privilleges add
// V - Privilleges delete

int ShowObjRights(LSA_HANDLE lsahPolicyHandle, PSID AccountSid, HMODULE advHandle)
{
	PLSA_UNICODE_STRING lsau16sRights;
	ULONG ulRightsCount = 0;
	LSA_ENUMERATION_INFORMATION *lsaeInformation;
	PROC_LsaEnumerateAccountsWithUserRight _LsaEnumerateAccountsWithUserRight = (PROC_LsaEnumerateAccountsWithUserRight)GetProcAddress(advHandle, "LsaEnumerateAccountsWithUserRight");
	PROC_LsaEnumerateAccountRights _LsaEnumerateAccountRights = (PROC_LsaEnumerateAccountRights)GetProcAddress(advHandle, "LsaEnumerateAccountRights");

	if (
		_LsaEnumerateAccountsWithUserRight == NULL ||
		_LsaEnumerateAccountRights == NULL
		)
	{
		printf("Can't get fuction address with error:: %d\n", GetLastError());
		return 0;
	}
	
	_LsaEnumerateAccountsWithUserRight(lsahPolicyHandle,NULL, (void**)&lsaeInformation,&ulRightsCount);
	ulRightsCount = 0;
	NET_API_STATUS nStatus = _LsaEnumerateAccountRights(lsahPolicyHandle, AccountSid, &lsau16sRights, &ulRightsCount);
	if (!(nStatus == NERR_Success || nStatus == 0xC0000034)) {
		printf("A system error has occurred: %u\n", nStatus);
		return -1;
	}
	printf(("There are %u rights\n"), ulRightsCount);
	for (int i = 0; i < ulRightsCount; i++)
	{
		printf("%d - %S\n", i+1, lsau16sRights->Buffer);
		lsau16sRights++;
	}
	return 0;
}

int getObjRights(LSA_HANDLE lsahPolicyHandle, PSID AccountSid, HMODULE advHandle, PWSTR *buffer)
{
	PLSA_UNICODE_STRING lsau16sRights;
	ULONG rights_count;
	LSA_ENUMERATION_INFORMATION *buf;
	ULONG count = 0;
	PROC_LsaEnumerateAccountsWithUserRight _LsaEnumerateAccountsWithUserRight = (PROC_LsaEnumerateAccountsWithUserRight)GetProcAddress(advHandle, "LsaEnumerateAccountsWithUserRight");
	PROC_LsaEnumerateAccountRights _LsaEnumerateAccountRights = (PROC_LsaEnumerateAccountRights)GetProcAddress(advHandle, "LsaEnumerateAccountRights");

	if (
		_LsaEnumerateAccountsWithUserRight == NULL ||
		_LsaEnumerateAccountRights == NULL
		)
	{
		printf("Can't get fuction address with error:: %d\n", GetLastError());
		return 0;
	}

	_LsaEnumerateAccountsWithUserRight(lsahPolicyHandle, NULL, (void**)&buf, &count);

	NET_API_STATUS nStatus = _LsaEnumerateAccountRights(lsahPolicyHandle, AccountSid, &lsau16sRights, &rights_count);
	//printf("Code from lsaenum :: %d\n", nStatus);
	if (!(nStatus == NERR_Success || nStatus == 0xC0000034)) {
		printf("A system error has occurred: %u\n", nStatus);
		return -1;
	}
	printf(("There are %d rights"), rights_count);
	for (int i = 0; i < rights_count; i++)
	{
		buffer[i] = lsau16sRights->Buffer;
		printf("\n%d - %S", i + 1, lsau16sRights->Buffer);
		lsau16sRights++;
	}
	printf(("\n"), rights_count);

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

	if (
		_LookupAccountNameW == NULL ||
		_HeapAlloc == NULL ||
		_GetProcessHeap == NULL ||
		_HeapFree == NULL
		)
	{
		printf("Can't get fuction address with error:: %d\n", GetLastError());
		return (PSID)NULL;
	}

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
		return (PSID)NULL;
		
	}

	ret_val = _LookupAccountNameW(NULL, (LPCSTR)username, psid, &size, (LPTSTR)domain, &dom_size, &peUse);
	if (!ret_val) return PSID(-1);

	_HeapFree(_GetProcessHeap(),
		0,
		domain);

	return psid;
}


DWORD outGroup(LPCWSTR user_name, HMODULE netHandle, std::vector<_LOCALGROUP_USERS_INFO_0*> &locpuGroupBuf) {
	NET_API_STATUS gruRes;
	
	PROC_NetUserGetLocalGroups _NetUserGetLocalGroups = (PROC_NetUserGetLocalGroups)GetProcAddress(netHandle, "NetUserGetLocalGroups");
	
	if (
		_NetUserGetLocalGroups == NULL
		)
	{
		printf("Can't get fuction address with error:: %d\n", GetLastError());
		return 0;
	}

	DWORD guent;
	DWORD guentread;
	//_LOCALGROUP_USERS_INFO_0 *locpuGroupBuf = new LOCALGROUP_USERS_INFO_0[50];
	locpuGroupBuf.resize(50);
	gruRes = _NetUserGetLocalGroups(
		NULL,
		user_name,
		0,
		LG_INCLUDE_INDIRECT,
		(LPBYTE*)&locpuGroupBuf[0],
		MAX_PREFERRED_LENGTH,
		&guent,
		&guentread
	);
	return guentread;
}


void outUsers(HMODULE netHandle, HMODULE advHandle, HMODULE kernHandle) {
	DWORD entries;	
	DWORD entRead;
	LPUSER_INFO_1 pUserBuf;
	LPUSER_INFO_1 pTmpUserBuf;

	LPLOCALGROUP_INFO_0 pGroupBuf;
	LPLOCALGROUP_INFO_0 pTmpGroupBuf;

	std::vector<_LOCALGROUP_USERS_INFO_0*>puGroupBuf(50);
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

	if (
		_NetUserEnum == NULL ||
		_NetLocalGroupEnum == NULL ||
		_ConvertSidToStringSidA == NULL ||
		_LsaOpenPolicy == NULL ||
		_LsaClose == NULL			
		)
	{
		printf("Can't get fuction address with error:: %d\n", GetLastError());
		return;
	}

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
		do
		{
			// TODO: Set Parameter Values
			usrRes = _NetUserEnum(
				NULL,
				1, // this attribute to change structure fields 
				2,
				(LPBYTE*)&pUserBuf,
				MAX_PREFERRED_LENGTH,
				/*out*/&entRead,
				/*out*/&entries,
				/*out resumehandle*/ NULL
			);


			if ((usrRes == NERR_Success) || (usrRes == ERROR_MORE_DATA))
			{
				printf("\tList of users in system :: \n");
				if ((pTmpUserBuf = pUserBuf) != NULL)
				{
					for (int i = 0; i != entries; i++)
					{
						printf("User :: %S\n", pTmpUserBuf->usri1_name);

						usrRes = outGroup(pTmpUserBuf->usri1_name, netHandle, puGroupBuf);
						if (!usrRes) {
							printf("None;\n");
						}
						else {
							//printf("\n");
							for (int j = 0; j < usrRes; j++) {
								if (puGroupBuf[j] != NULL) {
									printf("%S; ", puGroupBuf[j]->lgrui0_name);
									Sid = getSid(puGroupBuf[j]->lgrui0_name, advHandle, kernHandle);
									_ConvertSidToStringSidA(Sid, &sid_str);
									printf(" || group SID :: %s\n", sid_str);
									ShowObjRights(lsahPolicyHandle, Sid, advHandle);
								}
							}

						}

						Sid = getSid(pTmpUserBuf->usri1_name, advHandle, kernHandle);
						_ConvertSidToStringSidA(Sid, &sid_str);
						printf("user SID :: %s\n", sid_str);
						ShowObjRights(lsahPolicyHandle, Sid, advHandle);
						printf("\n\n");
						pTmpUserBuf++;
					}
				}
			}
		} while (usrRes == ERROR_MORE_DATA);

		entRead = 0;
		entries = 0;

		do
		{
			grRes = _NetLocalGroupEnum(
				NULL,
				0,
				(LPBYTE*)&pGroupBuf,
				MAX_PREFERRED_LENGTH,
				/*out*/&entRead,
				/*out*/&entries,
				NULL
			);

			if ((grRes == NERR_Success) || (grRes == ERROR_MORE_DATA))
			{
				printf("\tList of groups in system :: \n");
				if ((pTmpGroupBuf = pGroupBuf) != NULL)
				{
					for (int i = 0; i != entries; i++)
					{
						Sid = getSid(pTmpGroupBuf->lgrpi0_name, advHandle, kernHandle);
						_ConvertSidToStringSidA(Sid, &sid_str);
						printf("group SID :: %s\t", sid_str);
						wprintf(L"%ls\n", pTmpGroupBuf->lgrpi0_name);
						pTmpGroupBuf++;
					}
				}
			}
		} while (grRes == ERROR_MORE_DATA);

	}

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

	if (_NetUserAdd == NULL)
	{
		printf("Can't get fuction address with error:: %d\n", GetLastError());
		return 0;
	}

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
	return err;
}

int delUser(HMODULE netHandle, HMODULE advHandle, HMODULE kernHandle) {
	// Source Code
	wchar_t lpszUser[50];
	if (netHandle != NULL)
	{
		PROC_NetUserDel _NetUserDel = (PROC_NetUserDel)GetProcAddress(netHandle, "NetUserDel");

		if (_NetUserDel == NULL)
		{
			printf("Can't get fuction address with error:: %d\n", GetLastError());
			return 0;
		}

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
	return 0;
}

int addGroup(HMODULE netHandle, HMODULE advHandle, HMODULE kernHandle) {
	DWORD	parm_err = 0;
	DWORD dwLevel = 0;
	wchar_t lpszGroup[50];
	_LOCALGROUP_INFO_0 l_group;
	PROC_NetLocalGroupAdd _NetLocalGroupAdd = (PROC_NetLocalGroupAdd)GetProcAddress(netHandle, "NetLocalGroupAdd");
		
	if (_NetLocalGroupAdd == NULL)
	{
		printf("Can't get fuction address with error:: %d\n", GetLastError());
		return 0;
	}
		
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
		
	return 0;
}

int delGroup(HMODULE netHandle, HMODULE advHandle, HMODULE kernHandle) {
	wchar_t lpszGroup[50];
	PROC_NetLocalGroupDel _NetLocalGroupDel = (PROC_NetLocalGroupDel)GetProcAddress(netHandle, "NetLocalGroupDel");
	if (_NetLocalGroupDel == NULL)
	{
		printf("Can't get fuction address with error:: %d\n", GetLastError());
		return 0;
	}

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

	return 0;
}


void AddMembersInGroup(HMODULE advHandle, HMODULE kernHandle, HMODULE netHandle)
{
	PROC_NetLocalGroupAddMembers _NetLocalGroupAddMembers = (PROC_NetLocalGroupAddMembers)GetProcAddress(netHandle, "NetLocalGroupAddMembers");
	PROC_LsaOpenPolicy _LsaOpenPolicy = (PROC_LsaOpenPolicy)GetProcAddress(advHandle, "LsaOpenPolicy");
	PROC_LsaClose _LsaClose = (PROC_LsaClose)GetProcAddress(advHandle, "LsaClose");

	if (_LsaOpenPolicy == NULL ||
		_NetLocalGroupAddMembers == NULL ||
		_LsaClose == NULL)
	{
		printf("Can't get fuction address with error:: %d\n", GetLastError());
		return;
	}

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

	if (_LsaOpenPolicy == NULL ||
		_NetLocalGroupDelMembers == NULL ||
		_LsaClose == NULL)
	{
		printf("Can't get fuction address with error:: %d\n", GetLastError());
		return;
	}

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
	
	if (_LsaOpenPolicy == NULL ||
		_LsaAddAccountRights == NULL ||
		_LsaClose == NULL)
	{
		printf("Can't get fuction address with error:: %d\n", GetLastError());
		return;
	}

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
		printf("Successfully added logon right\n");
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

	if (_LsaOpenPolicy == NULL ||
		_LsaRemoveAccountRights == NULL ||
		_LsaClose == NULL)
	{
		printf("Can't get fuction address with error:: %d\n", GetLastError());
		return;
	}

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

	if (_LsaOpenPolicy == NULL ||
		_LsaAddAccountRights == NULL ||
		_LsaClose == NULL)
	{
		printf("Can't get fuction address with error:: %d\n", GetLastError());
		return;
	}

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
	printf("-1 - Exit \n");
	for (int i = 0; i != 41; i++) printf("%d - %ls\n", i + 1, privil[i]);

	do {
		scanf("%d", &mode);
		getchar();
		if (mode < 0 || mode > 41) break;
		mode -= 1;
		UserRights.Buffer = privil[mode];
		UserRights.Length = wcslen(privil[mode]) * sizeof(wchar_t);
		UserRights.MaximumLength = (wcslen(privil[mode]) + 1) * sizeof(wchar_t);
		nStatus = _LsaAddAccountRights(lsahPolicyHandle,
			AccountSid,
			&UserRights,
			CountOfRights);
		if (nStatus == NERR_Success)
			printf("Successfully added %ls\n", privil[mode]);
		else {
			printf("A system error has occurred :: %d\n", nStatus);
		}

	} while (mode);


	_LsaClose(lsahPolicyHandle);
}

void DelRights(HMODULE advHandle, HMODULE kernHandle, HMODULE netHandle)
{
	PROC_LsaOpenPolicy _LsaOpenPolicy = (PROC_LsaOpenPolicy)GetProcAddress(advHandle, "LsaOpenPolicy");
	PROC_LsaRemoveAccountRights _LsaRemoveAccountRights = (PROC_LsaRemoveAccountRights)GetProcAddress(advHandle, "LsaRemoveAccountRights");
	PROC_LsaClose _LsaClose = (PROC_LsaClose)GetProcAddress(advHandle, "LsaClose");

	if (_LsaOpenPolicy == NULL ||
		_LsaRemoveAccountRights == NULL ||
		_LsaClose == NULL)
	{
		printf("Can't get fuction address with error:: %d\n", GetLastError());
		return;
	}

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
	printf("-1 :: Exit\n");

	do{
		ret_mode = getObjRights(lsahPolicyHandle, AccountSid, advHandle, buffer_privil);
		scanf("%d", &mode);
		if (mode <= 0 || mode > ret_mode) break;
		mode -= 1;
		UserRights.Buffer = buffer_privil[mode];
		UserRights.Length = wcslen(buffer_privil[mode]) * sizeof(wchar_t);
		UserRights.MaximumLength = (wcslen(buffer_privil[mode]) + 1) * sizeof(wchar_t);
		nStatus = _LsaRemoveAccountRights(lsahPolicyHandle,
			AccountSid,
			FALSE,
			&UserRights,
			CountOfRights);
		if (nStatus == NERR_Success) {
			printf("Successfully deleted %ls\n", buffer_privil[mode]);
			memset(buffer_privil, 0, sizeof(buffer_privil));
		}
		else 
		{
			printf("A system error has occurred: %d\n", nStatus);
		}

	} while (mode != -1);

	_LsaClose(lsahPolicyHandle);
}

void printFileProperties(wchar_t wcPath[])
{
	struct _stat64i32 stats;

	if (_wstat(wcPath, &stats) == -1)
	{
		return;
	}

	struct tm dt;

	printf("\nFile size: %d Bytes", stats.st_size);
	dt = *(gmtime(&stats.st_ctime));
	//dt = *(localtime(&stats.st_ctime));
	printf("\nCreated on: %02d-%02d-%d %02d:%02d:%02d", dt.tm_mday, dt.tm_mon + 1, dt.tm_year + 1900,
		dt.tm_hour, dt.tm_min, dt.tm_sec);
	dt = *(gmtime(&stats.st_mtime));
	//dt = *(localtime(&stats.st_mtime));
	printf("\nModified on: %02d-%02d-%d %02d:%02d:%02d", dt.tm_mday, dt.tm_mon + 1, dt.tm_year + 1900,
		dt.tm_hour, dt.tm_min, dt.tm_sec);
	dt = *(gmtime(&stats.st_atime));
	//dt = *(localtime(&stats.st_atime));
	printf("\nAccessed on: %02d-%02d-%d %02d:%02d:%02d", dt.tm_mday, dt.tm_mon + 1, dt.tm_year + 1900,
		dt.tm_hour, dt.tm_min, dt.tm_sec);
	printf("\n");

}

void printFileAttributes(wchar_t filepath[])
{
	long unsigned int FileAttributes;
	FileAttributes = GetFileAttributesW(filepath);
	printf("\nFile type:");
	if (FileAttributes & FILE_ATTRIBUTE_ARCHIVE)
	{
		printf("Archive\n");
	}
	if (FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		printf("Directory\n");
	}
	if (FileAttributes & FILE_ATTRIBUTE_READONLY)
	{
		printf("Read-Only\n");
	}
	if (FileAttributes & FILE_ATTRIBUTE_HIDDEN)
	{
		printf("Hidden\n");
	}
}

void printGroupProperties(HMODULE advHandle, wchar_t wcPath[])
{
	DWORD dwRtnCode = 0;
	PSECURITY_DESCRIPTOR psd = NULL;
	PACL pdacl;
	ACL_SIZE_INFORMATION aclSize = { 0 };
	PSID sidowner = NULL;
	PSID sidgroup = NULL;
	std::wstring wsName;
	std::wstring wsDomain;

	DWORD dwNameLen = 0;
	DWORD dwDomainNameLen = 0;
	SID_NAME_USE peUse;
	ACCESS_ALLOWED_ACE* ace;

	PROC_GetNamedSecurityInfoW _GetNamedSecurityInfoW = (PROC_GetNamedSecurityInfoW)GetProcAddress(advHandle, "GetNamedSecurityInfoW");

	if (_GetNamedSecurityInfoW == NULL)
	{
		printf("Can't get fuction address with error:: %d\n", GetLastError());
		return;
	}

	dwRtnCode = _GetNamedSecurityInfoW(wcPath
		, SE_FILE_OBJECT
		, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
		, &sidowner
		, &sidgroup
		, &pdacl
		, NULL
		, &psd);


	if (pdacl == NULL)
	{
		printf("Can't get object dacl with error: %x\n", GetLastError());
		return;
	}

	printFileAttributes(wcPath);

	LookupAccountSidW(NULL, sidowner, NULL, (LPDWORD)&dwNameLen, NULL, (LPDWORD)&dwDomainNameLen, &peUse);

	wsName.resize(dwNameLen);
	wsDomain.resize(dwDomainNameLen);

	LookupAccountSidW(NULL, sidowner, wsName.data(), (LPDWORD)&dwNameLen, wsDomain.data(), (LPDWORD)&dwDomainNameLen, &peUse);
	std::wcout << "Owner: " << wsDomain << "/" << wsName << std::endl;
	std::wcout << "::ACCESS CONTROL LIST::";
	SID* sid;

	for (int i = 0; i < (*pdacl).AceCount; i++) {
		int c = 1;
		dwNameLen = 0;
		dwDomainNameLen = 0;
		BOOL b = GetAce(pdacl, i, (PVOID*)&ace);

		if (((ACCESS_ALLOWED_ACE*)ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE) {
			sid = (SID*)&((ACCESS_ALLOWED_ACE*)ace)->SidStart;
			LookupAccountSidW(NULL, sid, NULL, (LPDWORD)&dwNameLen, NULL, (LPDWORD)&dwDomainNameLen, &peUse);
			
			wsName.clear();
			wsDomain.clear();
			wsName.resize(dwNameLen);
			wsDomain.resize(dwDomainNameLen);

			LookupAccountSidW(NULL, sid, wsName.data(), (LPDWORD)&dwNameLen, wsDomain.data(), (LPDWORD)&dwDomainNameLen, &peUse);
			std::wcout << "\nUser Group " << i + 1 << ":" << wsDomain << "/" << wsName;
		}
		else if (((ACCESS_DENIED_ACE*)ace)->Header.AceType == ACCESS_DENIED_ACE_TYPE) {
			sid = (SID*)&((ACCESS_DENIED_ACE*)ace)->SidStart;
			LookupAccountSidW(NULL, sid, NULL, (LPDWORD)&dwNameLen, NULL, (LPDWORD)&dwDomainNameLen, &peUse);
			
			wsName.clear();
			wsDomain.clear();
			wsName.resize(dwNameLen);
			wsDomain.resize(dwDomainNameLen);

			LookupAccountSidW(NULL, sid, wsName.data(), (LPDWORD)&dwNameLen, wsDomain.data(), (LPDWORD)&dwDomainNameLen, &peUse);
			std::wcout << "\nUser Group " << i + 1 << ":" << wsDomain << "/" << wsName;
		}
		else
		{
			printf("Other ACE\n");
		}

		std::cout << "\nPERMISSIONS:\n";

		if (DELETE & ace->Mask) {
			std::wcout << " Delete" << "\n";
		}
		if (FILE_READ_ATTRIBUTES & ace->Mask) {
			std::wcout << " File Read Attribute" << "\n";
		}
		if (FILE_WRITE_ATTRIBUTES & ace->Mask) {
			std::wcout << " File Write Attribute" << "\n";
		}
		if (FILE_EXECUTE & ace->Mask) {
			std::wcout << " File Execute Attribute" << "\n";
		}
		if (GENERIC_READ & ace->Mask) {
			std::wcout << " Generic Read" << "\n";
		}
		if (GENERIC_WRITE & ace->Mask) {
			std::wcout << " Generic Write" << "\n";
		}
		if (GENERIC_EXECUTE & ace->Mask) {
			std::wcout << " Generic Execute" << "\n";
		}
		if (GENERIC_ALL & ace->Mask) {
			std::wcout << " Generic All" << "\n";
		}
		if (READ_CONTROL & ace->Mask) {
			std::wcout << " Read Control" << "\n";
		}
		if (WRITE_DAC & ace->Mask) {
			std::wcout << " Write DAC" << "\n";
		}
		if (WRITE_OWNER & ace->Mask) {
			std::wcout << " Write Owner" << "\n";
		}
		if (SYNCHRONIZE & ace->Mask) {
			std::wcout << " Synchronize" << "\n";
		}
		std::wcout << "\n";
	}
}

// Get file or folder information
void GetObjectInfo(HMODULE advHandle)
{
	wchar_t wcPath[MAX_PATH] = { 0 };

	printf("Input full file path:: ");
	fgetws(wcPath, MAX_PATH, stdin);
	wcPath[wcscspn(wcPath, L"\n")] = 0;

	printGroupProperties(advHandle, wcPath);
	printFileProperties(wcPath);
	return;
}

DWORD AddAceToObjectsSecurityDescriptor(
	HMODULE advHandle,
	HMODULE kernHandle,
	LPWSTR pszObjName,          // name of object
	SE_OBJECT_TYPE ObjectType,  // type of object
	LPWSTR pszTrustee,          // trustee for new ACE
	TRUSTEE_FORM TrusteeForm,   // format of trustee structure
	DWORD dwAccessRights,       // access mask for new ACE
	ACCESS_MODE AccessMode,     // type of ACE
	DWORD dwInheritance         // inheritance flags for new ACE
)
{
	DWORD dwRes = 0;
	PACL pOldDACL = NULL, pNewDACL = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	EXPLICIT_ACCESS_W ea;

	if (NULL == pszObjName)
	{
		return ERROR_INVALID_PARAMETER;
	}

	PROC_GetNamedSecurityInfoW _GetNamedSecurityInfoW = (PROC_GetNamedSecurityInfoW)GetProcAddress(advHandle, "GetNamedSecurityInfoW");
	PROC_SetEntriesInAclW _SetEntriesInAclW = (PROC_SetEntriesInAclW)GetProcAddress(advHandle, "SetEntriesInAclW");
	PROC_SetNamedSecurityInfoW _SetNamedSecurityInfoW = (PROC_SetNamedSecurityInfoW)GetProcAddress(advHandle, "SetNamedSecurityInfoW");
	
	if (_GetNamedSecurityInfoW == NULL ||
		_SetEntriesInAclW == NULL ||
		_SetNamedSecurityInfoW == NULL)
	{
		printf("Can't get fuction address with error:: %d\n", GetLastError());
		return -1;
	}

	// Get a pointer to the existing DACL.

	dwRes = _GetNamedSecurityInfoW(pszObjName, ObjectType,
		DACL_SECURITY_INFORMATION,
		NULL, NULL, &pOldDACL, NULL, &pSD);

	if (ERROR_SUCCESS != dwRes) {
		printf("GetNamedSecurityInfo Error %u\n", dwRes);
		goto Cleanup;
	}

	SID* sid;
	ACCESS_ALLOWED_ACE* ace;

	bool bFind = false;
	for (int i = 0; i < (*pOldDACL).AceCount; i++) 
	{
		int c = 1;
		BOOL b = GetAce(pOldDACL, i, (PVOID*)&ace);

		if (((ACCESS_ALLOWED_ACE*)ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE) {
			sid = (SID*)&((ACCESS_ALLOWED_ACE*)ace)->SidStart;
			PSID pSid = getSid(pszTrustee, advHandle, kernHandle);

			if (pSid == NULL)
			{
				printf("getSid Error psid is NULL\n");
				goto Cleanup;
			}

			if (pSid != sid)
			{
				continue;
			}
			else
			{
				bFind = true;
				if (AccessMode == REVOKE_ACCESS)
				{
					if (((ACCESS_ALLOWED_ACE*)ace)->Mask & dwAccessRights)
					{
						dwAccessRights ^= ((ACCESS_ALLOWED_ACE*)ace)->Mask;
					}
					else
					{
						dwRes = -1;
						goto Cleanup;
					}
				}
				else
				{
					dwAccessRights |= ((ACCESS_ALLOWED_ACE*)ace)->Mask;
				}

				AccessMode = SET_ACCESS;
				break;
			}
		}
		else if (((ACCESS_DENIED_ACE*)ace)->Header.AceType == ACCESS_DENIED_ACE_TYPE) {
			sid = (SID*)&((ACCESS_DENIED_ACE*)ace)->SidStart;
			PSID pSid = getSid(pszTrustee, advHandle, kernHandle);

			if (pSid == NULL)
			{
				printf("getSid Error psid is NULL\n");
				dwRes = -1;
				goto Cleanup;
			}

			if (pSid != sid)
			{
				continue;
			}
			else
			{
				bFind = true;

				if (AccessMode == REVOKE_ACCESS)
				{
					if (((ACCESS_DENIED_ACE*)ace)->Mask & dwAccessRights)
					{
						dwAccessRights ^= ((ACCESS_DENIED_ACE*)ace)->Mask;
					}
					else
					{
						dwRes = -1;
						goto Cleanup;
					}
				}
				else
				{
					dwAccessRights |= ((ACCESS_DENIED_ACE*)ace)->Mask;
				}

				AccessMode = SET_ACCESS;
				break;
			}
		}
		else
		{
			return -1;
		}
	}

	if (bFind == false && AccessMode == REVOKE_ACCESS)
	{
		printf("Can't revoke permission for unexist user\n");
		dwRes = -1;
		goto Cleanup;
	}

	long unsigned int FileAttributes;
	FileAttributes = GetFileAttributesW(pszObjName);

	if (FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		dwInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	}

	// Initialize an EXPLICIT_ACCESS structure for the new ACE. 

	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS_W));
	ea.grfAccessPermissions = dwAccessRights;
	ea.grfAccessMode = AccessMode;
	ea.grfInheritance = dwInheritance;
	ea.Trustee.TrusteeForm = TrusteeForm;
	ea.Trustee.ptstrName = pszTrustee;

	// Create a new ACL that merges the new ACE
	// into the existing DACL.

	dwRes = _SetEntriesInAclW(1, &ea, pOldDACL, &pNewDACL);
	if (ERROR_SUCCESS != dwRes) {
		printf("SetEntriesInAcl Error %u\n", dwRes);
		goto Cleanup;
	}

	// Attach the new ACL as the object's DACL.
	dwRes = _SetNamedSecurityInfoW(pszObjName, ObjectType,
		DACL_SECURITY_INFORMATION,
		NULL, NULL, pNewDACL, NULL);
	if (ERROR_SUCCESS != dwRes) {
		printf("SetNamedSecurityInfo Error %u\n", dwRes);
		goto Cleanup;
	}

Cleanup:

	if (pSD != NULL)
		LocalFree((HLOCAL)pSD);
	if (pNewDACL != NULL)
		LocalFree((HLOCAL)pNewDACL);

	return dwRes;
}

DWORD GetAccessMask()
{
	int dMode = 0;

	printf("Enter numbers of the access to edit (allow multimode):\n");
	printf("1 :: To read, write, and execute the object (generic all)\n");
	printf("2 :: To modify the control (security) information\n");
	printf("3 :: To modify the owner SID of the object\n");
	printf("4 :: To delete file\n");
	printf("5 :: To read the information maintained by the object\n");
	printf("6 :: To write the information maintained by the object\n");
	printf("7 :: To execute or alternatively look into the object\n");
	printf("Input :: ");
	scanf("%d", &dMode);
	getchar();

	DWORD mask = 0;
	while (dMode > 0)
	{
		char cLocalMode = dMode % 10;
		dMode /= 10;
		switch (cLocalMode)
			{
			case 1: mask |= GENERIC_ALL; break;
			case 2: mask |= WRITE_DAC; break;
			case 3: mask |= WRITE_OWNER; break;
			case 4: mask |= DELETE; break;
			case 5: mask |= FILE_GENERIC_READ; break;
			case 6: mask |= FILE_GENERIC_WRITE; break;
			case 7: mask |= FILE_GENERIC_EXECUTE; break;
			default: break;
		}
	}
	return mask;
}

int GetAccessMode()
{
	ACCESS_MODE accessMode = (ACCESS_MODE)0;
	int dMode = 0;

	printf("Enter access mode\n");
	printf("1 :: Setting access\n");
	printf("2 :: Denying access\n");
	printf("3 :: Remove access\n");
	printf("Input :: ");
	scanf("%d", &dMode);
	getchar();

	if (dMode == 1)
	{
		return GRANT_ACCESS;
	}
	if (dMode == 2)
	{
		return DENY_ACCESS;
	}
	if (dMode == 3)
	{
		return REVOKE_ACCESS;
	}
	return -1;
}


void AddPermissionsToObject(HMODULE advHandle, HMODULE kernHandle)
{
	wchar_t wcPath[MAX_PATH] = { 0 };
	wchar_t wcName[MAX_PATH] = { 0 };
	int dMode = -1;

	printf("Input full file path:: ");
	fgetws(wcPath, MAX_PATH, stdin);
	wcPath[wcscspn(wcPath, L"\n")] = 0;

	printf("Input group or user name :: ");
	fgetws(wcName, MAX_PATH, stdin);
	wcName[wcscspn(wcName, L"\n")] = 0;

	int dAccessMode = GetAccessMode();

	if (dAccessMode == -1)
	{
		printf("Can't retrieve access mode\n");
		return;
	}

	DWORD dwAccessMask = GetAccessMask();

	dwAccessMask = AddAceToObjectsSecurityDescriptor(
		advHandle,
		kernHandle,
		wcPath, SE_FILE_OBJECT,
		wcName, TRUSTEE_IS_NAME,
		dwAccessMask, (ACCESS_MODE)dAccessMode,
		NO_INHERITANCE
	);

	if (dwAccessMask == 0)
	{
		printf("Permissions is successfully added\n");
	}
	else
	{
		printf("Problem with added\n");
	}
}


int main(void)
{
	setlocale(LC_ALL, "Russian");
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	HMODULE netHandle = LoadLibrary("Netapi32.dll");
	HMODULE advHandle = LoadLibrary("Advapi32.dll");
	HMODULE kernHandle = LoadLibrary("Kernel32.dll");
	if (netHandle == NULL ||
		advHandle == NULL ||
		kernHandle == NULL)
	{
		printf("Some problems while loading dll libraries: 0x%x", GetLastError());
		return -1;
	}

	int dMode = 0;

	do
	{
		printf("Select program mode ::\n");
		printf("-1	:: Exit\n");
		printf("0	:: Show all info\n");
		printf("1	:: Add user\n");
		printf("2	:: Del user\n");
		printf("3	:: Add group\n");
		printf("4	:: Del group\n");
		printf("5	:: Add user to group\n");
		printf("6	:: Del user from group\n");
		printf("7	:: Add privilege to user or group\n");
		printf("8	:: Delete privilege from user or group\n");
		printf("9	:: Get object info\n");
		printf("10	:: Add permissions to object\n");

		scanf("%d", &dMode);
		getchar();
		switch (dMode) 
		{
			case 0: outUsers(netHandle, advHandle, kernHandle); break;
			case 1: addUser(netHandle, advHandle, kernHandle); break;
			case 2: delUser(netHandle, advHandle, kernHandle); break;
			case 3: addGroup(netHandle, advHandle, kernHandle); break;
			case 4: delGroup(netHandle, advHandle, kernHandle); break;
			case 5: AddMembersInGroup(advHandle, kernHandle, netHandle); break;
			case 6: DelMembersInGroup(advHandle, kernHandle, netHandle); break;
			case 7: AddRights(advHandle, kernHandle, netHandle); break;
			case 8: DelRights(advHandle, kernHandle, netHandle); break;
			case 9: GetObjectInfo(advHandle); break;
			case 10: AddPermissionsToObject(advHandle, kernHandle); break;
		}
	}while (dMode != -1);

	if (netHandle != NULL)
	{
		FreeLibrary(netHandle);
	}

	if (advHandle != NULL)
	{

		FreeLibrary(advHandle);
	}

	if (kernHandle != NULL)
	{
		FreeLibrary(kernHandle);
	}
	system("pause");

	return 0;
}
