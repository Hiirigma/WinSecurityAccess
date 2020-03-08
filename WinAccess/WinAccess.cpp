// BSIT laboratory work - 1

//		The criteria ::
// - Dynamic loaded library (Windows functions) 
// - Without functions from WinApi
// - Win 7 \\ Win 10

//		What to do ::

//		View Registåred ::
// V - Users	
// V - Groups
// - SID 
// - Privilleges
//		Must change ::
// - Users
// - Groups
// - Privilleges

#include "LibHeader.h"

int getSid(LPWSTR username, HMODULE advHandle, HMODULE kernHandle) {
	LPTSTR sid_str;
	LPWSTR domain = NULL;
	DWORD size = 0, dom_size = 0;
	SID_NAME_USE peUse;
	PSID  psid = NULL;
	UINT ret_val = ERROR_FUNCTION_FAILED;

	PROC_ConvertSidToStringSidA _ConvertSidToStringSidA = (PROC_ConvertSidToStringSidA)GetProcAddress(advHandle, "ConvertSidToStringSidA");
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
		return (ERROR_OUTOFMEMORY);
		
	}

	ret_val = _LookupAccountNameW(NULL, (LPCSTR)username, psid, &size, (LPTSTR)domain, &dom_size, &peUse);
	if (!ret_val) return ret_val;

	ret_val = _ConvertSidToStringSidA(psid, &sid_str);
	if (!ret_val) return ret_val;

	printf("SID :: %s\n", sid_str);

	_HeapFree(_GetProcessHeap(),
		0,
		psid);

	_HeapFree(_GetProcessHeap(),
		0,
		domain);

	return 0;
}


void outUsers() {
	// API Prototype for Netapi32.dll!NetUserEnum
	HMODULE netHandle = LoadLibrary(("Netapi32.dll"));
	HMODULE advHandle = LoadLibrary(("Advapi32.dll"));
	HMODULE kernHandle = LoadLibrary(("Kernel32.dll"));

	if (netHandle == NULL || advHandle == NULL || kernHandle == NULL) {
		printf("Error in loading library\n");
		exit(-1);
	}

	NET_API_STATUS status;
	DWORD entries;
	DWORD guent;
	DWORD entRead;
	DWORD guentread;
	_USER_INFO_1 * pUserBuf = new USER_INFO_1[20];
	_LOCALGROUP_INFO_0  * pGroupBuf = new _LOCALGROUP_INFO_0[255];
	_LOCALGROUP_USERS_INFO_0 * puGroupBuf = new LOCALGROUP_USERS_INFO_0[50];
	PSID Sid;
	NET_API_STATUS usrRes;
	NET_API_STATUS grRes;
	NET_API_STATUS gruRes;

	if (netHandle != NULL)
	{
		PROC_NetUserEnum _NetUserEnum = (PROC_NetUserEnum)GetProcAddress(netHandle, "NetUserEnum");
		PROC_NetLocalGroupEnum _NetLocalGroupEnum = (PROC_NetLocalGroupEnum)GetProcAddress(netHandle, "NetLocalGroupEnum");
		PROC_NetUserGetLocalGroups _NetUserGetLocalGroups = (PROC_NetUserGetLocalGroups)GetProcAddress(netHandle, "NetUserGetLocalGroups");

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



					printf("%S\n", pUserBuf[i].usri1_name);
					if (guentread == 0)
						printf("None;");
					for (int j = 0; j < guentread; j++) {
						if (puGroupBuf[j].lgrui0_name != NULL)
							printf("%S; ", puGroupBuf[j].lgrui0_name);
					}

					printf("\n");
					usrRes = getSid(pUserBuf[i].usri1_name, advHandle,kernHandle);
					if (usrRes)
						printf("Get sid error with code :: %d", usrRes);
					printf("\n");
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
