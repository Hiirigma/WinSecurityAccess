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

void outUsers(HMODULE hModule) {
	// API Prototype for Netapi32.dll!NetUserEnum
	NET_API_STATUS status;
	DWORD entries;
	DWORD guent;
	DWORD entRead;
	DWORD guentread;

	DWORD uPrefLen = 20;
	DWORD ugPrefLen = 20;
	DWORD guPrefLen = 50;
	_USER_INFO_1 * pUserBuf = new USER_INFO_1[20];
	_LOCALGROUP_INFO_0 * pGroupBuf = new LOCALGROUP_INFO_0[255];
	_GROUP_USERS_INFO_1 * puGroupBuf = new GROUP_USERS_INFO_1[50];

	NET_API_STATUS usrRes;
	NET_API_STATUS grRes;
	NET_API_STATUS gruRes;

	if (hModule != NULL)
	{
		PROC_NetUserEnum _NetUserEnum = (PROC_NetUserEnum)GetProcAddress(hModule, "NetUserEnum");
		PROC_NetLocalGroupEnum _NetLocalGroupEnum = (PROC_NetLocalGroupEnum)GetProcAddress(hModule, "NetLocalGroupEnum");
		PROC_NetUserGetGroups _NetUserGetGroups = (PROC_NetUserGetGroups)GetProcAddress(hModule, "NetUserGetGroups");


		if (_NetUserEnum != NULL && _NetLocalGroupEnum != NULL)
		{
			// TODO: Set Parameter Values
			usrRes = _NetUserEnum(
				NULL,
				1, // this attribute to change structure fields 
				0,
				(LPBYTE*)&pUserBuf,
				uPrefLen,
				/*out*/&entRead,
				/*out*/&entries,
				/*out resumehandle*/ NULL
			);

			
			if (usrRes == NERR_Success)
			{
				printf("\tList of users in system :: \n");
				for (int i = 0;i!=entries; i++) {
					if (pUserBuf[i].usri1_name == NULL) break;
					gruRes = _NetUserGetGroups(
						NULL,
						pUserBuf[i].usri1_name,
						1,
						(LPBYTE*)&puGroupBuf,
						guPrefLen,
						&guent,
						&guentread
					);
					printf("%S\n", pUserBuf[i].usri1_name);
					for (int j = 0; j < guentread; j++) {
						printf("%S; ", puGroupBuf[j].grui1_name);
					}
					printf("\n\n");
				}
			}
			delete[] pUserBuf;

			entRead = 0;
			entries = 0;
			grRes = _NetLocalGroupEnum(
				NULL,
				0,
				(LPBYTE*)&pGroupBuf,
				-1,
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

}




int main(void)
{
	setlocale(LC_ALL, "Russian");
	HMODULE hModule = LoadLibrary(("Netapi32.dll"));
	if (hModule == NULL) {
		printf("Error in loading library\n");
		exit(-1);
	}

	outUsers(hModule);
	FreeLibrary(hModule);
	system("pause");
    return 0;
}

