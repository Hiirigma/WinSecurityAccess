#include <stdio.h>
#include <Windows.h>
#include <locale.h>
// For outUsers and netusersenum
#define NET_API_STATUS DWORD
#define NERR_Success 0
#define LG_INCLUDE_INDIRECT 1
#define MAX_PREFERRED_LENGTH -1
// API Prototype for Netapi32.dll!NetUserEnum
typedef NET_API_STATUS(__stdcall *PROC_NetUserEnum)(
	LPCWSTR servername,
	DWORD level,
	DWORD filter,
	LPBYTE* bufptr,
	DWORD prefmaxlen,
	LPDWORD entriesread,
	LPDWORD totalentries,
	LPDWORD resume_handle
	);


// API Prototype for Netapi32.dll!NetLocalGroupEnum
typedef NET_API_STATUS(__stdcall *PROC_NetLocalGroupEnum)(
	LPCWSTR servername,
	DWORD level,
	LPBYTE* bufptr,
	DWORD prefmaxlen,
	LPDWORD entriesread,
	LPDWORD totalentries,
	PDWORD_PTR resumehandle
	);

// API Prototype for Netapi32.dll!NetUserGetLocalGroups
typedef NET_API_STATUS(__stdcall *PROC_NetUserGetLocalGroups)(
	LPCWSTR servername,
	LPCWSTR username,
	DWORD level,
	DWORD flags,
	LPBYTE* bufptr,
	DWORD prefmaxlen,
	LPDWORD entriesread,
	LPDWORD totalentries
	);

// API Prototype for Advapi32.dll!LookupAccountNameW
typedef BOOL(__stdcall *PROC_LookupAccountNameW)(
	LPCTSTR lpSystemName,
	LPCTSTR lpAccountName,
	PSID Sid,
	LPDWORD cbSid,
	LPTSTR ReferencedDomainName,
	LPDWORD cchReferencedDomainName,
	PSID_NAME_USE peUse
	);


// API Prototype for Advapi32.dll!ConvertSidToStringSidA
typedef BOOL(__stdcall *PROC_ConvertSidToStringSidA)(
	PSID Sid,
	LPTSTR* StringSid
	);

// API Prototype for Kernel32.dll!HeapAlloc
typedef LPVOID(__stdcall *PROC_HeapAlloc)(
	HANDLE hHeap,
	DWORD dwFlags,
	SIZE_T dwBytes
	);

// API Prototype for Kernel32.dll!HeapFree
typedef BOOL(__stdcall *PROC_HeapFree)(
	HANDLE hHeap,
	DWORD dwFlags,
	LPVOID lpMem
	);

// API Prototype for Kernel32.dll!GetProcessHeap
typedef HANDLE(__stdcall *PROC_GetProcessHeap)(
	);


typedef struct _USER_INFO_1 {
	LPWSTR   usri1_name;
	LPWSTR   usri1_password;
	DWORD    usri1_password_age;
	DWORD    usri1_priv;
	LPWSTR   usri1_home_dir;
	LPWSTR   usri1_comment;
	DWORD    usri1_flags;
	LPWSTR   usri1_script_path;
}USER_INFO_1, *PUSER_INFO_1, *LPUSER_INFO_1;

typedef struct _GROUP_USERS_INFO_1 {
	LPWSTR  grui1_name;
	DWORD   grui1_attributes;
} GROUP_USERS_INFO_1, *PGROUP_USERS_INFO_1, *LPGROUP_USERS_INFO_1;


typedef struct _LOCALGROUP_USERS_INFO_0 {
	LPWSTR lgrui0_name;
} LOCALGROUP_USERS_INFO_0, *PLOCALGROUP_USERS_INFO_0, *LPLOCALGROUP_USERS_INFO_0;


typedef struct _LOCALGROUP_INFO_0 {
	LPWSTR   lgrpi0_name;
}LOCALGROUP_INFO_0, *PLOCALGROUP_INFO_0, *LPLOCALGROUP_INFO_0;