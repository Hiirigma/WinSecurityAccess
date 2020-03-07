#include <stdio.h>
#include <Windows.h>
#include <locale.h>
// For outUsers and netusersenum
#define NET_API_STATUS DWORD
#define NERR_Success 0

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

// API Prototype for Netapi32.dll!NetUserGetGroups
typedef NET_API_STATUS(__stdcall *PROC_NetUserGetGroups)(
	LPCWSTR servername,
	LPCWSTR username,
	DWORD level,
	LPBYTE* bufptr,
	DWORD prefmaxlen,
	LPDWORD entriesread,
	LPDWORD totalentries
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


typedef struct _LOCALGROUP_INFO_0 {
	LPWSTR   lgrpi0_name;
}LOCALGROUP_INFO_0, *PLOCALGROUP_INFO_0, *LPLOCALGROUP_INFO_0;

