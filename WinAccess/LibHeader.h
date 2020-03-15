#include <stdio.h>
#include <Windows.h>
#include <locale.h>
// For outUsers and netusersenum
#define NET_API_STATUS DWORD
#define NERR_Success 0
#define LG_INCLUDE_INDIRECT 1
#define MAX_PREFERRED_LENGTH -1
// API Prototype for Netapi32.dll!NetUserEnum

#define POLICY_VIEW_LOCAL_INFORMATION 0x00000001
#define POLICY_VIEW_AUDIT_INFORMATION 0x00000002
#define POLICY_GET_PRIVATE_INFORMATION  0x00000004
#define POLICY_TRUST_ADMIN 0x00000008
#define POLICY_CREATE_ACCOUNT 0x00000010
#define POLICY_CREATE_SECRET 0x00000020
#define POLICY_CREATE_PRIVILEGE 0x00000040
#define POLICY_SET_DEFAULT_QUOTA_LIMITS 0x00000080
#define POLICY_SET_AUDIT_REQUIREMENTS 0x00000100
#define POLICY_AUDIT_LOG_ADMIN 0x00000200
#define POLICY_SERVER_ADMIN 0x00000400
#define POLICY_LOOKUP_NAMES 0x00000800
#define POLICY_NOTIFICATION 0x00001000
#define POLICY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|4095)
#define USER_PRIV_GUEST 0
#define USER_PRIV_USER 1
#define USER_PRIV_ADMIN 2

#define UF_SCRIPT 1
#define UF_ACCOUNTDISABLE 2
#define UF_HOMEDIR_REQUIRED 8
#define UF_LOCK 16
#define UF_PASSWD_NOTREQD 32
#define UF_PASSWD_CANT_CHANGE 64
#define UF_TEMP_DUPLICATE_ACCOUNT 256
#define UF_NORMAL_ACCOUNT 512
#define UF_INTERDOMAIN_TRUST_ACCOUNT 2048
#define UF_WORKSTATION_TRUST_ACCOUNT 4096
#define UF_SERVER_TRUST_ACCOUNT 8192
#define UF_MACHINE_ACCOUNT_MASK (UF_INTERDOMAIN_TRUST_ACCOUNT|UF_WORKSTATION_TRUST_ACCOUNT|UF_SERVER_TRUST_ACCOUNT)
#define UF_ACCOUNT_TYPE_MASK (UF_TEMP_DUPLICATE_ACCOUNT|UF_NORMAL_ACCOUNT|UF_INTERDOMAIN_TRUST_ACCOUNT|UF_WORKSTATION_TRUST_ACCOUNT|UF_SERVER_TRUST_ACCOUNT)
#define UF_DONT_EXPIRE_PASSWD 65536
#define UF_SETTABLE_BITS (UF_SCRIPT|UF_ACCOUNTDISABLE|UF_LOCK|UF_HOMEDIR_REQUIRED|UF_PASSWD_NOTREQD|UF_PASSWD_CANT_CHANGE|UF_ACCOUNT_TYPE_MASK|UF_DONT_EXPIRE_PASSWD)

typedef PVOID LSA_HANDLE, *PLSA_HANDLE;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;

typedef struct _LSA_OBJECT_ATTRIBUTES {
	ULONG               Length;
	HANDLE              RootDirectory;
	PLSA_UNICODE_STRING ObjectName;
	ULONG               Attributes;
	PVOID               SecurityDescriptor;
	PVOID               SecurityQualityOfService;
} LSA_OBJECT_ATTRIBUTES, *PLSA_OBJECT_ATTRIBUTES;

typedef enum _SE_OBJECT_TYPE {
	SE_UNKNOWN_OBJECT_TYPE,
	SE_FILE_OBJECT,
	SE_SERVICE,
	SE_PRINTER,
	SE_REGISTRY_KEY,
	SE_LMSHARE,
	SE_KERNEL_OBJECT,
	SE_WINDOW_OBJECT,
	SE_DS_OBJECT,
	SE_DS_OBJECT_ALL,
	SE_PROVIDER_DEFINED_OBJECT,
	SE_WMIGUID_OBJECT,
	SE_REGISTRY_WOW64_32KEY,
	SE_REGISTRY_WOW64_64KEY
} SE_OBJECT_TYPE;


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


typedef struct _LSA_TRUST_INFORMATION {
	LSA_UNICODE_STRING Name;
	PSID               Sid;
} LSA_TRUST_INFORMATION, *PLSA_TRUST_INFORMATION;


typedef struct _LSA_TRANSLATED_SID2 {
	SID_NAME_USE Use;
	PSID         Sid;
	LONG         DomainIndex;
	ULONG        Flags;
} LSA_TRANSLATED_SID2, *PLSA_TRANSLATED_SID2;

typedef struct _LSA_REFERENCED_DOMAIN_LIST {
	ULONG                  Entries;
	PLSA_TRUST_INFORMATION Domains;
} LSA_REFERENCED_DOMAIN_LIST, *PLSA_REFERENCED_DOMAIN_LIST;

typedef struct _LSA_ENUMERATION_INFORMATION {
	PSID Sid;
} LSA_ENUMERATION_INFORMATION, *PLSA_ENUMERATION_INFORMATION;

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

// API Prototype for Advapi32.dll!LsaEnumerateAccountRights
typedef NTSTATUS(__stdcall *PROC_LsaEnumerateAccountRights)(
	LSA_HANDLE PolicyHandle,
	PSID AccountSid,
	PLSA_UNICODE_STRING* UserRights,
	PULONG CountOfRights
	);


// API Prototype for Advapi32.dll!LsaOpenPolicy
typedef NTSTATUS(__stdcall *PROC_LsaOpenPolicy)(
	PLSA_UNICODE_STRING SystemName,
	PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
	ACCESS_MASK DesiredAccess,
	PLSA_HANDLE PolicyHandle
	);


// API Prototype for Kernel32.dll!GetProcessHeap
typedef HANDLE(__stdcall *PROC_GetProcessHeap)(
	);
// API Prototype for Advapi32.dll!LookupPrivilegeDisplayNameW
typedef BOOL(__stdcall *PROC_LookupPrivilegeDisplayNameW)(
	LPCTSTR lpSystemName,
	LPCTSTR lpName,
	LPTSTR lpDisplayName,
	LPDWORD cchDisplayName,
	LPDWORD lpLanguageId
	);


// API Prototype for Advapi32.dll!GetNamedSecurityInfoW
typedef DWORD(__stdcall *PROC_GetNamedSecurityInfoW)(
	LPTSTR pObjectName,
	SE_OBJECT_TYPE ObjectType,
	SECURITY_INFORMATION SecurityInfo,
	PSID* ppsidOwner,
	PSID* ppsidGroup,
	PACL* ppDacl,
	PACL* ppSacl,
	PSECURITY_DESCRIPTOR* ppSecurityDescriptor
	);

// API Prototype for Advapi32.dll!LsaOpenPolicy
typedef NTSTATUS(__stdcall *PROC_LsaOpenPolicy)(
	PLSA_UNICODE_STRING SystemName,
	PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
	ACCESS_MASK DesiredAccess,
	PLSA_HANDLE PolicyHandle
	);


// API Prototype for Advapi32.dll!LsaLookupNames2
typedef NTSTATUS(__stdcall *PROC_LsaLookupNames2)(
	LSA_HANDLE PolicyHandle,
	ULONG Flags,
	ULONG Count,
	PLSA_UNICODE_STRING Names,
	PLSA_REFERENCED_DOMAIN_LIST* ReferencedDomains,
	PLSA_TRANSLATED_SID2* Sids
	);

// API Prototype for WtsApi32.dll!WTSQueryUserToken
typedef BOOL(__stdcall *PROC_WTSQueryUserToken)(
	ULONG SessionId,
	PHANDLE phToken
	);

// Source Code
// API Prototype for Advapi32.dll!LsaEnumerateAccountsWithUserRight
typedef NTSTATUS(__stdcall *PROC_LsaEnumerateAccountsWithUserRight)(
	LSA_HANDLE PolicyHandle,
	PLSA_UNICODE_STRING UserRights,
	PVOID* EnumerationBuffer,
	PULONG CountReturned
	);

// API Prototype for Netapi32.dll!NetUserAdd
typedef NET_API_STATUS(__stdcall *PROC_NetUserAdd)(
	LPCWSTR servername,
	DWORD level,
	LPBYTE buf,
	LPDWORD parm_err
	);
