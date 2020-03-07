// BSIT laboratory work - 1

//		The criteria ::
// - Dynamic loaded library (Windows functions) 
// - Without functions from WinApi
// - Win 7 \\ Win 10

//		What to do ::

//		View Registåred ::
// - Users 
// - Groups
// - SID 
// - Privilleges
//		Must change ::
// - Users
// - Groups
// - Privilleges

#include "LibHeader.h"
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "netapi32.lib")



int main(void)
{
	HINSTANCE hinstLib;
	BOOL fFreeResult, fRunTimeLinkSuccess = FALSE;
	hinstLib = LoadLibrary(TEXT("MyPuts.dll"));

    return 0;
}

