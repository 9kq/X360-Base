#include <xtl.h>
#include <windef.h>
#include <vector>
#include <functional>
#include <assert.h>
#include <xtl.h>
#include <windef.h>
#include <vector>
#include <xtl.h>
#include <xboxmath.h>
#include <time.h>
#include <xtl.h>
#include <xboxmath.h>
#include <stdio.h>
#include <map>
#include <math.h>
#include <vector>
#include <array>
#include <ctime>
#include "cdecl.h"

/*
    Very simple 'Base'(Just hooking)
	You can do the ui your self
	My Github > https://github.com/TeamKet
*/

#pragma region Stuff
Detour<DWORD> RageVmHook;
BOOL Hookings[3] = { false, false, false };
#define ENC_SEED ((("update.rpf"[5] * 1337) + ("default.xex"[9] * 1337)) * 5)
#define ENC_VAR(A) (A ^ ENC_SEED)
template<typename T>
T DecVar(T dwVal) {
	return (dwVal ^ ENC_SEED);
}
#pragma endregion

#pragma region RageVM
DWORD RageVM_Hook(DWORD r3, DWORD dwGlobalPtr, DWORD r5, s_ScrThread* scrThread) {
	if (strstr(scrThread->m_ThreadName, "main_persistent") != NULL)
	{
          // Your menu stuff goes here
	}
	if (strstr(scrThread->m_ThreadName, "freemode") != NULL) {
		// For network tings
	}
	return RageVmHook.CallOriginal(r3, dwGlobalPtr, r5, scrThread);
}
VOID TitleThread() {
	for (;;) {
		if (XamGetCurrentTitleId() == 0xFFFE07D1 && !Hookings[0]) { // Dash 
			Sleep(500);
			Hookings[0] = TRUE;
			Hookings[1] = FALSE;
		}
		if (XamGetCurrentTitleId() == 0x545408A7 && !Hookings[1]) // GTA Id
		{
			// Basic bypass's extra
#pragma region Startup Shit
			*(int*)DecVar(ENC_VAR(0x820093A4)) = DecVar(ENC_VAR(0x60000000));
			*(int*)DecVar(ENC_VAR(0x835A30EC)) = DecVar(ENC_VAR(0x60000000));
			*(int*)DecVar(ENC_VAR(0x830C8F2C)) = DecVar(ENC_VAR(0x60000000));
			*(DWORD*)0x82D1E0BC = 0x60000000;
			ZeroMemory((PVOID)(0x8204DF70), 0x0B);
#pragma endregion

#pragma region Net Events
			*(int*)DecVar(ENC_VAR(0x830DEB58)) = DecVar(ENC_VAR(0x4E800020));
			*(int*)DecVar(ENC_VAR(0x830F2BB8)) = DecVar(ENC_VAR(0x4E800020));
			*(int*)DecVar(ENC_VAR(0x830D77A8)) = DecVar(ENC_VAR(0x4E800020));
			*(int*)DecVar(ENC_VAR(0x830D8B38)) = DecVar(ENC_VAR(0x4E800020));
			*(int*)DecVar(ENC_VAR(0x830D7330)) = DecVar(ENC_VAR(0x4E800020));
			*(int*)DecVar(ENC_VAR(0x830DF6D0)) = DecVar(ENC_VAR(0x4E800020));
#pragma endregion

#pragma region Script Bypass
			*(int*)DecVar(ENC_VAR(0x83288A30)) = DecVar(ENC_VAR(0x48000104)); //Script Bypass
			*(long long*)DecVar(ENC_VAR(0x838B60F4)) = DecVar(ENC_VAR(0x00000422F6D6AA59)); //Script Bypass
			*(int*)DecVar(ENC_VAR(0x82FDB57C)) = DecVar(ENC_VAR(0x3FC0022C)); //Script Bypass
			*(int*)DecVar(ENC_VAR(0x82FDB580)) = DecVar(ENC_VAR(0x63DEC800)); //Script Bypass
			*(int*)DecVar(ENC_VAR(0x82FDB584)) = DecVar(ENC_VAR(0x93DD0018)); //Script Bypass
			*(int*)DecVar(ENC_VAR(0x82FDB588)) = DecVar(ENC_VAR(0x3C60838B)); //Script Bypass
			*(int*)DecVar(ENC_VAR(0x82FDB58C)) = DecVar(ENC_VAR(0x606360F4)); //Script Bypass
			*(int*)DecVar(ENC_VAR(0x82FDB590)) = DecVar(ENC_VAR(0xE8630000)); //Script Bypass
			*(int*)DecVar(ENC_VAR(0x82FDB594)) = DecVar(ENC_VAR(0x907D001C)); //Script Bypass

			*(int*)DecVar(ENC_VAR(0x82CE583C)) = DecVar(ENC_VAR(0x60000000)); // Spawn Bypasses
			*(int*)DecVar(ENC_VAR(0x82D1E084)) = DecVar(ENC_VAR(0x60000000)); // Spawn Bypasses
			*(int*)DecVar(ENC_VAR(0x82D1E0BC)) = DecVar(ENC_VAR(0x60000000)); // Spawn Bypasses
			*(int*)DecVar(ENC_VAR(0x82D5C960)) = DecVar(ENC_VAR(0x60000000)); // Spawn Bypasses / Vehicle creation bypass
#pragma endregion

#pragma region Various Bypasses
			*(DWORD*)0x820093A4 = 0x60000000;
			*(QWORD*)0x838B60F4 = 0x00000422F6D6AA59;
			*(DWORD*)0x83288A30 = 0x48000104;
			*(CHAR*)0x82CF782B = 0x01;
			*(DWORD*)(0x82FDB564 + 0x0) = 0x3FC0022C;
			*(DWORD*)(0x82FDB564 + 0x4) = 0x63DEC800;
			*(DWORD*)(0x82FDB564 + 0x8) = 0x93DD0018;
			*(DWORD*)(0x82FDB564 + 0xC) = 0x3C60838B;
			*(DWORD*)(0x82FDB564 + 0x10) = 0x606360F4;
			*(DWORD*)(0x82FDB564 + 0x14) = 0xE8630000;
			*(DWORD*)(0x82FDB564 + 0x18) = 0x907D001C;
			*(DWORD*)(0x82FDB564 + 0x1C) = 0x3C60838B;
			*(DWORD*)(0x82FDB564 + 0x20) = 0x606360F4;
			*(DWORD*)(0x82FDB564 + 0x24) = 0xF8630000;
			*(DWORD*)(0x82FDB564 + 0x28) = 0x3C6082FD;
			*(DWORD*)(0x82FDB564 + 0x2C) = 0x6063B564;
			*(DWORD*)(0x82FDB564 + 0x30) = 0xF8630000;
			int Objectbypass = 0x4168F0AE;
			Objectbypass = Objectbypass - 80;
			Objectbypass = Objectbypass * 2;
			*(int*)Objectbypass = NOP;
#pragma endregion

#pragma region Weather For All
			*(DWORD*)0x82C6CDC8 = 0x60000000;
			*(DWORD*)0x82533CBC = 0x60000000;
			*(DWORD*)0x82533CFC = 0x60000000;
#pragma endregion

			RageVmHook.SetupDetour(0x83525E00, RageVM_Hook); // Main Hook

			Hookings[0] = FALSE;
			Hookings[1] = TRUE;
		}
		Sleep(2000);
	}
}
#pragma endregion

#pragma region DllMain
ULONG ThreadId;
HANDLE Thread;
BOOL bNewThread = true;
BOOL WINAPI DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved) {
	if (dwReason == DLL_PROCESS_ATTACH) {
		if (bNewThread) {
			ExCreateThread(&Thread, 0, &ThreadId, (PVOID)XapiThreadStartup, (LPTHREAD_START_ROUTINE)TitleThread, 0, 0x2);
			XSetThreadProcessor(Thread, 4);
			bNewThread = false;
		}
		else {
			CloseHandle(Thread);
			SuspendThread(Thread);
		}
	}
	if (dwReason == DLL_PROCESS_DETACH) {
		SuspendThread(Thread);
		RageVmHook.TakeDownDetour();
	}
	if (dwReason == DLL_THREAD_ATTACH) {
		ResumeThread(Thread);
	}
	if (dwReason == DLL_THREAD_DETACH) {
		CloseHandle(Thread);
		SuspendThread(Thread);
	}
	return true;
}
#pragma endregion