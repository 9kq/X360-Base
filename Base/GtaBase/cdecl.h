#pragma region Thread State
enum e_ThreadState
{
	ThreadStateIdle,
	ThreadStateRunning,
	ThreadStateKilled,
	ThreadState3,
	ThreadState4,
};
struct s_ScrThread
{
	DWORD m_ThreadId;
	DWORD m_ScrHash;
	e_ThreadState m_ThreadState;
	DWORD m_InstructionPtr;
	DWORD m_FrameStackPtr;
	DWORD m_StackPtr;
	DWORD m_TimerA;
	DWORD m_TimerB;
	DWORD m_TimerC;
	DWORD m_mUnk1;
	DWORD m_mUnk2;
	DWORD m_f2C;
	DWORD m_f30;
	DWORD m_f34;
	DWORD m_f38;
	DWORD m_f3C;
	DWORD m_f40;
	DWORD m_f44;
	DWORD m_f48;
	DWORD m_f4C;
	DWORD m_f50;
	DWORD m_pad1;
	DWORD m_pad2;
	DWORD m_pad3;
	char* m_AbortMessage;
	char m_ThreadName[16];
	DWORD m_pad4[10];
};
#pragma endregion

#pragma region Struct ting
#define NOP 0x60000000
using namespace std;
typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} STRING, *PSTRING;
extern "C" {
	BOOL MmIsAddressValid(PVOID addr);
	DWORD WINAPI MmSetAddressProtect(PVOID BaseAddress, DWORD NumberOfBytes, DWORD NewProtect);
	DWORD ExCreateThread(PHANDLE pHandle, DWORD dwStackSize, LPDWORD lpThreadId, VOID* apiThreadStartup, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlagsMod);
	VOID XapiThreadStartup(VOID(__cdecl *StartRoutine)(VOID*), VOID* StartContext);
	HRESULT NTAPI ObCreateSymbolicLink(PSTRING SymbolicLinkName, PSTRING DeviceName);
	HRESULT NTAPI ObDeleteSymbolicLink(PSTRING SymbolicLinkName);
}
int snprintf(char *buffer, size_t len, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vsnprintf(buffer, len, fmt, args);
	va_end(args);
	return i;
}
#define __isync()       __emit(0x4C00012C)
#define DBG_SERIAL_RCV		(DWORD volatile*)0x7FEA1010
#define DBG_SERIAL_XMIT		(DWORD volatile*)0x7FEA1014
#define DBG_SERIAL_STS		(DWORD volatile*)0x7FEA1018
#define DBG_SERIAL_CNTRL	(DWORD volatile*)0x7FEA101C

#define PWR_REAS_PWRBTN		0x11 // power button pushed
#define PWR_REAS_EJECT		0x12 // eject button pushed
#define PWR_REAS_ALARM		0x15 // guess ~ should be the wake alarm ~
#define PWR_REAS_REMOPWR	0x20 // power button on 3rd party remote/ xbox universal remote
#define PWR_REAS_REMOX		0x22 // xbox universal media remote X button
#define PWR_REAS_WINBTN		0x24 // windows button pushed IR remote
#define PWR_REAS_RESET		0x30 // HalReturnToFirmware(1 or 2 or 3) = hard reset by smc
#define PWR_REAS_WIRELESS	0x55 // wireless controller middle button/start button pushed to power on controller and console
#define PWR_REAS_WIRED		0x5A // wired controller guide button pushed (attached to back usb port)

#define CONSTANT_OBJECT_STRING(s)   { strlen( s ) / sizeof( OCHAR ), (strlen( s ) / sizeof( OCHAR ))+1, s }
#define MAKE_STRING(s)   {(USHORT)(strlen(s)), (USHORT)((strlen(s))+1), (PCHAR)s}
#define EXPORTNUM(x)

#define STATUS_SUCCESS	0
#define NT_EXTRACT_ST(Status)			((((ULONG)(Status)) >> 30)& 0x3)
#define NT_SUCCESS(Status)              (((NTSTATUS)(Status)) >= 0)
#define NT_INFORMATION(Status)          (NT_EXTRACT_ST(Status) == 1)
#define NT_WARNING(Status)              (NT_EXTRACT_ST(Status) == 2)
#define NT_ERROR(Status)                (NT_EXTRACT_ST(Status) == 3)

#define NEG_ONE_AS_DWORD				((DWORD)-1)

#define STATUS_SUCCESS	0
#define FILE_SYNCHRONOUS_IO_NONALERT	0x20
#define OBJ_CASE_INSENSITIVE			0x40

#define IDLE_PROC	0
#define USER_PROC	1
#define SYSTEM_PROC 2

typedef unsigned __int64 QWORD;
#pragma endregion

#pragma region Xam & kernel declarations
VOID(WINAPIV *HalReturnToFirmware)(DWORD dwPowerDownMode) = (VOID(__cdecl *)(DWORD))(DWORD)(GetProcAddress(GetModuleHandle("xboxkrnl.exe"), ((LPSTR)((ULONG_PTR)((WORD)(40))))));
int(WINAPIV *NetDll_XNetStartup)(int xnc, XNetStartupParams* xnsp) = (int(__cdecl *)(int, XNetStartupParams*))(DWORD)(GetProcAddress(GetModuleHandle("xam.xex"), ((LPSTR)((ULONG_PTR)((WORD)(51))))));
int(WINAPIV *NetDll_WSAStartupEx)(int xnc, WORD wVersionRequested, LPWSADATA wsad, DWORD versionReq) = (int(__cdecl *)(int, WORD, LPWSADATA, DWORD))(DWORD)(GetProcAddress(GetModuleHandle("xam.xex"), ((LPSTR)((ULONG_PTR)((WORD)(36))))));
SOCKET(WINAPIV *NetDll_socket)(int xnc, int af, int type, int protocol) = (SOCKET(__cdecl *)(int, int, int, int))(DWORD)(GetProcAddress(GetModuleHandle("xam.xex"), ((LPSTR)((ULONG_PTR)((WORD)(3))))));
int(WINAPIV *NetDll_setsockopt)(int xnc, SOCKET s, int level, int optname, const char * optval, int optlen) = (int(__cdecl *)(int, SOCKET, int, int, const char *, int))(DWORD)(GetProcAddress(GetModuleHandle("xam.xex"), ((LPSTR)((ULONG_PTR)((WORD)(7))))));
int(WINAPIV *NetDll_connect)(int xnc, SOCKET s, const struct sockaddr * name, int namelen) = (int(__cdecl *)(int, SOCKET, const struct sockaddr *, int))(DWORD)(GetProcAddress(GetModuleHandle("xam.xex"), ((LPSTR)((ULONG_PTR)((WORD)(12))))));
int(WINAPIV *NetDll_send)(int xnc, SOCKET s, const char * buf, int len, int flags) = (int(__cdecl *)(int, SOCKET, const char *, int, int))(DWORD)(GetProcAddress(GetModuleHandle("xam.xex"), ((LPSTR)((ULONG_PTR)((WORD)(22))))));
int(WINAPIV *NetDll_recv)(int xnc, SOCKET s, const char * buf, int len, int flags) = (int(__cdecl *)(int, SOCKET, const char *, int, int))(DWORD)(GetProcAddress(GetModuleHandle("xam.xex"), ((LPSTR)((ULONG_PTR)((WORD)(18))))));
int(WINAPIV *NetDll_closesocket)(int xnc, SOCKET s) = (int(__cdecl *)(int, SOCKET))(DWORD)(GetProcAddress(GetModuleHandle("xam.xex"), ((LPSTR)((ULONG_PTR)((WORD)(4))))));
VOID(WINAPIV *XNotifyQueueUI)(DWORD dwType, DWORD dwUserIndex, DWORD dwPriority, LPCWSTR pwszStringParam, ULONGLONG qwParam) = (VOID(__cdecl *)(DWORD, DWORD, DWORD, LPCWSTR, ULONGLONG))(DWORD)(GetProcAddress(GetModuleHandle("xam.xex"), ((LPSTR)((ULONG_PTR)((WORD)(656))))));
DWORD(WINAPIV *XamGetCurrentTitleId)() = (DWORD(__cdecl *)())(DWORD)(GetProcAddress(GetModuleHandle("xam.xex"), ((LPSTR)((ULONG_PTR)((WORD)(463))))));
DWORD(WINAPIV *XexLoadImageFromMemory)(PVOID pvXexBuffer, DWORD dwSize, LPCSTR szXexName, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion, PHANDLE pHandle) = (DWORD(__cdecl *)(PVOID, DWORD, LPCSTR, DWORD, DWORD, PHANDLE))(DWORD)(GetProcAddress(GetModuleHandle("xboxkrnl.exe"), ((LPSTR)((ULONG_PTR)((WORD)(410))))));
VOID(WINAPIV *XexUnloadImage)(HANDLE moduleHandle) = (VOID(__cdecl *)(HANDLE))(DWORD)(GetProcAddress(GetModuleHandle("xboxkrnl.exe"), ((LPSTR)((ULONG_PTR)((WORD)(417))))));
UCHAR(WINAPIV *KeGetCurrentProcessType)(VOID) = (UCHAR(__cdecl *)(VOID))(DWORD)(GetProcAddress(GetModuleHandle("xboxkrnl.exe"), ((LPSTR)((ULONG_PTR)((WORD)(102))))));
DWORD(WINAPIV* GetSpriteAddress)(PCHAR szDict, PCHAR szName) = (DWORD(WINAPIV *)(PCHAR, PCHAR))0x82CB5450;
DWORD(WINAPIV* GetModelAddress)(DWORD dwModel, DWORD* dwUnk) = (DWORD(WINAPIV *)(DWORD, DWORD*))0x835611B8;
VOID(WINAPIV* StoreNative)(DWORD dwNativeTable, DWORD dwNativeHash, DWORD dwFunctionAddress) = (VOID(WINAPIV *)(DWORD, DWORD, DWORD))0x83524A28;
DWORD(WINAPIV* SessionMigrateHost)(HANDLE hSession, DWORD dwUserIndex, PXSESSION_INFO pSessionInfo, PXOVERLAPPED pXOverlapped) = (DWORD(WINAPIV *)(HANDLE, DWORD, PXSESSION_INFO, PXOVERLAPPED))0x83800EB8;
BOOL(WINAPIV* SessionMigrateHost1)(DWORD dwStruct) = (BOOL(WINAPIV *)(DWORD))0x83343420;
#define MAKEINTRESOURCEA(i) ((LPSTR)((ULONG_PTR)((WORD)(i))))
DWORD ResolveFunction(PCHAR ModuleName, DWORD Ordinal)
{
	return (DWORD)(GetProcAddress(GetModuleHandle(ModuleName), MAKEINTRESOURCEA(Ordinal)));
}
VOID XNotifyThread(PWCHAR NotifyText)
{
	XNotifyQueueUI(14, 0, 2, NotifyText, NULL);
}
VOID XNotify(PWCHAR NotifyText, ...)
{
	if (KeGetCurrentProcessType() != USER_PROC)
	{
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)XNotifyThread, (LPVOID)NotifyText, 0, NULL);
	}
	else { XNotifyThread(NotifyText); }
}
#pragma endregion

#pragma region Detors
// Values for the class
BYTE DetourAsm[0x3000] = { 0 };
DWORD DetourAsmIndex;
RTL_CRITICAL_SECTION DetourAsmSection;

VOID PatchInJump(DWORD* Address, void* Dest, BOOL Linked);

int Int24ToInt32(int Value) {
	Value &= 0x00FFFFFF;
	if (Value & 0x800000)
		Value |= 0xFF000000;
	if (Value & 1)
		Value -= 1;
	return Value;
}

bool IsZero(PVOID Scr, DWORD Size) {

	bool result;
	byte *bZeroData = new byte[Size];
	ZeroMemory(bZeroData, Size);

	result = !memcmp(Scr, bZeroData, Size);
	delete[] bZeroData;
	return result;
}

// need to call this from the class because all the agrs are pushed up
// from r3 because it is the class pointer
void __declspec(naked) SetupCaller()
{
	__asm
	{
		mr r3, r4
		mr r4, r5
			mr r5, r6
			mr r6, r7
			mr r7, r8
			mr r8, r9
			mr r9, r10

			fmr fr1, fr2
			fmr fr2, fr3
			fmr fr3, fr4
			fmr fr4, fr5
			fmr fr5, fr6
			fmr fr6, fr7
			fmr fr7, fr8
			fmr fr8, fr9
			fmr fr9, fr10
			blr
	}
}

bool bCheckIfCMP(int ptr)
{
	byte b = *(byte *)ptr;
	byte b2 = *(byte *)(ptr + 1);

	if (b == 0x40 || b == 0x41)
	{
		if (b2 == 0x9A || b2 == 0x82 || b2 == 0x99
			|| b2 == 0x81 || b2 == 0x98 || b2 == 0x80)
			return true;
	}
	return false;
}

template<class _ClassType>
class Detour
{
private:
	BYTE OriginalAsm[0x10]; // 4 instructions
	DWORD DetourIndex;

	__int64 iArgs[8];
	double fArgs[8];

	// This function will get any 'b' or 'bl' and any 'cmp' function added to the stub that
	// it replaces and return the size of the stub in byte lengths
	virtual DWORD DetourFunctionStart(DWORD dwFunctionAddress, DWORD dwStubAddress, PVOID pDestFunc)
	{
		DWORD dwLength = 0;
		DWORD dwTemp;
		DWORD dwTempFuncAddr;
		BOOL bTemp;

		for (int i = 0; i < 4; i++)
		{
			dwTempFuncAddr = dwFunctionAddress + (i * 4);
			byte b = *(byte *)dwTempFuncAddr;
			byte b2 = *(byte *)(dwTempFuncAddr + 1);

			// b or bl
			if (b == 0x48 || b == 0x4B)
			{
				// get the branch to address
				dwTemp = dwTempFuncAddr + Int24ToInt32(*(DWORD *)dwTempFuncAddr);
				bTemp = (*(DWORD *)dwTempFuncAddr & 1) != 0;
				PatchInJump((PDWORD)(dwStubAddress + dwLength), (PVOID)dwTemp, bTemp);
				dwLength += 0x10;

				// if it was a 'b loc_' call, we won't need to anything else to the stub
				if (!bTemp)
					goto DoHook;
			}

			// beq or bne, ble or bgt, bge or blt
			else if (bCheckIfCMP(dwTempFuncAddr))
			{
				dwTemp = *(DWORD *)dwTempFuncAddr & 0xFFFF;

				// if bTemp is true the op code is 'beq'
				bTemp = b == 0x41;

				// check if the branch location is within the stub
				if (dwTemp <= 0x10 && dwTemp > 0)
				{
					if (dwTemp <= (DWORD)(0x10 - (i * 4)))
					{
						*(DWORD *)(dwStubAddress + dwLength) = *(DWORD *)dwTempFuncAddr;
						dwLength += 4;
					}
					else
						goto branch_else;
				}
				else
				{
				branch_else:
					// make a jump past the call if the cmp != what it is checking
					*(DWORD *)(dwStubAddress + dwLength) = ((0x40000000 + (*(DWORD *)dwTempFuncAddr & 0x00FF0000) + 0x14) +
						bTemp ? 0 : 0x01000000);
					dwLength += 4;
					PatchInJump((PDWORD)(dwStubAddress + dwLength), (PVOID)(dwTempFuncAddr + dwTemp), FALSE);
					dwLength += 0x10;
				}
			}

			// if the function op code is null it is invalid
			else if (*(DWORD *)dwTempFuncAddr == 0)
				break;

			else
			{
				*(DWORD *)(dwStubAddress + dwLength) = *(DWORD *)dwTempFuncAddr;
				dwLength += 4;
			}
		}

		// make the stub call the orig function
		PatchInJump((PDWORD)(dwStubAddress + dwLength), (PVOID)(dwFunctionAddress + 0x10), FALSE);
		dwLength += 0x10;

	DoHook:
		// apply the hook
		PatchInJump((PDWORD)dwFunctionAddress, pDestFunc, FALSE);
		return dwLength;
	}

public:
	DWORD Addr;
	DWORD SaveStub;
	Detour() {};
	~Detour() {};

	virtual void SetupDetour(DWORD Address, PVOID Destination)
	{
		if (IsZero(&DetourAsmSection, sizeof(DetourAsmSection)))
			InitializeCriticalSection(&DetourAsmSection);

		EnterCriticalSection(&DetourAsmSection);

		DetourIndex = DetourAsmIndex;
		SaveStub = (DWORD)&DetourAsm[DetourIndex];

		// save the address incase we take-down the detour
		Addr = Address;
		// Copy the asm bytes before we replace it with the hook
		memcpy(OriginalAsm, (PVOID)Address, 0x10);

		// increment the index for the space we are using for the stub
		DetourAsmIndex += DetourFunctionStart(Address, SaveStub, Destination);

		LeaveCriticalSection(&DetourAsmSection);
	}

	virtual void TakeDownDetour()
	{
		if (Addr && MmIsAddressValid((PVOID)Addr))
			memcpy((PVOID)Addr, OriginalAsm, 0x10);
	}

	virtual _ClassType CallOriginal(...)
	{
		SetupCaller();
		return ((_ClassType(*)(...))SaveStub)();
	}

	virtual BYTE* ReturnOriginal(...)
	{
		return OriginalAsm;
	}
};

VOID PatchInJump(DWORD* Address, void* Dest, BOOL Linked) {

	DWORD Bytes[4];
	DWORD Destination = (DWORD)Dest;

	Bytes[0] = 0x3D600000 + ((Destination >> 16) & 0xFFFF);// lis %r11, dest>>16

	if (Destination & 0x8000) // If bit 16 is 1
		Bytes[0] += 1;

	Bytes[1] = 0x396B0000 + (Destination & 0xFFFF); // addi	%r11, %r11, dest&0xFFFF
	Bytes[2] = 0x7D6903A6; // mtctr	%r11

	Bytes[3] = 0x4E800420; // bctr

	if (Linked)
		Bytes[3] += 1; // bctrl

	memcpy(Address, Bytes, 0x10);
	__dcbst(0, Address);
	__sync();
	__isync();
}

static wchar_t* CharToWChar(const char* text)
{
	const size_t size = strlen(text) + 1;
	wchar_t* wText = new wchar_t[size];
	mbstowcs(wText, text, size);
	return wText;
}
#pragma endregion
