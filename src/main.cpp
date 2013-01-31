/**
 *
 * LdrDebug
 *
 * Utility that helps with debugging of ring 3 part of PE/PE+ loader
 *
 * Copyright (c) 2013 ReWolf
 * http://blog.rewolf.pl/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <Windows.h>
#include <cstdio>
#include <vector>
#include <string>
#include "wow64ext.h"


void printUsage()
{
	printf("LdrDebug v1.0\nCopyright (c) 2013 ReWolf\nhttp://blog.rewolf.pl\n\nUsage:\n\n");
	printf("  Debugging PE/PE+ loader according to file format: ldrdebug executable_file(x86/x64)\n");
	printf("  Debugging x64 part of WOW64 process             : ldrdebug /x64 executable_file_x86\n\n");
	printf("After successful process creation attach favourite debugger e.g.:\n\n");
	printf("ollydbg.exe -p PID\n");
	printf("windbg.exe -p PID\n");
	printf("idag.exe -rw+PID\n");
}

bool inject32(HANDLE hProcess)
{
	BYTE shellcode32[] = 
	{
								// _begin:
		0xEB, 0x0B,					// jmp		_skip
		0x6A, 0x00,					// push		0
		0x6A, 0x00,					// push		0
		0xB8, 0x78, 0x56, 0x34, 0x12,			// mov		eax, NtTerminateThread
		0xFF, 0xD0,					// call		eax
								// _skip:
		0xE8, 0x00, 0x00, 0x00, 0x00,			// call		$+5
		0x58,						// pop		eax
		0x66, 0xC7, 0x40, 0xEE, 0x90, 0x90,		// mov		word ptr [eax - ($ - _begin - 1)], 9090h
		0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,		// mov		eax, dword [fs:18h]		; TEB
		0x8B, 0x40, 0x30,				// mov		eax, dword [eax + 30h]	; PEB
								// _loop:
		0xF3, 0x90,					// pause
		0x80, 0x78, 0x02, 0x00,				// cmp		byte [eax + 2], 0		; PEB.BeingDebugged
		0x74, 0xF8,					// je		_loop
		0xCC,						// int3
		0xB8, 0x78, 0x56, 0x34, 0x12,			// mov		eax, LdrInitializeThunk
		0xC7, 0x00, 0x78, 0x56, 0x34, 0x12,		// mov		dword [eax], original_bytes_1
		0x66, 0xC7, 0x40, 0x04, 0x34, 0x12,		// mov		word [eax + 4], original_bytes2
		0xFF, 0xE0					// jmp		eax
	};

	static const int shl32_LdrInitThunk = 0x2C;
	static const int shl32_NtTerminateThread = 0x07;
	static const int shl32_OrigBytes1 = 0x32;
	static const int shl32_OrigBytes2 = 0x3A;

	BYTE shellcode32_2[] =
	{
		0x68, 0x00, 0x00, 0x00, 0x00,			// push		shellcode32
		0xC3						// ret
	};

	BYTE* addr = (BYTE*)VirtualAllocEx(hProcess, 0, sizeof(shellcode32), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (0 == addr)
	{
		printf("VirtualAllocEx failed.\n");
		return false;
	}

	BYTE* addr_LdrInitializeThunk = (BYTE*)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "LdrInitializeThunk");
	BYTE* addr_NtTerminateThread = (BYTE*)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtTerminateThread");
	*(DWORD*)(shellcode32 + shl32_LdrInitThunk) = (DWORD)addr_LdrInitializeThunk;
	*(DWORD*)(shellcode32 + shl32_NtTerminateThread) = (DWORD)addr_NtTerminateThread;
	*(DWORD*)(shellcode32 + shl32_OrigBytes1) = *(DWORD*)addr_LdrInitializeThunk;
	*(WORD*)(shellcode32 + shl32_OrigBytes2) = *(WORD*)(addr_LdrInitializeThunk + 4);

	DWORD tmp = 0;
	WriteProcessMemory(hProcess, addr, shellcode32, sizeof(shellcode32), &tmp);

	*(DWORD*)(shellcode32_2 + 1) = (DWORD)(addr + 2);
	DWORD oldProtect = 0;
	VirtualProtectEx(hProcess, addr_LdrInitializeThunk, sizeof(shellcode32_2), PAGE_EXECUTE_READWRITE, &oldProtect);
	WriteProcessMemory(hProcess, addr_LdrInitializeThunk, shellcode32_2, sizeof(shellcode32_2), &tmp);

	return true;
}

bool inject64(HANDLE hProcess, HANDLE hThread)
{
	BYTE shellcode64[] =
	{
											// _begin:
		0xEB, 0x12,								// jmp		_skip
		0x48, 0x31, 0xC9,							// xor		rcx, rcx
		0x48, 0x31, 0xD2,							// xor		rdx, rdx
		0x48, 0xB8, 0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12,		// mov		rax, NtTerminateThread
		0xFF, 0xD0,								// call		rax
											// _skip:
		0x66, 0xC7, 0x05, 0xE3, 0xFF, 0xFF, 0xFF, 0x90, 0x90,			// mov		word [_begin], 9090h
		0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,			// mov		rax, [gs:30h]			;TEB
		0x48, 0x8B, 0x40, 0x60,							// mov	rax, [rax + 60h]			; PEB
											// _loop:
		0xF3, 0x90,								// pause
		0x80, 0x78, 0x02, 0x00,							// cmp		byte [rax + 2], 0		; PEB.BeingDebugged
		0x74, 0xF8,								// je		_loop
		0xCC,									// int3
		0x48, 0xB8, 0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12,		// mov		rax, LdrInitializeThunk
		0xC7, 0x00, 0x78, 0x56, 0x34, 0x12,					// mov		dword [rax], original_bytes_1
		0xC7, 0x40, 0x04, 0x78, 0x56, 0x34, 0x12,				// mov		dword [rax + 4], original_bytes_2
		0xC7, 0x40, 0x08, 0x78, 0x56, 0x34, 0x12,				// mov		dword [rax + 8], original_bytes_3
		0xFF, 0xE0								// jmp		rax
	};

	static const int shl64_LdrInitThunk = 0x35+0;
	static const int shl64_NtTerminateThread = 0x0A+0;
	static const int shl64_OrigBytes1 = 0x3F+0;
	static const int shl64_OrigBytes2 = 0x46+0;
	static const int shl64_OrigBytes3 = 0x4D+0;

	BYTE shellcode64_2[] =
	{
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// mov		rax, shellcode64
		0xFF, 0xE0								// jmp		rax
	};

	DWORD64 addr = VirtualAllocEx64(hProcess, 0, sizeof(shellcode64), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (0 == addr)
	{
		printf("VirtualAllocEx failed.\n");
		return false;
	}

	BYTE* addr_LdrInitializeThunk = (BYTE*)GetProcAddress64(GetModuleHandle64(L"ntdll.dll"), "LdrInitializeThunk");
	BYTE* addr_NtTerminateThread = (BYTE*)GetProcAddress64(GetModuleHandle64(L"ntdll.dll"), "NtTerminateThread");
	*(DWORD64*)(shellcode64 + shl64_LdrInitThunk) = (DWORD64)addr_LdrInitializeThunk;
	*(DWORD64*)(shellcode64 + shl64_NtTerminateThread) = (DWORD64)addr_NtTerminateThread;
	*(DWORD*)(shellcode64 + shl64_OrigBytes1) = *(DWORD*)addr_LdrInitializeThunk;
	*(DWORD*)(shellcode64 + shl64_OrigBytes2) = *(DWORD*)(addr_LdrInitializeThunk + 4);
	*(DWORD*)(shellcode64 + shl64_OrigBytes3) = *(DWORD*)(addr_LdrInitializeThunk + 8);

	DWORD64 tmp = 0;
	WriteProcessMemory64(hProcess, addr, shellcode64, sizeof(shellcode64), (SIZE_T*)&tmp);

	*(DWORD64*)(shellcode64_2 + 2) = (DWORD64)(addr);
	DWORD oldProtect = 0;
	VirtualProtectEx(hProcess, addr_LdrInitializeThunk, sizeof(shellcode64_2), PAGE_EXECUTE_READWRITE, &oldProtect);
	WriteProcessMemory64(hProcess, (DWORD64)addr_LdrInitializeThunk, shellcode64_2, sizeof(shellcode64_2), (SIZE_T*)&tmp);

	return true;
}

//ollydbg.exe -p PID
//windbg.exe -p PID
//idag.exe -rw+PID

int wmain(int argc, wchar_t* argv[])
{
	if (argc < 2)
	{
		printUsage();
		return 0;
	}

	int ca = 1;
	wchar_t* strAppName = 0;
	wchar_t* strCmdLine = 0;
	bool force64 = false;
	while (ca < argc)
	{
		if ('/' == argv[ca][0])
		{
			if (0 == wcscmp(argv[ca], L"/x64"))
				force64 = true;
		}
		else
		{
			if (0 == strAppName)
				strAppName = argv[ca];
			else if (0 == strCmdLine)
				strCmdLine = argv[ca];
		}
		ca++;
	}

	if (0 == strAppName)
	{
		printUsage();
		return 0;
	}
	
	DWORD binType = -1;
	if (!GetBinaryType(strAppName, &binType))
	{
		printf("Can't determine executable format (GetBinaryType failed).\n");
		return 0;
	}

	printf("Creating process: %ws\nArguments       : %ws\nType            : %ws\n", strAppName, strCmdLine, binType == SCS_32BIT_BINARY ? L"x86" : binType == SCS_64BIT_BINARY ? L"x64" : L"unknown");

	wchar_t tmpBuf[0x1000] = { 0 };
	if (0 != strCmdLine)
	{
		wcscat_s(tmpBuf, strAppName);
		wcscat_s(tmpBuf, L" ");
		wcscat_s(tmpBuf, strCmdLine);
		strCmdLine = tmpBuf;
	}

	STARTUPINFO sui = { 0 };
	sui.cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION pi = { 0 };
	if (!CreateProcess(strAppName, strCmdLine, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &sui, &pi))
	{
		printf("CreateProcess failed.\n");
		return 0;
	}
	printf("PID             : %d (%08X)\n", pi.dwProcessId, pi.dwProcessId);

	if ((SCS_64BIT_BINARY == binType) || force64)
	{
		inject64(pi.hProcess, pi.hThread);
	}
	else
	{
		if (!inject32(pi.hProcess))
			printf("Can't inject shellcode to the process.\n");
	}

	ResumeThread(pi.hThread);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return 0;
}
