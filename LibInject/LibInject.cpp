// LibInject.cpp : 定义应用程序的入口点。
//

#include "framework.h"
#include "LibInject.h"
#include <windows.h>
#include "resource.h"
#include <TlHelp32.h>
#include <cstdio>
#include <Shellapi.h>

TCHAR szDllPath[MAX_PATH] = { 0 };
TCHAR szDllName[MAX_PATH] = { 0 };
INT_PTR CALLBACK Dlgproc(_In_ HWND hWnd, _In_ UINT uMsg, _In_ WPARAM wParam, _In_ LPARAM lParam);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_MAIN_DLG),NULL, &Dlgproc);
	return 0;
}

int GetPidByProcessName(const char* ProcessName) {
	HANDLE Processes = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,NULL);
	PROCESSENTRY32 ProcessInfo = { 0 };
	ProcessInfo.dwSize = sizeof(PROCESSENTRY32);
	while (Process32Next(Processes, &ProcessInfo)) {
		if (strcmp(ProcessInfo.szExeFile, ProcessName) == 0) {
			return ProcessInfo.th32ProcessID;
		}
	} 
	return -1;
}

HMODULE GetModuleHandleByName(const char* ModuleName,DWORD pid) {
	//TH32CS_SNAPHEAPLIST TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPALL 这些值要指定第二参数
	HANDLE Processes = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32 ModuleInfo = { 0 };
	ModuleInfo.dwSize = sizeof(MODULEENTRY32);
	char buf[0x100];

	while (Module32Next(Processes, &ModuleInfo)) {
		sprintf_s(buf, "- %s \n", ModuleInfo.szModule);
		OutputDebugString(buf);
		if (strcmp(ModuleInfo.szModule, ModuleName) == 0) {
			return ModuleInfo.hModule;
		}
	}
	return NULL;
}

int UninjectDllFromProcess(DWORD pid,const char * ModuleName) {
	if (pid < 0) {
		return -1;
	}
	//1. 打开已存在的目标进程
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (NULL == hProcess) {
		OutputDebugString("Cannot open this process.\n");
		return -1;
	}

	HMODULE hKernel32Module = GetModuleHandle("kernel32.dll");
	if (NULL == hKernel32Module) {
		OutputDebugString("Cannot find kernel32.dll.\n");
		return -1;
	}
	//2. 获取函数的地址
	FARPROC hFarProc = GetProcAddress(hKernel32Module, "FreeLibrary");
	if (NULL == hFarProc) {
		OutputDebugString("Cannot find get function address.\n");
		return -1;
	}

	//3. 获取模块句柄 

	HMODULE hModule = GetModuleHandleByName(ModuleName,pid);

	if (NULL == hModule) {
		OutputDebugString("Cannot find this module.\n");
		return -1;
	}
	//4. 在远程的进程创建一个线程调用FreeLibrary

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0
		, (LPTHREAD_START_ROUTINE)hFarProc //函数地址
		, hModule //传给线程的参数,必须是目标进程能访问到的地址
		, 0
		, NULL 
	);

	if (NULL == hThread) {
		OutputDebugString("Cannot create thread to call FreeLibrary.\n");
		return -1;
	}

	WaitForSingleObject(hThread, INFINITE);
	
	CloseHandle(hProcess);
	CloseHandle(hThread);
	return 0;
}


int InjectDllToProcess(TCHAR *DllPath, DWORD pid,HMODULE *hLoadLibraryModule) {
	if (pid < 0 || NULL == DllPath) {
		return -1;
	}
	//1. 打开已存在的目标进程
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	if (NULL == hProcess) {
		OutputDebugString("Cannot open this process.\n");
		return -1;
	}
	//2. 创建在目标进程创建内存
	LPVOID lpAddr = VirtualAllocEx(hProcess, NULL, strlen(DllPath), MEM_COMMIT, PAGE_READWRITE);
	if (NULL == lpAddr) {
		OutputDebugString("Cannot alloc memory.\n");
		return -1;
	}

	char  buf[0x100];
	sprintf_s(buf, "Alloc memory address: %p \n", lpAddr);
	OutputDebugString(buf);

	//3. 写入内存
	BOOL isOk = WriteProcessMemory(hProcess //要写入的目标进程
		, lpAddr //写入目标进程的位置
		, DllPath //写入的内容
		, strlen(DllPath) //写入的长度
		, NULL);
	if (!isOk) {
		OutputDebugString("Cannot write memory.\n");
		return -1;
	}

	HMODULE hKernel32Module = GetModuleHandle("kernel32.dll");
	if (NULL == hKernel32Module) {
		OutputDebugString("Cannot find kernel32.dll.\n");
		return -1;
	}
	//4. 获取函数的地址
	FARPROC hFarProc = GetProcAddress(hKernel32Module, "LoadLibraryA");
	if (NULL == hFarProc) {
		OutputDebugString("Cannot find get function address.\n");
		return -1;
	}
	//5. 在远程的进程创建一个线程调用LoadLibraryA
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0
		, (LPTHREAD_START_ROUTINE)hFarProc //函数地址
		, lpAddr //传给线程的参数,必须是目标进程能访问到的地址
		, 0
		, NULL 
	);
	
	if (NULL == hThread) {
		OutputDebugString("Cannot create thread to call LoadLibraryA.\n");
		return -1;
	}
	//6. 释放资源
	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(hThread, lpAddr, 0, MEM_RELEASE);

	CloseHandle(hProcess);
	CloseHandle(hThread);
	return 0;
}

INT_PTR CALLBACK Dlgproc( HWND hWnd,  UINT uMsg,  WPARAM wParam,  LPARAM lParam) {

	TCHAR ProcName[MAX_PATH] = { 0 };
	HMODULE hModule = NULL;

	if (uMsg == WM_COMMAND) {
		switch (wParam) {
		case ID_INJECT_DLL: {
			GetDlgItemText(hWnd, IDC_PROC_NAME, ProcName, MAX_PATH);

			int Pid = GetPidByProcessName(ProcName);
			if (szDllPath == NULL) {
				MessageBox(hWnd, "注入失败,请先拖入dll文件", "提示", MB_OK | MB_ICONWARNING);
				break;
			}
			if (Pid < 0) {
				MessageBox(hWnd, "注入失败,请检查进程名", "提示", MB_OK | MB_ICONWARNING);
				break;
			}
			int InjectRet = InjectDllToProcess(szDllPath, Pid, &hModule);
			if (InjectRet < 0){
				MessageBox(hWnd, "注入失败,请检查路径", "提示", MB_OK|MB_ICONWARNING);
				break;
			}
			else {
				MessageBox(hWnd, "注入成功！", "提示", MB_OK | MB_ICONWARNING);
			}
			break;
			}
		case ID_UNINJECT_DLL: {
			GetDlgItemText(hWnd, IDC_PROC_NAME, ProcName,MAX_PATH);
			int Pid = GetPidByProcessName(ProcName);
			if (szDllName == NULL) {
				MessageBox(hWnd, "停止注入失败,请先拖入dll文件", "提示", MB_OK | MB_ICONWARNING);
				break;
			}

			if (Pid < 0) {
				MessageBox(hWnd, "停止注入失败,请检查进程名", "提示", MB_OK | MB_ICONWARNING);
				break;
			}
			int UninjectRet = UninjectDllFromProcess(Pid, szDllName);
			if (UninjectRet >= 0) {
				MessageBox(hWnd, "停止注入成功", "提示", 0);
			}
			else {
				MessageBox(hWnd, "停止注入失败，可能该进程没有注入DLL文件", "提示", MB_OK|MB_ICONWARNING);
			}
			break;
			}
		}
	}
	else if (uMsg == WM_DROPFILES) {
		TCHAR szFilePath[MAX_PATH] = { 0 };
		DragQueryFile((HDROP)wParam, 0, szFilePath, MAX_PATH - 1);
		DragFinish((HDROP)wParam);
		SetDlgItemText(hWnd,IDC_DLL_PATH,szFilePath);
		memcpy_s(szDllPath, MAX_PATH, szFilePath, MAX_PATH);

		TCHAR* t = (TCHAR*)strrchr(szDllPath, '\\');
		memcpy_s(szDllName, MAX_PATH, t+1, strlen(t+1));
		
	}
	else if (uMsg == WM_CLOSE) {
		exit(0);
	}
	return FALSE;
}