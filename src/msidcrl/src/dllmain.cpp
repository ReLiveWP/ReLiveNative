#include "globals.h"
#include "logging.h"
#include "wlidcomm.h"

#include <tlhelp32.h>

#ifndef TH32CS_GETALLMODS
#define TH32CS_GETALLMODS 0
#endif

#if _WIN64
#define ADDRESS_PRINTF L"0x%016x"
#else
#define ADDRESS_PRINTF L"0x%08x"
#endif

using namespace msidcrl::globals;

extern "C"
{
    static volatile BOOL g_ProbeFault = FALSE;
    LONG WINAPI MSIDCRL_IgnoreExceptionHandler(EXCEPTION_POINTERS *pExceptionInfo)
    {
        if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
        {
            g_ProbeFault = TRUE;

            // try to skip the faulting instruction as best we can
#ifdef UNDER_CE
#if defined(ARM)
            if (pExceptionInfo->ContextRecord->Psr & 0x20) // THUMB
                pExceptionInfo->ContextRecord->Pc += 2;
            else
                pExceptionInfo->ContextRecord->Pc += 4;
#else
#error Unsupported platform
#endif
#else
            return EXCEPTION_CONTINUE_SEARCH;
#endif
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // something else failed, continuing on will just keep calling the same exception handler ad nauseum, just kill it
        LOG_MESSAGE("WE FUCKED IT");
        TerminateProcess(GetCurrentProcess(), -1);

        return EXCEPTION_CONTINUE_SEARCH;
    }

    BOOL ProbeAddress(PVOID pAddress, volatile DWORD_PTR *value)
    {
        g_ProbeFault = FALSE;
        HANDLE hIgnoreException = AddVectoredExceptionHandler(1, MSIDCRL_IgnoreExceptionHandler);

        volatile DWORD_PTR b = 0;
        b = *(volatile const DWORD_PTR *)pAddress;

        if (!g_ProbeFault && value)
        {
            *value = b;
        }
        else if (value)
        {
            *value = 0;
        }

        RemoveVectoredExceptionHandler(hIgnoreException);

        return g_ProbeFault;
    }

    LONG WINAPI MSIDCRL_ExceptionHandler(EXCEPTION_POINTERS *pExceptionInfo)
    {
        EnterCriticalSection(&msidcrl::globals::g_hDriverCrtiSec);

        LOG_MESSAGE_FMT(L"Is this thing on?? ExceptionHandler called in client DLL!!! ExceptionCode=" ADDRESS_PRINTF "; ExceptionAddress=" ADDRESS_PRINTF "; ExceptionInformation=" ADDRESS_PRINTF "",
                        pExceptionInfo->ExceptionRecord->ExceptionCode,
                        pExceptionInfo->ExceptionRecord->ExceptionAddress,
                        pExceptionInfo->ExceptionRecord->ExceptionInformation);

        if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
        {
            LPCWSTR attempt = pExceptionInfo->ExceptionRecord->ExceptionInformation[0] ? L"READ" : L"WRITE";
            LOG_MESSAGE_FMT(L"Attempt to %s at address " ADDRESS_PRINTF, attempt, pExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
        }

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE | TH32CS_GETALLMODS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            LOG_MESSAGE(L"Failed to CreateToolhelp32Snapshot, you're going in blind!!");
            return EXCEPTION_CONTINUE_SEARCH;
        }

        MODULEENTRY32 mod = {0};
        PROCESSENTRY32 proc{0};
        mod.dwSize = sizeof(MODULEENTRY32);
        proc.dwSize = sizeof(PROCESSENTRY32);

        if (Module32First(hSnapshot, &mod))
        {
            do
            {
                LOG_MESSAGE_FMT(L"Module: %s @ " ADDRESS_PRINTF " size: " ADDRESS_PRINTF, mod.szModule, mod.modBaseAddr, mod.modBaseSize);
            } while (Module32Next(hSnapshot, &mod));
        }

#if defined(UNDER_CE) && defined(ARM)
        auto ContextRecord = pExceptionInfo->ContextRecord;
        auto SP = (DWORD_PTR *)ContextRecord->Sp;
        LOG_MESSAGE_FMT(L"Registers: R0=" ADDRESS_PRINTF L"; R1=" ADDRESS_PRINTF L"; R2=" ADDRESS_PRINTF L"; R3=" ADDRESS_PRINTF L";\n"
                        L"R4=" ADDRESS_PRINTF L"; R5=" ADDRESS_PRINTF L"; R6=" ADDRESS_PRINTF L"; R7=" ADDRESS_PRINTF L";\n"
                        L"R8=" ADDRESS_PRINTF L"; R9=" ADDRESS_PRINTF L"; R10=" ADDRESS_PRINTF L"; R11=" ADDRESS_PRINTF L";\n"
                        L"R12=" ADDRESS_PRINTF L"; SP=" ADDRESS_PRINTF L"; LR=" ADDRESS_PRINTF L"; PC=" ADDRESS_PRINTF L"; PSR=" ADDRESS_PRINTF L";",
                        ContextRecord->R0, ContextRecord->R1, ContextRecord->R2, ContextRecord->R3,
                        ContextRecord->R4, ContextRecord->R5, ContextRecord->R6, ContextRecord->R7,
                        ContextRecord->R8, ContextRecord->R9, ContextRecord->R10, ContextRecord->R11,
                        ContextRecord->R12,
                        ContextRecord->Sp,
                        ContextRecord->Lr,
                        ContextRecord->Pc,
                        ContextRecord->Psr);
#elif defined(__x86_64__)
        auto ContextRecord = pExceptionInfo->ContextRecord;
        auto SP = (DWORD_PTR *)ContextRecord->Rsp;
#endif
        DWORD_PTR stackBase = -1;
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(SP, &mbi, sizeof(mbi)) != sizeof(mbi))
            LOG_MESSAGE(L"DOUBLE FUCKED IT");

        stackBase = (DWORD_PTR)mbi.AllocationBase;

        DWORD_PTR addr;
        int x = 0;
        while ((DWORD_PTR)SP > stackBase && !ProbeAddress(SP, &addr) && x < 64)
        {
            DWORD_PTR offset = 0;

            if (Module32First(hSnapshot, &mod))
            {
                do
                {
                    if (addr > (DWORD_PTR)mod.modBaseAddr && addr < (DWORD_PTR)(mod.modBaseAddr + mod.modBaseSize))
                    {
                        offset = addr - (DWORD_PTR)mod.modBaseAddr;
                        break;
                    }
                } while (Module32Next(hSnapshot, &mod));
            }

            if (offset != 0)
            {
                x++;
                LOG_MESSAGE_FMT(L"Stack: " ADDRESS_PRINTF L": " ADDRESS_PRINTF L" (mod: %s + " ADDRESS_PRINTF L")", SP, addr, mod.szModule, offset);
                goto loop;
            }

#ifdef UNDER_CE
            if (Process32First(hSnapshot, &proc))
            {
                do
                {
                    if (addr > (DWORD_PTR)proc.th32MemoryBase && addr < (DWORD_PTR)(proc.th32MemoryBase + 0x2000000))
                    {
                        offset = addr - (DWORD_PTR)proc.th32MemoryBase;
                        break;
                    }
                } while (Process32Next(hSnapshot, &proc));
            }

            if (offset != 0)
            {
                x++;
                LOG_MESSAGE_FMT(L"Stack: " ADDRESS_PRINTF L": " ADDRESS_PRINTF L"(proc: %s + " ADDRESS_PRINTF L")", SP, addr, proc.szExeFile, offset);
                goto loop;
            }
#endif

            LOG_MESSAGE_FMT(L"Stack: " ADDRESS_PRINTF L": " ADDRESS_PRINTF L"", SP, addr);
        loop:
            --SP;
        }

#ifdef UNDER_CE
        CloseToolhelp32Snapshot(hSnapshot);
#else
        CloseHandle(hSnapshot);
#endif

        LeaveCriticalSection(&msidcrl::globals::g_hDriverCrtiSec);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    BOOL DllMain(
        HINSTANCE hinstDLL, // handle to DLL module
        DWORD fdwReason,    // reason for calling function
        LPVOID lpvReserved) // reserved
    {
        // Perform actions based on the reason for calling.
        switch (fdwReason)
        {
        case DLL_PROCESS_ATTACH:
            InitializeCriticalSection(&g_hDriverCrtiSec);
#ifdef UNDER_CE
            AddVectoredExceptionHandler(1, MSIDCRL_ExceptionHandler);
#endif
            break;

        case DLL_THREAD_ATTACH:
            // Do thread-specific initialization.
            break;

        case DLL_THREAD_DETACH:
            // Do thread-specific cleanup.
            break;

        case DLL_PROCESS_DETACH:

            if (lpvReserved != nullptr)
            {
                break; // do not do cleanup if process termination scenario
            }

            // Perform any necessary cleanup.
            break;
        }
        return TRUE; // Successful DLL_PROCESS_ATTACH.
    }
}