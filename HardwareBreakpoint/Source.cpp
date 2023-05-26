// Disable warning for usage of ctime
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <ProcessSnapshot.h>

#include <chrono>
#include <ctime>
#include <format>
#include <future>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#define OVERLOADED_MACRO(M, ...) _OVR(M, _COUNT_ARGS(__VA_ARGS__)) (__VA_ARGS__)
#define _OVR(macroName, number_of_args)   _OVR_EXPAND(macroName, number_of_args)
#define _OVR_EXPAND(macroName, number_of_args)    macroName##number_of_args

#define _COUNT_ARGS(...)  _ARG_PATTERN_MATCH(__VA_ARGS__,2,1)
#define _ARG_PATTERN_MATCH(_1,_2,N, ...)   N

#define PrintErrorAndExit(...)     OVERLOADED_MACRO(PrintErrorAndExit, __VA_ARGS__)

#define PrintErrorAndExit2( X, Y ) PrintErrorWithLineAndExit(X, __LINE__, Y)
#define PrintErrorAndExit1( X ) PrintErrorWithLineAndExit(X, __LINE__, GetLastError())

void PrintErrorWithLineAndExit(const std::string& functionName, const size_t line, const size_t errorCode) {

    std::cerr << std::format("{}@{} failed with {:X}",
        functionName, line, errorCode) << std::endl;

    std::exit(-1);
}

void DisplayMessageOnInterval(const std::string& message) {

    const auto currentTime{ std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now()) };

    std::cout << std::format("{} @ {}",
        message, std::ctime(&currentTime)) << std::endl;
}

LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* const exceptionInfo) {

    if (exceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        
        if (exceptionInfo->ContextRecord->Dr6 & 0x1) {
            static std::string replacementMessage{ "Hooked Hello World!" };

            // Write in replacement message
            auto* firstParameter{ reinterpret_cast<std::string*>(
                exceptionInfo->ContextRecord->Rcx) };
            *firstParameter = replacementMessage;

            // Set the resume flag before continuing execution
            exceptionInfo->ContextRecord->EFlags |= 0x10000;
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

DWORD GetMainThreadId(const HANDLE processHandle) {

    std::shared_ptr<HPSS> snapshot(new HPSS{}, [&](HPSS* snapshotPtr) {
        PssFreeSnapshot(processHandle, *snapshotPtr);
    });

    auto result{ PssCaptureSnapshot(processHandle,
        PSS_CAPTURE_THREADS, 0, snapshot.get()) };
    if (result != ERROR_SUCCESS) {
        PrintErrorAndExit("PssCaptureSnapshot", result);
    }

    std::shared_ptr<HPSSWALK> walker(new HPSSWALK{}, [&](HPSSWALK* walkerPtr) {
        PssWalkMarkerFree(*walkerPtr);
    });

    result = PssWalkMarkerCreate(nullptr, walker.get());
    if (result != ERROR_SUCCESS) {
        PrintErrorAndExit("PssWalkMarkerCreate", result);
    }

    DWORD mainThreadId{};
    FILETIME lowestCreateTime{ MAXDWORD, MAXDWORD };

    PSS_THREAD_ENTRY thread{};

    // Iterate through the threads and keep track of the one
    // with the lowest creation time.
    while (PssWalkSnapshot(*snapshot, PSS_WALK_THREADS,
        *walker, &thread, sizeof(thread)) == ERROR_SUCCESS) {
        if (CompareFileTime(&lowestCreateTime, &thread.CreateTime) == 1) {
            lowestCreateTime = thread.CreateTime;
            mainThreadId = thread.ThreadId;
        }
    }

    return mainThreadId;
}

bool SetDebugBreakpoint(const HANDLE& mainThreadHandle, const void* const targetAddress) {

    CONTEXT mainThreadContext {
        .ContextFlags = CONTEXT_DEBUG_REGISTERS,

        // Set an address to break at on Dr0
        .Dr0 = reinterpret_cast<DWORD64>(targetAddress),
        
        // Set the debug control register to enable the breakpoint in Dr0
        .Dr7 = (1 << 0)
    };

    // Suspend the thread before setting its context
    SuspendThread(mainThreadHandle);

    // Set the main threads context
    auto result{ SetThreadContext(mainThreadHandle, &mainThreadContext) };
    if (!result) {
        PrintErrorAndExit("SetThreadContext");
    }

    // Resume the thread after setting its context
    ResumeThread(mainThreadHandle);

    return result != 0;
}

int main(int argc, char* argv[]) {

    std::async([]() {
        const auto mainThreadId{ GetMainThreadId(GetCurrentProcess()) };
        const auto mainThreadHandle{ OpenThread(
            THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
            false, mainThreadId) };

        if (mainThreadHandle == nullptr) {
            PrintErrorAndExit("OpenThread");
        }

        // Add a custom exception handler
        AddVectoredExceptionHandler(true, ExceptionHandler);

        if (!SetDebugBreakpoint(mainThreadHandle, DisplayMessageOnInterval)) {
            std::cerr << std::format("Failed to set hardware breakpoint on {:X}",
                reinterpret_cast<DWORD_PTR>(DisplayMessageOnInterval))
                << std::endl;
        }

        CloseHandle(mainThreadHandle);

    }).wait();

    while (true) {
        DisplayMessageOnInterval("Hello World!");
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    return 0;
}
