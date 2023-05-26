// Disable warning for usage of ctime
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>

#include <chrono>
#include <ctime>
#include <format>
#include <iostream>
#include <string>
#include <thread>

static void* drawTextAddress{ GetProcAddress(
    GetModuleHandleA("user32.dll"),
    "DrawTextA") };

#define PrintErrorAndExit(functionName) \
    PrintErrorWithLineAndExit(functionName, __LINE__)

void PrintErrorWithLineAndExit(const std::string& functionName, const size_t line) {

    std::cerr << std::format("{}@{} failed with {:X}",
        functionName, line, GetLastError()) << std::endl;

    std::exit(-1);
}

void SetMemoryBreakpoint(void* const targetAddress) {

    DWORD oldProtections{};
    MEMORY_BASIC_INFORMATION memoryInfo{};
    auto result{ VirtualQuery(targetAddress, &memoryInfo,
        sizeof(MEMORY_BASIC_INFORMATION)) };
    if (result == 0) {
        PrintErrorAndExit("VirtualQuery");
    }

    result = VirtualProtect(targetAddress, sizeof(void*),
        memoryInfo.Protect | PAGE_GUARD, &oldProtections);
    if (!result) {
        PrintErrorAndExit("VirtualProtect");
    }
}

LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* const exceptionInfo) {

    if (exceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {

        if (exceptionInfo->ExceptionRecord->ExceptionAddress == drawTextAddress) {

            const static std::string replacementMessage{ "Hooked Hello World!" };

            // Set to replacement message address
            exceptionInfo->ContextRecord->Rdx = reinterpret_cast<DWORD64>(
                replacementMessage.c_str());
        }

        // Set single step flag so that memory breakpoints are re-enabled
        // on the next instruction execution.
        exceptionInfo->ContextRecord->EFlags |= 0x100;

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (exceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

        // Re-enable memory breakpoint since a different address might
        // have caused the guard page violation.
        SetMemoryBreakpoint(drawTextAddress);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char* argv[]) {

    // Add a custom exception handler
    AddVectoredExceptionHandler(true, ExceptionHandler);

    SetMemoryBreakpoint(drawTextAddress);

    auto hDC{ GetDC(nullptr) };
    const auto fontHandle{ GetStockObject(DEFAULT_GUI_FONT) };
    LOGFONT logFont{};
    GetObject(fontHandle, sizeof(LOGFONT), &logFont);

    logFont.lfHeight = 200;

    const auto newFontHandle{ CreateFontIndirect(&logFont) };
    SelectObject(hDC, newFontHandle);

    const std::string message{ "Hello World!" };

    while (true) {
        RECT rect{};
        DrawTextA(hDC, message.c_str(),
                -1, &rect, DT_CALCRECT);

        DrawTextA(hDC, message.c_str(),
            -1, &rect, DT_SINGLELINE | DT_NOCLIP);

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return 0;
}
