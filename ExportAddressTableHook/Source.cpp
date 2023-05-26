#pragma comment(lib, "Dbghelp.lib")

#include <Windows.h>

#include <dbghelp.h>
#include <Psapi.h>

#include <array>
#include <cstring>
#include <format>
#include <iostream>
#include <string>
#include <type_traits>

using MessageBoxAPtr = int(__stdcall*)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
static MessageBoxAPtr OriginalMessageBoxA{};

int HookMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    return OriginalMessageBoxA(hWnd, "Hooked Hello World!", lpCaption, uType);
}

#define PrintErrorAndExit(functionName) \
    PrintErrorWithLineAndExit(functionName, __LINE__)

void PrintErrorWithLineAndExit(const std::string& functionName, const size_t line) {

    std::cerr << std::format("{}@{} failed with {:X}",
        functionName, line, GetLastError()) << std::endl;

    std::exit(-1);
}

template <typename T, std::enable_if_t<!std::is_pointer_v<T>, bool> = false>
T* RvaToPointer(const void* const baseAddress, const size_t offset) {

    return reinterpret_cast<std::add_pointer<T>::type>(
        reinterpret_cast<DWORD_PTR>(baseAddress) +
        offset);
}

DWORD_PTR PointerToRva(const void* const baseAddress, const void* const offset) {

    return reinterpret_cast<DWORD_PTR>(baseAddress) -
        reinterpret_cast<DWORD_PTR>(offset);
}

DWORD ChangeMemoryPermissions(void* const address, const size_t size, const DWORD protections) {

    DWORD oldProtections{};
    auto result{ VirtualProtect(address, size, protections, &oldProtections) };
    if (!result) {
        PrintErrorAndExit("VirtualProtect");
    }

    return oldProtections;
}

IMAGE_EXPORT_DIRECTORY* GetExportDirectory(void* const moduleBaseAddress) {

    ULONG size{};
    auto* exportDirectoryAddress{ ImageDirectoryEntryToData(
        moduleBaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size) };

    return reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        exportDirectoryAddress);
}

DWORD* GetEATEntryByName(void* const moduleBaseAddress,
    const std::string& targetFunctionName) {

    auto* exportDirectory {
        GetExportDirectory(moduleBaseAddress) };
    if (exportDirectory == nullptr) {
        std::cerr << "Could not get base address of exports directory"
            << std::endl;
        return nullptr;
    }

    auto* const addressOffsets{ RvaToPointer<DWORD>(moduleBaseAddress,
        exportDirectory->AddressOfFunctions) };
    const auto* const nameOffsets{ RvaToPointer<DWORD>(moduleBaseAddress,
        exportDirectory->AddressOfNames) };
    const auto* const ordinalOffsets{ RvaToPointer<WORD>(moduleBaseAddress,
        exportDirectory->AddressOfNameOrdinals) };

    for (size_t index{}; index < exportDirectory->NumberOfFunctions; index++) {

        const auto exportedFunctionName{ std::string {
            RvaToPointer<char>(moduleBaseAddress,  nameOffsets[index]) } };

        if (targetFunctionName == exportedFunctionName) {
            return &addressOffsets[ordinalOffsets[index]];
        }
    }

    return nullptr;
}

std::array<unsigned char, 12> CreateJumpBytes(const void* const destinationAddress) {

    std::array<unsigned char, 12> jumpBytes{ {
        /*mov rax, 0xCCCCCCCCCCCCCCCC*/
        0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,

        /*jmp rax*/
        0xFF, 0xE0
    } };

    // Replace placeholder value with the actual hook address
    const auto address{ reinterpret_cast<size_t>(destinationAddress) };
    std::memcpy(&jumpBytes[2], &address, sizeof(void*));

    return jumpBytes;
}

void* AllocateClosestAfterAddress(void* const moduleAddress, const size_t size) {

    MODULEINFO moduleInfo{};
    const auto result{ GetModuleInformation(GetCurrentProcess(), 
        static_cast<HMODULE>(moduleAddress), &moduleInfo, sizeof(MODULEINFO)) };
    if (!result) {
        PrintErrorAndExit("GetModuleInformation");
    }

    auto allocAddress{ reinterpret_cast<DWORD_PTR>(
        moduleInfo.lpBaseOfDll) + moduleInfo.SizeOfImage };

    void* allocatedAddress{};
    constexpr size_t ALLOC_ALIGNMENT = 0x10000;
    do {
        allocatedAddress = VirtualAlloc(reinterpret_cast<void*>(allocAddress),
            size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        allocAddress += ALLOC_ALIGNMENT;
    } while (allocatedAddress == nullptr);

    return allocatedAddress;
}

template <typename OriginalFunctionPtr>
void InstallEATHook(const std::string& targetModuleName,
    const std::string& targetFunctionName, void* const hookAddress,
    OriginalFunctionPtr& originalFunction) {

    auto* moduleBaseAddress{ GetModuleHandleA(targetModuleName.c_str()) };
    if (moduleBaseAddress == nullptr) {
        moduleBaseAddress = LoadLibraryA(targetModuleName.c_str());
    }

    auto* const eatEntryRva{ GetEATEntryByName(moduleBaseAddress, targetFunctionName) };
    if (eatEntryRva == nullptr) {
        std::cerr << std::format("Export address table entry "
            "for {}:{} not found", targetModuleName, targetFunctionName)
            << std::endl;
        return;
    }

    originalFunction = reinterpret_cast<OriginalFunctionPtr>(
        RvaToPointer<void>(moduleBaseAddress, *eatEntryRva));

    const auto jumpBytes{ CreateJumpBytes(hookAddress) };
    auto* const jumpStub{ AllocateClosestAfterAddress(
        moduleBaseAddress, jumpBytes.size()) };
    if (jumpStub == nullptr) {
        PrintErrorAndExit("VirtualAlloc");
    }

    std::memcpy(jumpStub, jumpBytes.data(), jumpBytes.size());

    const auto oldProtections{ ChangeMemoryPermissions(
        eatEntryRva, sizeof(void*), PAGE_EXECUTE_READWRITE) };
    *eatEntryRva = static_cast<DWORD>(PointerToRva(jumpStub, moduleBaseAddress));
    ChangeMemoryPermissions(eatEntryRva, sizeof(void*), oldProtections);
}

int main(int argc, char* argv[]) {

    MessageBoxAPtr UnusedMessageBoxAOriginalFncPtr =
        reinterpret_cast<MessageBoxAPtr>(
            GetProcAddress(GetModuleHandleA("user32.dll"),
                "MessageBoxA"));

    InstallEATHook("user32.dll", "MessageBoxA",
        HookMessageBoxA, OriginalMessageBoxA);

    MessageBoxAPtr MessageBoxAFnc =
        reinterpret_cast<MessageBoxAPtr>(
            GetProcAddress(GetModuleHandleA("user32.dll"),
                "MessageBoxA"));

    if (MessageBoxAFnc == nullptr) {
        std::cerr << "Could not find MessageBoxA export"
            << std::endl;
        return -1;
    }

    MessageBoxAFnc(nullptr, "Hello World!", nullptr, 0);

    return 0;
}