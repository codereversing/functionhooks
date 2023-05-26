#pragma comment(lib, "Dbghelp.lib")

#include <Windows.h>

#include <dbghelp.h>

#include <algorithm>
#include <format>
#include <iostream>
#include <string>
#include <type_traits>

using MessageBoxAPtr = int(__stdcall*)(HWND, LPCSTR, LPCSTR, UINT);
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

DWORD ChangeMemoryPermissions(void* const address, const size_t size, const DWORD protections) {

    DWORD oldProtections{};
    auto result{ VirtualProtect(address, size, protections, &oldProtections) };
    if (!result) {
        PrintErrorAndExit("VirtualProtect");
    }

    return oldProtections;
}

IMAGE_IMPORT_DESCRIPTOR* GetImportsDirectory(void* const moduleBaseAddress) {
    
    ULONG size{};
    auto* importsDirectoryBaseAddress{ ImageDirectoryEntryToData(
        moduleBaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size) };

    return reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        importsDirectoryBaseAddress);
}

IMAGE_THUNK_DATA* GetIATEntryByName(void* const moduleBaseAddress,
    const std::string& targetModuleName,
    const std::string& targetFunctionName) {

    auto* importsDirectory{
        GetImportsDirectory(moduleBaseAddress) };
    if (importsDirectory == nullptr) {
        std::cerr << "Could not get base address of imports directory"
            << std::endl;
        return nullptr;
    }

    for (size_t index{}; importsDirectory[index].Characteristics != 0; index++) {

        auto moduleName{ std::string {
            RvaToPointer<char>(moduleBaseAddress,
            importsDirectory[index].Name) } };

        std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(),
            [](unsigned char letter) { return std::tolower(letter); });

        // Skip modules that are not the target module
        if (moduleName != targetModuleName)
            continue;

        auto* addressTableEntry{ RvaToPointer<IMAGE_THUNK_DATA>(
            moduleBaseAddress, importsDirectory[index].FirstThunk) };
        auto* nameTableEntry{ RvaToPointer<IMAGE_THUNK_DATA>(
            moduleBaseAddress, importsDirectory[index].OriginalFirstThunk) };

        for (; nameTableEntry->u1.Function != 0; nameTableEntry++, addressTableEntry++) {

            // Skip functions exported by ordinal
            if (nameTableEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                continue;
            }

            auto* importedFunction{ RvaToPointer<IMAGE_IMPORT_BY_NAME>(
                moduleBaseAddress, nameTableEntry->u1.AddressOfData) };

            auto importedFunctionName{ std::string { 
                importedFunction->Name } };
            if (importedFunctionName == targetFunctionName) {
                return addressTableEntry;
            }
        }
    }

    return nullptr;
}

template <typename OriginalFunctionPtr>
void InstallIATHook(const std::string& targetModuleName,
    const std::string& targetFunctionName, void* const hookAddress,
    OriginalFunctionPtr& originalFunction) {

    auto* const moduleBaseAddress{ GetModuleHandle(nullptr) };
    auto* const iatEntry{ GetIATEntryByName(moduleBaseAddress,
        targetModuleName, targetFunctionName) };
    if (iatEntry == nullptr) {
        std::cerr << std::format("Import address table entry "
            "for {}:{} not found", targetModuleName, targetFunctionName)
            << std::endl;
        return;
    }

    originalFunction = reinterpret_cast<OriginalFunctionPtr>(
        iatEntry->u1.Function);

    const auto oldProtections{ ChangeMemoryPermissions(iatEntry,
        sizeof(IMAGE_THUNK_DATA), PAGE_EXECUTE_READWRITE) };
    iatEntry->u1.Function = reinterpret_cast<ULONGLONG>(hookAddress);
    ChangeMemoryPermissions(iatEntry, sizeof(IMAGE_THUNK_DATA), oldProtections);
}

int main(int argc, char* argv[]) {

    MessageBoxA(nullptr, "Hello World!", nullptr, 0);

    InstallIATHook<MessageBoxAPtr>("user32.dll", "MessageBoxA",
        HookMessageBoxA, OriginalMessageBoxA);

    MessageBoxA(nullptr, "Hello World!", nullptr, 0);

    return 0;
}
