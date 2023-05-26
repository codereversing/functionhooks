#include <Windows.h>

#include <iostream>
#include <format>
#include <typeinfo>

using NamePtr = void(__stdcall*)(void* const thisPointer);
static NamePtr OriginalName{};

void HookName(void* const thisPointer) {
    std::cout << "Hooked Name!" << std::endl;
    OriginalName(thisPointer);
}

class BaseClass {
public:
    virtual ~BaseClass() = default;

    virtual void Hello() const {
        std::cout << "Hello" << std::endl;
    }

    virtual void Name() const {
        std::cout << "Base" << std::endl;
    }

    virtual void Order() const {
        std::cout << "0" << std::endl;
    }
};

class DerivedClass : public BaseClass {
public:
    void Name() const override {
        std::cout << "Derived" << std::endl;
    }

    void Order() const override {
        std::cout << "1" << std::endl;
    }
};

#define PrintErrorAndExit(functionName) \
    PrintErrorWithLineAndExit(functionName, __LINE__)

void PrintErrorWithLineAndExit(const std::string& functionName, const size_t line) {

    std::cerr << std::format("{}@{} failed with 0x{:X}",
        functionName, line, GetLastError()) << std::endl;

    std::exit(-1);
}

DWORD ChangeMemoryPermissions(void* const address,
    const size_t size, const DWORD protections) {

    DWORD oldProtections{};
    auto result{ VirtualProtect(address, size,
        protections, &oldProtections) };
    if (!result) {
        PrintErrorAndExit("VirtualProtect");
    }

    return oldProtections;
}

void OverwriteVTablePointer(void** const vtableBaseAddress,
    const size_t index, const void* const hookAddress) {

    auto oldProtections{ ChangeMemoryPermissions(&vtableBaseAddress[index],
        sizeof(void*), PAGE_EXECUTE_READWRITE) };
    std::memcpy(&vtableBaseAddress[index], &hookAddress, sizeof(void*));
    ChangeMemoryPermissions(&vtableBaseAddress[index],
        sizeof(void*), oldProtections);
}

int main(int argc, char* argv[]) {
    
    BaseClass* base{ new BaseClass{} };
    BaseClass* derived{ new DerivedClass{} };

    // Prints out "Base"
    base->Name();

    // Prints out "Derived"
    derived->Name();

    std::cout << std::format("Base type equals derived type? {}",
        (typeid(base) == typeid(derived))) << std::endl;

    auto** vtableDerivedBaseAddress{ reinterpret_cast<void**>(
        *reinterpret_cast<void**>(derived))};

    for (int i{}; i < 4; i++) {
        const auto* const vtableEntry{ vtableDerivedBaseAddress[i] };
        std::cout << std::format("{}: 0x{:X}",  i,
            reinterpret_cast<size_t>(vtableEntry)) << std::endl;
    }

    std::cout << "Performing function hook on derived instance"
        << std::endl;

    OriginalName = reinterpret_cast<NamePtr>(vtableDerivedBaseAddress[2]);

    std::cout << "Calling Name" << std::endl;
    derived->Name();

    OverwriteVTablePointer(vtableDerivedBaseAddress, 2, HookName);

    std::cout << "Calling Name after hook was installed" << std::endl;
    derived->Name();

    return 0;
}