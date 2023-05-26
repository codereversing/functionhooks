// Disable warning for usage of ctime
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>

#include <array>
#include <chrono>
#include <cstring>
#include <ctime>
#include <format>
#include <iostream>
#include <iterator>
#include <string>
#include <thread>

// Trampoline pointer declaration
using HookDisplayMessageOnIntervalTrampolinePtr = void (__stdcall*)(
    const std::string& message);
static HookDisplayMessageOnIntervalTrampolinePtr HookDisplayMessageOnIntervalTrampoline{};

void HookDisplayMessageOnInterval(const std::string& message) {

    std::cout << "HookDisplayMessageOnInterval function called!"
        << std::endl;
    HookDisplayMessageOnIntervalTrampoline("Hooked Hello World");
}

#define PrintErrorAndExit(functionName) \
    PrintErrorWithLineAndExit(functionName, __LINE__)

void PrintErrorWithLineAndExit(const std::string& functionName, const size_t line) {

    std::cerr << std::format("{}@{} failed with {:X}",
        functionName, line, GetLastError()) << std::endl;

    std::exit(-1);
}

void DisplayMessageOnInterval(const std::string& message) {

    const auto currentTime{ std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now()) };

    std::cout << std::format("{} @ {}",
        message, std::ctime(&currentTime)) << std::endl;
}

DWORD ChangeMemoryPermissions(void* const address, const size_t size, const DWORD protections) {

    DWORD oldProtections{};
    auto result{ VirtualProtect(address, size, protections, &oldProtections) };
    if (!result) {
        PrintErrorAndExit("VirtualProtect");
    }

    return oldProtections;
}

std::array<unsigned char, 12> CreateJumpBytes(const void* const destinationAddress) {

    std::array<unsigned char, 12> jumpBytes{ {
            /*mov rax, 0xAABBCCDD11223344*/
            0x48, 0xB8, 0x44, 0x33, 0x22, 0x11, 0xDD, 0xCC, 0xBB, 0xAA,

            /*jmp rax*/
            0xFF, 0xE0
        } };

    // Replace placeholder value with the actual hook address
    const auto address{ reinterpret_cast<size_t>(destinationAddress) };
    std::memcpy(&jumpBytes[2], &address, sizeof(void*));

    return jumpBytes;
}

void* CreateTrampoline(void* const targetAddress, const size_t size) {

    const auto jumpBack{ CreateJumpBytes(
        reinterpret_cast<unsigned char*>(targetAddress) + size) };
    
    const auto trampolineStub{ VirtualAlloc(nullptr, size + jumpBack.size(),
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) };
    if (trampolineStub == nullptr) {
        PrintErrorAndExit("VirtualAlloc");
    }

    std::memcpy(trampolineStub, targetAddress, size);
    std::memcpy(&reinterpret_cast<unsigned char *>(trampolineStub)[size],
        jumpBack.data(), jumpBack.size());

    return trampolineStub;
}

template <typename Trampoline>
void InstallInlineHook(void* const targetAddress, const void* const hookAddress,
    const Trampoline*& trampolineAddress) {

    // If you are seeing crashes, check the overwritten instruction
    // length below with what your compiler generated.
    trampolineAddress = reinterpret_cast<Trampoline*>(
        CreateTrampoline(targetAddress, 19));

    const auto hookBytes{ CreateJumpBytes(hookAddress) };
    const auto oldProtections{ ChangeMemoryPermissions(
        targetAddress, hookBytes.size(), PAGE_EXECUTE_READWRITE) };
    std::memcpy(targetAddress, hookBytes.data(), hookBytes.size());
    ChangeMemoryPermissions(targetAddress, hookBytes.size(), oldProtections);

    FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
}

int main(int argc, char* argv[]) {

    DisplayMessageOnInterval("Hello World!");

    InstallInlineHook(DisplayMessageOnInterval,
        HookDisplayMessageOnInterval, HookDisplayMessageOnIntervalTrampoline);

    while (true) {
        DisplayMessageOnInterval("Hello World!");
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    return 0;
}