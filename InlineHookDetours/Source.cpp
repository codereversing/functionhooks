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

#include <detours/detours.h>

using HookDisplayMessageOnIntervalTrampolinePtr = void(__stdcall*)(const std::string& message);
static HookDisplayMessageOnIntervalTrampolinePtr HookDisplayMessageOnIntervalTrampoline{};

void HookDisplayMessageOnInterval(const std::string& message) {

    std::cout << "HookDisplayMessageOnInterval function called!"
        << std::endl;
    HookDisplayMessageOnIntervalTrampoline("Hooked Hello World!");
}

void DisplayMessageOnInterval(const std::string& message) {

    const auto currentTime{ std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now()) };

    std::cout << std::format("{} @ {}",
        message, std::ctime(&currentTime)) << std::endl;

}

template <typename Trampoline>
void InstallInlineHook(void* targetAddress, void* const hookAddress,
    const Trampoline*& trampolineAddress) {

    DetourTransactionBegin();

    DetourUpdateThread(GetCurrentThread());
    PDETOUR_TRAMPOLINE detourTrampolineAddress{};
    DetourAttachEx(&(static_cast<void*&>(targetAddress)),
        static_cast<void *>(hookAddress),
        &detourTrampolineAddress, nullptr, nullptr);
    trampolineAddress = reinterpret_cast<Trampoline*>(detourTrampolineAddress);
    // Add any additional hooks here

    DetourTransactionCommit();
}

int main(int argc, char* argv[]) {

    InstallInlineHook(DisplayMessageOnInterval, HookDisplayMessageOnInterval,
        HookDisplayMessageOnIntervalTrampoline);

    while (true) {
        DisplayMessageOnInterval("Hello World!");
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    return 0;
}