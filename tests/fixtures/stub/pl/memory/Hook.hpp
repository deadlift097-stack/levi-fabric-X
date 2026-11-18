// Same declarations as preloader-android 0.2.2 pl/memory/Hook.hpp (without PL_EXPORT).
#pragma once
#include <utility>
namespace pl::memory {
using FuncPtr = void *;
enum class HookPriority : int { Highest = 0, High = 100, Normal = 200, Low = 300, Lowest = 400 };
int hook(FuncPtr target, FuncPtr detour, FuncPtr *originalFunc, HookPriority priority = HookPriority::Normal);
bool unhook(FuncPtr target, FuncPtr detour);
} // namespace pl::memory
