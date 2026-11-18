// Same declaration as preloader-android 0.2.2 pl/memory/Vtable.hpp (without PL_EXPORT).
#pragma once
#include <cstddef>
#include <cstdint>
#include <string_view>
namespace pl::memory {
uintptr_t resolveVtableFunction(std::string_view typeInfoName, size_t slot, std::string_view moduleName);
}
