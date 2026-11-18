#include <string>
#include "mod/Resolve.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>
using namespace demo::resolve;
int main() {
    // 1. maps parsing
    std::string maps =
        "7a00000000-7a00001000 r--p 00000000 fe:01 1 /data/app/x/lib/arm64/libminecraftpe.so\n"
        "7a00001000-7a00005000 r-xp 00001000 fe:01 1 /data/app/x/lib/arm64/libminecraftpe.so\n"
        "7a00005000-7a00006000 rw-p 00005000 fe:01 1 /data/app/x/lib/arm64/libminecraftpe.so\n"
        "7b00000000-7b00001000 r--p 00000000 fe:01 2 /system/lib64/libc.so\n";
    Module m = findModuleInMaps(maps, "libminecraftpe.so");
    assert(m.base == 0x7a00000000ull && m.end == 0x7a00006000ull);
    assert(findModuleInMaps(maps, "libnothere.so").base == 0);
    // lowest mapping with a non-zero offset (e.g. inside an APK) is rejected
    assert(findModuleInMaps("7a00001000-7a00005000 r-xp 00001000 fe:01 1 /x/libminecraftpe.so\n", "libminecraftpe.so").base == 0);
    // 2. real process maps: libc must be found
    Module c = findModule("libc.so.6");
    if (!c.base) c = findModule("libc.so");
    assert(c.base && c.end > c.base);
    // 3. virtualTarget over a fake module living in a heap buffer
    std::vector<uint8_t> buf(0x400, 0);
    Module f{reinterpret_cast<uintptr_t>(buf.data()), reinterpret_cast<uintptr_t>(buf.data()) + buf.size()};
    uint32_t code[2] = {0x2A1F03E0u, 0xD65F03C0u};
    std::memcpy(buf.data() + 0x100, code, 8);                   // "function" at rva 0x100
    uintptr_t fn = f.base + 0x100;
    std::memcpy(buf.data() + 0x200 + 8 * 3, &fn, 8);            // vtable at rva 0x200, slot 3 -> fn
    assert(virtualTarget(f, 0x200, 3, code, 2) == fn);          // match
    uint32_t wrong[2] = {0x2A1F03E0u, 0xD503201Fu};
    assert(virtualTarget(f, 0x200, 3, wrong, 2) == 0);          // prologue differs -> refused
    assert(virtualTarget(f, 0x200, 4, code, 2) == 0);           // slot 4 is null -> outside module
    assert(virtualTarget(f, 0x7000, 3, code, 2) == 0);          // slot outside module -> refused, no crash
    assert(virtualTarget(Module{}, 0x200, 3, code, 2) == 0);    // module not found
    std::puts("resolve tests ok");
}
