// Runs the generated Hooks.cpp + Resolve.cpp against a fake libminecraftpe.so (a file of that name, mmapped so that
// /proc/self/maps shows it) and a mocked preloader. Checks: guards, per-address trampolines, subclass overrides,
// SDK cross-check, unhook.  Layout is mirrored in tests/test_hooks_runtime.py (DB built there).
#include "mod/Hooks.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>
#include <pl/memory/Hook.hpp>
#include <pl/memory/Vtable.hpp>

struct Rec { void *target, *detour; void **orig; };
static std::vector<Rec> g_hooks;
static int g_unhooked = 0;
static uintptr_t g_sdk = 0;
static int origA(void *) { return 100; }
static int origB(void *) { return 200; }
static int origC(void *) { return 300; }
static void *g_origs[] = {(void *)&origA, (void *)&origB, (void *)&origC};

namespace pl::memory {
int hook(FuncPtr t, FuncPtr d, FuncPtr *o, HookPriority) {
    *o = g_origs[g_hooks.size() % 3]; g_hooks.push_back({t, d, o}); return 0;
}
bool unhook(FuncPtr, FuncPtr) { ++g_unhooked; return true; }
uintptr_t resolveVtableFunction(std::string_view, size_t, std::string_view) { return g_sdk; }
} // namespace pl::memory

static const uint32_t A[2] = {0x2A1F03E0u, 0xD65F03C0u};     // base Item::getAttackDamage
static const uint32_t B[2] = {0x11111111u, 0x22222222u};     // Sword override
static constexpr size_t SIZE = 0x8000, VT_BASE = 0x1000, VT_SWORD = 0x2000, VT_AXE = 0x2100, FA = 0x4000, FB = 0x4100;
static constexpr unsigned SLOT = 5;

static char *makeLib(uint32_t a0 = A[0]) {
    const char *path = "libminecraftpe.so";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0 && ftruncate(fd, SIZE) == 0);
    char *m = (char *)mmap(nullptr, SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    assert(m != MAP_FAILED);
    uint32_t a[2] = {a0, A[1]};
    std::memcpy(m + FA, a, 8); std::memcpy(m + FB, B, 8);
    uintptr_t fa = (uintptr_t)m + FA, fb = (uintptr_t)m + FB;
    std::memcpy(m + VT_BASE + 8 * SLOT, &fa, 8);
    std::memcpy(m + VT_SWORD + 8 * SLOT, &fb, 8);
    std::memcpy(m + VT_AXE + 8 * SLOT, &fb, 8);           // second subclass, same override -> must be de-duplicated
    return m;
}

int main() {
    auto &mod = *ll::mod::NativeMod::current();
    char *lib = makeLib();
    uintptr_t fa = (uintptr_t)lib + FA, fb = (uintptr_t)lib + FB;

    // 1. happy path: base + ONE de-duplicated subclass override
    g_sdk = fa;
    demo::hooks::installAll(mod);
    assert(g_hooks.size() == 2);
    assert((uintptr_t)g_hooks[0].target == fa && (uintptr_t)g_hooks[1].target == fb);
    // each address has its own detour that forwards to ITS OWN trampoline (+3 from the override body)
    auto d0 = (int (*)(void *))g_hooks[0].detour, d1 = (int (*)(void *))g_hooks[1].detour;
    assert(d0(nullptr) == 103 && d1(nullptr) == 203);
    assert(g_hooks[0].detour != g_hooks[1].detour);

    // 2. unhook releases everything and clears trampolines
    demo::hooks::uninstallAll(mod);
    assert(g_unhooked == 2);

    // 3. SDK RTTI resolver disagrees -> refuse to hook
    g_hooks.clear(); g_sdk = fa + 4;
    demo::hooks::installAll(mod);
    assert(g_hooks.empty());

    // 4. different game build (prologue differs) -> nothing hooked, no crash
    munmap(lib, SIZE);
    lib = makeLib(0xDEADBEEFu); g_sdk = 0;
    demo::hooks::installAll(mod);
    assert(g_hooks.empty());

    // 5. SDK cannot cross-check (returns 0) -> still hooks, with a debug line
    munmap(lib, SIZE);
    lib = makeLib(); g_sdk = 0;
    demo::hooks::installAll(mod);
    assert(g_hooks.size() == 2);
    demo::hooks::uninstallAll(mod);
    munmap(lib, SIZE); unlink("libminecraftpe.so");
    std::puts("hooks runtime ok");
}
