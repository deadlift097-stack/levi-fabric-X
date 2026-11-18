// Host stand-in mirroring the parts of the preloader's <pl/Mod.hpp> that generated code uses (real SDK: v0.2.2).
#pragma once
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>
namespace pl::log {
struct Logger {
    std::vector<std::string> lines;
    template <class... A> void info(std::string_view f, A &&...) { lines.push_back("I " + std::string(f)); }
    template <class... A> void debug(std::string_view f, A &&...) { lines.push_back("D " + std::string(f)); }
    template <class... A> void warn(std::string_view f, A &&...) { lines.push_back("W " + std::string(f)); }
    template <class... A> void error(std::string_view f, A &&...) { lines.push_back("E " + std::string(f)); }
};
} // namespace pl::log
namespace pl::mod {
struct NativeMod {
    pl::log::Logger log;
    pl::log::Logger &getLogger() { return log; }
    static NativeMod *current() { static NativeMod m; return &m; }
};
} // namespace pl::mod
namespace ll::mod { using NativeMod = ::pl::mod::NativeMod; }
