#pragma once
#include <string>
#include <vector>
#include <mutex>

namespace PrettyPrint
{
    enum class PrintType : uint8_t
    {
        ENUM_INFO       = 0u,
        ENUM_WARNING    = 1u,
        ENUM_ERROR      = 2u,
        ENUM_DEBUG      = 3u
    };

    static std::mutex io_mutex;
    static std::vector<std::string> print_formats = {
        "\e[97;1m[\e[32m   INFO\e[97m]:  \e[0m",
        "\e[97;1m[\e[33mWARNING\e[97m]:  \e[0m",
        "\e[97;1m[\e[31m  ERROR\e[97m]:  \e[0m",
        "\e[97;1m[\e[36m  DEBUG\e[97m]:  \e[0m",
    };

    template <typename... Args>
    void RawPrint(const PrintType print_type, const char* format,
                    Args const & ... args) noexcept
    {
        auto type = static_cast<std::underlying_type<PrintType>::type>(print_type);

        if(type > 0x03u)
            return;

        io_mutex.lock();
        printf("%s", print_formats[type].c_str());
        printf(format, args...);
        printf("\n");
        io_mutex.unlock();
    }

    template <typename... Args>
    void PrintInfo(const char* format, Args const & ... args) noexcept
    {
        RawPrint(PrintType::ENUM_INFO, format, args...);
    }

    template <typename... Args>
    void PrintWarning(const char* format, Args const & ... args) noexcept
    {
        RawPrint(PrintType::ENUM_WARNING, format, args...);
    }

    template <typename... Args>
    void PrintError(const char* format, Args const & ... args) noexcept
    {
        RawPrint(PrintType::ENUM_ERROR, format, args...);
    }

    template <typename... Args>
    void PrintDebug(const char* format, Args const & ... args) noexcept
    {
        RawPrint(PrintType::ENUM_DEBUG, format, args...);
    }
}