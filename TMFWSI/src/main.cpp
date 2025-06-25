#include "tmfwsi.h"

#define MAIN_PROC(func) do { auto result = func; if (result) return tmfwsi::main::cleanup(result); } while (false)

int main()
{
    auto cmdline = GetCommandLineA();

    if (strstr(cmdline, "-undo-hosts"))
    {
        return tmfwsi::main_undo_hosts();
    }

    // Since main_do_hosts() needs to know the IP address, we must parse it here
    std::string cmdline_str = cmdline;
    constexpr auto ip_cmd = "-ip ";
    bool invalid_ip = false;
    std::string ip = "";
    
    auto i = cmdline_str.find(ip_cmd);
    if (i != std::string::npos)
    {
        std::string sub = cmdline_str.substr(i + std::char_traits<char>::length(ip_cmd));
        if (!sub.empty())
        {
            ip = sub.substr(0, sub.find(' '));
            if (!ip.empty())
            {
                std::regex r("^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$");
                if (std::regex_match(ip, r))
                {
                    tmfwsi::server_ip = ip;
                }
                else
                {
                    invalid_ip = true;
                }
            }
            else
            {
                invalid_ip = true;
            }
        }
        else
        {
            invalid_ip = true;
        }
    }

    if (strstr(cmdline, "-do-hosts"))
    {
        return tmfwsi::main_do_hosts();
    }

    using namespace tmfwsi::main;

    // Only if we're not in debug mode already (at compile time)
    if (!debug)
    {
        debug = strstr(cmdline, "-debug");
    }

    if (strstr(cmdline, "-logging"))
    {
        if (strstr(cmdline, "-logging verbose"))
        {
            logging = log_mode::verbose;
        }
        else
        {
            logging = log_mode::on;
        }
    }

    pause = !strstr(cmdline, "-no-pause");

    MAIN_PROC(init_console_and_logging());

    if (invalid_ip)
    {
        log(log_level::error, std::format("The IP you've entered, '{}', is invalid.", ip));
        return cleanup(1);
    }

    MAIN_PROC(init_mutex());
    MAIN_PROC(init_resource());
    MAIN_PROC(init_curl());

    if (!strstr(cmdline, "-no-update"))
    {
        MAIN_PROC(update_check());
    }
    else
    {
        log(log_level::warn, "Skipping update check due to launch parameter - please check for important TMFWSI updates manually on GitHub.");
    }

    MAIN_PROC(get_tmfws_ip());
    MAIN_PROC(generate_ssl_certificate());

    bool hosts_enabled = !strstr(cmdline, "-no-hosts");
    if (hosts_enabled)
    {
        MAIN_PROC(do_hosts());
    }
    else
    {
        log(log_level::warn, "Skipping hosts file modification due to launch parameter.");
    }

    MAIN_PROC(ssl_server::loop());

    if (hosts_enabled)
    {
        MAIN_PROC(undo_hosts());
    }

    return cleanup(0);
}