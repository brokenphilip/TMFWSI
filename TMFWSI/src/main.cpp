#include "tmfwsi.h"

#define MAIN_PROC(func) do { auto result = func; if (result) return tmfwsi::main::cleanup(result); } while (false)

int main()
{
    auto cmdline = GetCommandLineA();
    if (strstr(cmdline, "-do-hosts"))
    {
        return tmfwsi::main_do_hosts();
    }
    else if (strstr(cmdline, "-undo-hosts"))
    {
        return tmfwsi::main_undo_hosts();
    }

    // Only if we're not in debug mode already (at compile time)
    if (!tmfwsi::debug)
    {
        tmfwsi::debug = strstr(cmdline, "-debug");
    }

    MAIN_PROC(tmfwsi::main::init_console());
    MAIN_PROC(tmfwsi::main::init_mutex());
    MAIN_PROC(tmfwsi::main::init_resource());
    MAIN_PROC(tmfwsi::main::init_curl());

    if (!strstr(cmdline, "-no-update"))
    {
        MAIN_PROC(tmfwsi::main::update_check());
    }
    else
    {
        tmfwsi::log(tmfwsi::log_level::warn, "Skipping update check due to launch parameter - please check for important TMFWSI updates manually on GitHub.");
    }

    MAIN_PROC(tmfwsi::main::get_tmfws_ip());
    MAIN_PROC(tmfwsi::main::generate_ssl_certificate());

    bool hosts_enabled = !strstr(cmdline, "-no-hosts");
    if (hosts_enabled)
    {
        MAIN_PROC(tmfwsi::main::do_hosts());
    }
    else
    {
        tmfwsi::log(tmfwsi::log_level::warn, "Skipping hosts file modification due to launch parameter.");
    }

    MAIN_PROC(tmfwsi::main::ssl_server::loop());

    if (hosts_enabled)
    {
        MAIN_PROC(tmfwsi::main::undo_hosts());
    }

    return tmfwsi::main::cleanup(0);
}