#include "tmfwsi.h"

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

    auto result = tmfwsi::main::init();
    if (result)
    {
        return tmfwsi::main::cleanup(result);
    }

    result = tmfwsi::main::generate_ssl_certificate();
    if (result)
    {
        return tmfwsi::main::cleanup(result);
    }

    bool hosts_enabled = !strstr(cmdline, "-no-hosts");
    if (hosts_enabled)
    {
        result = tmfwsi::main::do_hosts();
        if (result)
        {
            return tmfwsi::main::cleanup(result);
        }
    }

    result = tmfwsi::main::ssl_server::loop();
    if (result)
    {
        return tmfwsi::main::cleanup(result);
    }

    if (hosts_enabled)
    {
        result = tmfwsi::main::undo_hosts();
        if (result)
        {
            return tmfwsi::main::cleanup(result);
        }
    }

    return tmfwsi::main::cleanup(0);
}