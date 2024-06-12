#include <iostream>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../ext/httplib.h"

#define CURL_STATICLIB
#include "../ext/curl/curl.h"

#include "../ext/zlib/zlib.h"

#define myprint(stream) std::cout << stream << std::endl
#define end(status) do { myprint("# TMFWSI is shutting down... Status: " << (status? "FAIL" : "OK")); \
        X509_free(x509); EVP_PKEY_free(pkey); curl_easy_cleanup(g::curl); return status; } while (false) \

#define TMFWSI "TrackMania Forever Web Services Interceptor"
#define TMFWSI_VERSION "1.0"

// 127 :3c
#define ADDRESS "127.58.51.99"

#define HOSTS_PATH      "%SystemRoot%\\system32\\drivers\\etc\\"
#define HOSTS           HOSTS_PATH "hosts"
#define BACKUP_FILE     HOSTS_PATH "hosts.tmfwsi_bak"

namespace g
{
    CURL* curl = nullptr;

    httplib::SSLServer* server = nullptr;
    bool server_stopped = false;
}

namespace ws
{
    void authorize(const httplib::Request& request, httplib::Response& response)
    {
        myprint("# Got something.");

        //curl_easy_reset(g::curl);

        response.set_content(
            "<?xml version='1.0' encoding='utf-8' ?>"
            "<maniacode noconfirmation=\"1\">"
            "<show_message><message>meow :3</message></show_message>"
            "</maniacode>", "text/plain");

        //curl_easy_setopt(g::curl, CURLOPT_URL, );
    }
}

int __stdcall handle_console(unsigned long ctrl)
{
    if (!g::server_stopped && (ctrl == CTRL_C_EVENT || ctrl == CTRL_CLOSE_EVENT))
    {
        g::server_stopped = true;
        myprint("# Close or CTRL+C event received - stopping server...");
        g::server->stop();
        return 1;
    }

    return 0;
}

void handle_errors()
{
    unsigned long e = 0L;

    for (int i = 1; e = ERR_get_error(); i++)
    {
        auto error = ERR_error_string(e, nullptr);
        auto lib = ERR_lib_error_string(e);
        auto reason = ERR_reason_error_string(e);

        myprint("# " << i << ". [" << e << "] " << error << " (lib: " << lib << ") (reason: " << reason << ")");
    }
}

void hosts_help()
{
    myprint("# -----");
    myprint("# To manually modify your '" HOSTS "' file, add the following line using a text editor, without the quotes:");
    myprint("# '" ADDRESS " ws.trackmania.com'");
    myprint("# This will redirect all traffic directed towards 'ws.trackmania.com' to this local address - it is required for TMFWSI to function properly.");
    myprint("# However, if this entry is left in the 'hosts' file and TMFWSI is not running, all traffic to 'ws.trackmania.com' will effectively be 'blocked'.");
    myprint("# TMFWSI attempts to automate this process - if successful, it will modify the 'hosts' file accordingly on startup and on application shutdown.");
    myprint("# Please note that, should you decide to add this entry manually, it will be detected by TMFWSI on startup and will not be automatically removed.");
    myprint("# -----");
}

int main()
{
    SetConsoleTitleA(TMFWSI " " TMFWSI_VERSION);

    myprint("# -----");
    myprint("# " TMFWSI " " TMFWSI_VERSION " by brokenphilip");
    myprint("# Compiled with 'cURL " << curl_version_info(CURLVERSION_NOW)->version << "', '" OPENSSL_VERSION_TEXT "' and 'zlib " ZLIB_VERSION "'.");
    myprint("# For more information and troubleshooting, please visit: https://github.com/brokenphilip/TMFWSI");
    myprint("# -----");

    g::curl = curl_easy_init();
    if (!g::curl)
    {
        myprint("# Failed to initialize cURL!");
        return 1;
    }

    myprint("# Generating SSL certificate...");

    auto pkey = EVP_RSA_gen(2048);
    if (!pkey)
    {
        myprint("# Error: Failed to generate RSA key pair!");

        myprint("# TMFWSI is shutting down... Status: FAIL");
        curl_easy_cleanup(g::curl);
        return 1;
    }

    auto x509 = X509_new();
    if (!x509)
    {
        myprint("# Error: Failed to generate X509 certificate structure! The following errors occurred:");
        handle_errors();

        myprint("# TMFWSI is shutting down... Status: FAIL");
        EVP_PKEY_free(pkey);
        curl_easy_cleanup(g::curl);
        return 1;
    }

    // Set our certificate's serial number to 1 (default is 0, but sometimes it can be refused?)
    if (!ASN1_INTEGER_set(X509_get_serialNumber(x509), 1))
    {
        myprint("# Error: Failed to set the certificate's serial number!");
        end(1);
    }

    // Our certificate starts now and lasts for a year (which is the maximum as of September 1st, 2020)
    constexpr long one_year = 60L /* seconds */ * 60L /* minutes */ * 24L /* hours */ * 365L /* days */;
    if (!X509_gmtime_adj(X509_get_notBefore(x509), 0))
    {
        myprint("# Error: Failed to set the certificate's begin date!");
        end(1);
    }
    if (!X509_gmtime_adj(X509_get_notAfter(x509), one_year))
    {
        myprint("# Error: Failed to set the certificate's end date!");
        end(1);
    }

    if (!X509_set_pubkey(x509, pkey))
    {
        myprint("# Error: Failed to set the certificate's public key!");
        end(1);
    }

    auto name = X509_get_subject_name(x509);
    if (!X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"RS", -1, -1, 0))
    {
        myprint("# Error: Failed to set the certificate's country!");
        end(1);
    }
    if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"brokenphilip", -1, -1, 0))
    {
        myprint("# Error: Failed to set the certificate's organization!");
        end(1);
    }
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)TMFWSI, -1, -1, 0))
    {
        myprint("# Error: Failed to set the certificate's common name!");
        end(1);
    }

    if (!X509_set_issuer_name(x509, name))
    {
        myprint("# Error: Failed to set the certificate's issuer!");
        end(1);
    }

    if (!X509_sign(x509, pkey, EVP_sha1()))
    {
        myprint("# Error: Failed to sign the certificate!");
        end(1);
    }

    myprint("# SSL certificate generated.");

    /*
    myprint("# Checking 'hosts' file for existing entries of 'ws.trackmania.com'...");

    if (found_ours)
    {
        myprint("# Note: Found an existing entry which matches our address " ADDRESS " - will leave as-is on application shutdown.");
        myprint("# It will be briefly removed and re-added after fetching the website's IP address.");
    }
    else if (found_elses)
    {
        myprint("# Error: Found an existing entry, but it doesn't match our address " ADDRESS "!");
        myprint("# Either remove the entry, or manually modify it by following the steps below.");
        hosts_help();
        end(1);
    }

    myprint("# 'Hosts' file checked - no existing entries.");

    myprint("# Fetching IP address of 'ws.trackmania.com'...");

    myprint("# Fetched: '" << ip << "'.");

    myprint("# Backing up the 'hosts' file...");

    if (backup_created)
    {
        myprint("# A backup file '" BACKUP_FILE "' has been created.");
    }
    else
    {
        myprint("# Warning: failed to create the '" BACKUP_FILE "' backup file!");
    }

    myprint("# Modifying 'hosts' file...");

    if (modified)
    {
        if (found_ours)
        {
            myprint("# 'Hosts' file modified - re-added previous entry.");
        }
        else
        {
            myprint("# 'Hosts' file modified - the change will be reverted on application shutdown.");
        }
    }
    else
    {
        myprint("# Error: Unable to modify the hosts file!");
        // get error
        myprint("# Either launch TMFWSI as admin, end conflicting programs, restart your machine, or manually modify the 'hosts' file by following the steps below.");
        hosts_help();
        end(1);
    }
    */

    myprint("# Starting SSL server...");
    g::server = new httplib::SSLServer(x509, pkey);
    SetConsoleCtrlHandler(&handle_console, 1);

    if (!g::server->bind_to_port(ADDRESS, 443))
    {
        myprint("# Error: Failed to bind to address " ADDRESS ":443 - make sure it is not in use!");

        SetConsoleCtrlHandler(&handle_console, 0);
        delete g::server;
        end(1);
    }

    g::server->Get("/oauth2/authorize/", ws::authorize);

    myprint("# SSL Server started - listening to " ADDRESS ":443...");

    int status = g::server->listen_after_bind() ? 0 : 1;
    if (!status)
    {
        if (g::server_stopped)
        {
            myprint("# Server has been stopped.");
            status = 0;
        }
        else
        {
            myprint("# Error: An error occurred while listening!");
        }
    }

    SetConsoleCtrlHandler(&handle_console, 0);
    delete g::server;

    /*
    myprint("# Reverting 'hosts' file...");

    if (reverted)
    {
        myprint("# 'Hosts' file reverted.");
    }
    else
    {
        myprint("# Warning: failed to revert '" HOSTS "' file!");
        // error
        myprint("Restore from the backup file '" BACKUP_FILE "' if present, or, ideally, remove the following entry:");
        myprint("# '" ADDRESS " ws.trackmania.com'");
        myprint("# It's safe to leave this entry in, but traffic to 'ws.trackmania.com' will be blocked if TMFWSI is not running, and it will NOT be removed on startup.");
    }
    
    */
    end(status);
}

