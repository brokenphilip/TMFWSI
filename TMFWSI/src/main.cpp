#include <iostream>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../ext/httplib.h"

#define CURL_STATICLIB
#include "../ext/curl/curl.h"

#include "../ext/zlib/zlib.h"

#define myprint(stream) std::cout << stream << std::endl
#define end(status) do { myprint("# TMFWSI is shutting down... Status: " << (status? "FAIL" : "OK")); \
        X509_free(x509); EVP_PKEY_free(pkey); curl_easy_cleanup(curl); return status; } while (false) \

#define TMFWSI "TrackMania Forever Web Services Interceptor"
#define TMFWSI_VERSION "1.0"

// 127 :3c
#define ADDRESS "127.58.51.99"

#define HOSTS_PATH      "%SystemRoot%\\system32\\drivers\\etc\\"
#define HOSTS           HOSTS_PATH "hosts"
#define BACKUP_FILE     HOSTS_PATH "hosts.tmfwsi_bak"

httplib::SSLServer* server = nullptr;
bool server_stopped = false;

int __stdcall handle_console(unsigned long ctrl)
{
    if (!server_stopped && (ctrl == CTRL_C_EVENT || ctrl == CTRL_CLOSE_EVENT))
    {
        server_stopped = true;
        myprint("# Close or CTRL+C event received - stopping server...");
        server->stop();
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

int main()
{
    myprint("# " TMFWSI " " TMFWSI_VERSION " by brokenphilip");
    myprint("# Compiled with 'cURL " << curl_version_info(CURLVERSION_NOW)->version << "', '" OPENSSL_VERSION_TEXT "' and 'zlib " ZLIB_VERSION "'.");

    auto curl = curl_easy_init();
    if (!curl)
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
        curl_easy_cleanup(curl);
        return 1;
    }

    auto x509 = X509_new();
    if (!x509)
    {
        myprint("# Error: Failed to generate X509 certificate structure! The following errors occurred:");
        handle_errors();
        myprint("# TMFWSI is shutting down... Status: FAIL");
        EVP_PKEY_free(pkey);
        curl_easy_cleanup(curl);
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
    myprint("# Modifying 'hosts' file...");

    myprint("# Note: Found an existing entry for 'ws.trackmania.com' which matches our address " ADDRESS " - will leave as-is on application shutdown.");

    if (1)
    {
        if (1)
        {
            myprint("# Error: Found an existing entry for 'ws.trackmania.com', but it doesn't match our address " ADDRESS "!");
            myprint("# Either remove the entry, or manually modify it by following the steps below.");
        }
        else
        {
            myprint("# Error: Unable to modify the hosts file!");
            myprint("# Either launch TMFWSI as admin, end conflicting programs, restart your machine, or manually modify the 'hosts' file by following the steps below.");
        }

        myprint("# -----");
        myprint("# To manually modify your '" HOSTS "' file, add the following line using a text editor, without the quotes:");
        myprint("# '" ADDRESS " ws.trackmania.com'");
        myprint("# This will redirect all traffic directed towards 'ws.trackmania.com' to this local address - it is required for TMFWSI to function properly.");
        myprint("# However, if this entry is left in the 'hosts' file and TMFWSI is not running, all traffic to 'ws.trackmania.com' will effectively be 'blocked'.");
        myprint("# TMFWSI attempts to automate this process - if successful, it will modify the 'hosts' file accordingly on startup and on application shutdown.");
        myprint("# Please note that, should you decide to add this entry manually, it will be detected by TMFWSI on startup and will not be automatically removed.");
        myprint("# -----");
        end(1);
    }

    if (1)
    {
        myprint("# 'Hosts' file modified - the change will be reverted on application shutdown.");

        myprint("# A backup file '" BACKUP_FILE "' has been created.");
        myprint("# Warning: failed to create the '" BACKUP_FILE "' backup file!");
    }
    */

    myprint("# Starting SSL server...");
    server = new httplib::SSLServer(x509, pkey);
    SetConsoleCtrlHandler(&handle_console, 1);

    server->Get("/oauth2/authorize/", [](const httplib::Request&, httplib::Response& res)
    {
        myprint("# Got something.");
        res.set_content(
            "<?xml version='1.0' encoding='utf-8' ?>"
            "<maniacode noconfirmation=\"1\">"
            "<show_message><message>meow :3</message></show_message>"
            "</maniacode>", "text/plain");
    });

    if (!server->bind_to_port(ADDRESS, 443))
    {
        myprint("# Error: Failed to bind to address " ADDRESS ":443 - make sure it is not in use!");
        SetConsoleCtrlHandler(&handle_console, 0);
        delete server;
        end(1);
    }

    myprint("# SSL Server started - listening to " ADDRESS ":443...");

    int status = server->listen_after_bind() ? 0 : 1;
    if (!status)
    {
        if (server_stopped)
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
    delete server;

    /*
    if (1)
    {
        myprint("# Reverting 'hosts' file...");

        if (1)
        {
            myprint("# Warning: failed to revert '" HOSTS "' file! Restore from the backup file '" BACKUP_FILE "' if present, or remove the following entry:");
            myprint("# '" ADDRESS " ws.trackmania.com'");
            myprint("# You may leave this entry in, but traffic to 'ws.trackmania.com' will be blocked if TMFWSI is not running, and it will NOT be removed on startup.");
        }

        myprint("# 'Hosts' file reverted.");
    }
    */
    end(status);
}

