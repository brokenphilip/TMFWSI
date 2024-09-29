#include <iostream>
#include <filesystem>

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
#define DEFAULT_ADDRESS "127.58.51.99"

#define HOSTS_PATH      "%SystemRoot%\\system32\\drivers\\etc\\"
#define HOSTS           HOSTS_PATH "hosts"
#define BACKUP_FILE     HOSTS_PATH "hosts.tmfwsi_bak"

namespace g
{
    CURL* curl = nullptr;

    httplib::SSLServer* server = nullptr;
    bool server_stopped = false;
}

void handle_get(const httplib::Request& request, httplib::Response& response)
{
    // TODO: more detailed, optionally verbose, output
    myprint("# Request received...");

    // First, let's build our URL, making sure to include the query string
    bool first = true;
    std::string params;
    for (auto& it : request.params)
    {
        params += (first ? "?" : "&");
        params += it.first;
        params += "=";
        params += it.second;
        first = false;
    }

    // TODO: fetch IP dynamically, before hosts is set
    std::string url = "https://178.33.106.156" + request.path + params;
    curl_easy_setopt(g::curl, CURLOPT_URL, url.c_str());

    /////myprint("# URL: " << url);

    /////myprint("# HEADER START");

    // Next, fetch the request headers
    // User-Agent in particular is very important - for reference, TMF uses "GameBox" and MP uses "ManiaPlanet" for their in-game Manialink browsers
    // Authorization is also important, in case the Web Services API is used
    curl_slist* slist = nullptr;
    for (auto& it : request.headers)
    {
        std::string tag = it.first + ":" + it.second;
        curl_slist_append(slist, tag.c_str());

        /////std::cout << tag << std::endl;
    }
    if (slist)
    {
        curl_easy_setopt(g::curl, CURLOPT_HTTPHEADER, slist);
    }

    /////myprint("# HEADER END");

    // Do not check for certificates, as they're expired anyways (which is what we're trying to work around in the first place lol)
    curl_easy_setopt(g::curl, CURLOPT_SSL_VERIFYPEER, false);

    // Save the result for later
    std::string data;
    curl_easy_setopt(g::curl, CURLOPT_WRITEFUNCTION, +[](void* buffer, size_t size, size_t n_items, std::string* data)
    {
        data->append(static_cast<char*>(buffer), size * n_items);
        return size * n_items;
    });
    curl_easy_setopt(g::curl, CURLOPT_WRITEDATA, &data);

    CURLcode res = curl_easy_perform(g::curl);
    if (res)
    {
        myprint("# Error: " << curl_easy_strerror(res) << " (" << res << ")");
    }
    else
    {
        // Set the HTTP code
        curl_easy_getinfo(g::curl, CURLINFO_RESPONSE_CODE, &response.status);

        // Set the content to the result we saved earlier
        response.body = data;

        /////myprint("# DATA START");
        /////std::cout << data << std::endl;
        /////myprint("# DATA END");
        /////
        /////myprint("# HEADER START");

        // Set the headers
        curl_header* prev = nullptr;
        curl_header* header = nullptr;
        while ((header = curl_easy_nextheader(g::curl, CURLH_HEADER, 0, prev)))
        {
            /////std::cout << header->name << ":" << header->value << std::endl;

            response.set_header(header->name, header->value);
            prev = header;
        }

        /////myprint("# HEADER END");

        myprint("# Success!");
    }

    // Done :3
    if (slist)
    {
        curl_slist_free_all(slist);
    }
    curl_easy_reset(g::curl);
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

void handle_openssl_errors()
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

// TODO: is hosts_help obsolete?
void hosts_help()
{
    myprint("# -----");
    myprint("# To manually modify your '" HOSTS "' file, add the following line using a text editor, without the quotes:");
    myprint("# '" DEFAULT_ADDRESS " ws.trackmania.com'");
    myprint("# This will redirect all traffic directed towards 'ws.trackmania.com' to this local address - it is required for TMFWSI to function properly.");
    myprint("# However, if this entry is left in the 'hosts' file and TMFWSI is not running, all traffic to 'ws.trackmania.com' will effectively be 'blocked'.");
    myprint("# TMFWSI attempts to automate this process - if successful, it will modify the 'hosts' file accordingly on startup and on application shutdown.");
    myprint("# Please note that, should you decide to add this entry manually, it will be detected by TMFWSI on startup and will not be automatically removed.");
    myprint("# -----");
}

void demo_perms(std::filesystem::perms p)
{
    using std::filesystem::perms;
    auto show = [=](char op, perms perm)
    {
        std::cout << (perms::none == (perm & p) ? '-' : op);
    };
    show('r', perms::owner_read);
    show('w', perms::owner_write);
    show('x', perms::owner_exec);
    show('r', perms::group_read);
    show('w', perms::group_write);
    show('x', perms::group_exec);
    show('r', perms::others_read);
    show('w', perms::others_write);
    show('x', perms::others_exec);
    std::cout << '\n';
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
        myprint("# Error: Failed to initialize cURL!");

        myprint("# TMFWSI is shutting down... Status: FAIL");
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
        handle_openssl_errors();

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

    // TODO: CertAddCertificateContextToStore

    // TODO: check and modify hosts file
    //myprint("# 'hosts' file permissions: ");
    //demo_perms(std::filesystem::status(HOSTS).permissions());
    //myprint("# 'etc' folder permissions: ");
    //demo_perms(std::filesystem::status(HOSTS_PATH).permissions());

    myprint("# Starting SSL server...");
    g::server = new httplib::SSLServer(x509, pkey);
    SetConsoleCtrlHandler(&handle_console, 1);

    if (!g::server->bind_to_port(DEFAULT_ADDRESS, 443))
    {
        myprint("# Error: Failed to bind to address " DEFAULT_ADDRESS ":443 - make sure it is not in use!");

        SetConsoleCtrlHandler(&handle_console, 0);
        delete g::server;
        end(1);
    }

    g::server->Get(R"(.*)", handle_get);

    // TODO: custom address launch parameter
    myprint("# SSL Server started - listening to " DEFAULT_ADDRESS ":443...");

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

    // TODO: revert hosts file

    end(status);
}