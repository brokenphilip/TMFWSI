#include <iostream>
#include <filesystem>
#include <fstream>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../ext/httplib.h"

#define CURL_STATICLIB
#include "../ext/curl/curl.h"

#include "../ext/zlib/zlib.h"

#include "last_error.h"

//#include <Shlobj_core.h>

#define myprint(stream) std::cout << stream << std::endl
#define end(status) do { myprint("# TMFWSI is shutting down... Status: " << (status? "FAIL" : "OK")); \
        X509_free(x509); EVP_PKEY_free(pkey); curl_easy_cleanup(g::curl); return status; } while (false) \

#define TMFWSI "TrackMania Forever Web Services Interceptor"
#define TMFWSI_VERSION "1.0"

// 127 :3c
#define DEFAULT_ADDRESS "127.58.51.99"

#define HOSTS_PATH      "C:\\Windows\\system32\\drivers\\etc\\"
#define HOSTS           HOSTS_PATH "hosts"

// 0x20000000	 user defined error

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

// Starts a new hidden TMFWSI instance as admin with the specified arguments
HRESULT run_tmfwsi(LPCSTR args)
{
    char exe[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, exe, MAX_PATH);

    SHELLEXECUTEINFOA sexi = { 0 };
    sexi.cbSize = sizeof(sexi);
    sexi.fMask = SEE_MASK_NOCLOSEPROCESS;
    sexi.hwnd = GetConsoleWindow();
    sexi.lpVerb = "runas";
    sexi.lpFile = exe;
    sexi.lpParameters = args;
    sexi.nShow = SW_HIDE;

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    auto executed = ShellExecuteExA(&sexi);
    CoUninitialize();

    if (!executed)
    {
        auto gle = GetLastError();
        if (gle != S_OK)
        {
            return gle;
        }

        switch ((int)sexi.hInstApp)
        {
            case SE_ERR_FNF: return ERROR_FILE_NOT_FOUND;
            case SE_ERR_PNF: return ERROR_PATH_NOT_FOUND;
            case SE_ERR_ACCESSDENIED: return ERROR_ACCESS_DENIED;
            case SE_ERR_OOM: return ERROR_OUTOFMEMORY;
            case SE_ERR_DLLNOTFOUND: return ERROR_DLL_NOT_FOUND;
            case SE_ERR_SHARE: return ERROR_SHARING_VIOLATION;
            //case SE_ERR_ASSOCINCOMPLETE:
            case SE_ERR_DDETIMEOUT: return ERROR_DDE_FAIL;
            case SE_ERR_DDEFAIL: return ERROR_DDE_FAIL;
            case SE_ERR_DDEBUSY: return ERROR_DDE_FAIL;
            case SE_ERR_NOASSOC: return ERROR_NO_ASSOCIATION;
            default: return E_UNEXPECTED;
        }
    }

    if (!sexi.hProcess)
    {
        return ERROR_INVALID_HANDLE;
    }

    auto result = WaitForSingleObject(sexi.hProcess, INFINITE);
    if (result != STATUS_WAIT_0)
    {
        if (result == WAIT_FAILED)
        {
            return GetLastError();
        }

        return result;
    }

    do
    {
        if (!GetExitCodeProcess(sexi.hProcess, &result))
        {
            return GetLastError();
        }
    }
    while (result == STILL_ACTIVE);

    return result;
}

namespace fs = std::filesystem;

int main()
{
    auto cmdline = GetCommandLineA();

    if (strstr(cmdline, "-do-hosts"))
    {
        // Calculate the path to the backup file
        char path[MAX_PATH] = { 0 };
        GetModuleFileNameA(NULL, path, MAX_PATH);

        fs::path path_fs = path;
        fs::path bak_fs = path_fs.parent_path() / "hosts.tmfwsi_bak";

        std::string bak_str = bak_fs.string();
        const char* bak = bak_str.c_str();
        
        // I will be very sad if you make a directory called "hosts.tmfwsi_bak"
        auto attribs = GetFileAttributesA(bak);
        if (attribs != INVALID_FILE_ATTRIBUTES && attribs & FILE_ATTRIBUTE_DIRECTORY)
        {
            return ERROR_DIRECTORY_NOT_SUPPORTED;
        }

        // Delete the old backup file, if any
        if (!DeleteFileA(bak))
        {
            auto gle = GetLastError();

            // If the file wasn't found, we don't care. If deletion failed for any other reason though, bail
            if (gle != ERROR_FILE_NOT_FOUND)
            {
                return gle;
            }
        }

        // Make a backup of the hosts file
        if (!CopyFileA(HOSTS, bak, true))
        {
            return GetLastError();
        }

        // Modify the hosts file - make sure our local address replaces the Web Services
        std::ofstream out;
        out.open(HOSTS, std::ios::app);
        if (!out.is_open())
        {
            out.close();
            return ERROR_FILE_READ_ONLY;
        }

        if (!(out << "\n\n" "// " TMFWSI "\n" DEFAULT_ADDRESS "\t" "ws.trackmania.com"))
        {
            out.close();
            return ERROR_WRITE_PROTECT;
        }

        out.close();
        return S_OK;
    }

    if (strstr(cmdline, "-undo-hosts"))
    {
        // Calculate the path to the backup file
        char path[MAX_PATH] = { 0 };
        GetModuleFileNameA(NULL, path, MAX_PATH);

        fs::path path_fs = path;
        fs::path bak_fs = path_fs.parent_path() / "hosts.tmfwsi_bak";

        std::string bak_str = bak_fs.string();
        const char* bak = bak_str.c_str();

        // I will be very sad if you make a directory called "hosts.tmfwsi_bak"
        auto attribs = GetFileAttributesA(bak);
        if (attribs != INVALID_FILE_ATTRIBUTES && attribs & FILE_ATTRIBUTE_DIRECTORY)
        {
            return ERROR_DIRECTORY_NOT_SUPPORTED;
        }

        // Replace the 'hosts' file with our backup.
        if (!CopyFileA(bak, HOSTS, false))
        {
            return GetLastError();
        }

        // We don't erase the backup here, in case the user needs it for whatever reason
        return S_OK;
    }

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

    // Disable modifying the hosts file if we have the following launch parameter
    bool hosts_enabled = !strstr(cmdline, "-no-hosts");

    if (hosts_enabled)
    {
        myprint("# Modifying and backing up 'hosts' file...");

        auto result = run_tmfwsi("-do-hosts");
        if (result)
        {
            myprint("# Error: Failed to modify the 'hosts' file - " << LastError(result).Message());
            end(1);
        }

        myprint("# 'hosts' file modified and backed up - it will be reverted once the program shuts down.");
    }
    else
    {
        myprint("# Currently in 'no-hosts' mode - 'hosts' file remains unmodified.");
    }

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

    if (hosts_enabled)
    {
        myprint("# Reverting 'hosts' file...");

        auto result = run_tmfwsi("-undo-hosts");
        if (result)
        {
            myprint("# Error: Failed to revert the 'hosts' file - " << LastError(result).Message());
            end(1);
        }

        myprint("# 'hosts' file reverted.");
    }

    end(status);
}