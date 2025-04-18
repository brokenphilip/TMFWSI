#include "tmfwsi.h"

tmfwsi::error::last::last(DWORD last_error)
{
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK, NULL, last_error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msg, 0, NULL);
}

tmfwsi::error::last::~last()
{
    if (msg)
    {
        LocalFree(msg);
    }
}

const char* tmfwsi::error::last::message()
{
    return msg ? msg : "Unknown error - FormatMessageA failed.";
}

void tmfwsi::error::openssl()
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

DWORD tmfwsi::error::make(DWORD e, cause f)
{
    // If our cause bits are already taken by a legitimate Windows error, do nothing...
    // As far as I'm aware, this should never happen, but if it does, it's better to know the correct error than mistakenly erase it.
    if ((e & cause::_mask) != 0)
    {
        return e;
    }

    return e | customer | (f << cause::_bits);
}

DWORD tmfwsi::error::parse(DWORD e_tmfwsi)
{
    // If the customer bit isn't set, this is already a Windows error
    if ((e_tmfwsi & customer) == 0)
    {
        return e_tmfwsi;
    }

    return e_tmfwsi & ~(customer) & ~(cause::_mask);
}

const char* tmfwsi::error::cause_name(int e_tmfwsi)
{
    auto f = (e_tmfwsi & cause::_mask) >> cause::_bits;

    switch ((cause)f)
    {
        case shell_execute_ex: return "ShellExecuteEx";
        case wait_for_single_object: return "WaitForSingleObject";
        case get_exit_code_process: return "GetExitCodeProcess";
        case delete_file: return "DeleteFile";
        case copy_file: return "CopyFile";
        case std_ofstream: return "std::ofstream";
        default: return "(unknown)";
    }
}

DWORD tmfwsi::run(LPCSTR args)
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

    auto hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    auto executed = ShellExecuteExA(&sexi);
    auto gle = GetLastError();

    if (SUCCEEDED(hr))
    {
        CoUninitialize();
    }

    if (!executed)
    {
        if (gle != S_OK)
        {
            return error::make(gle, error::cause::shell_execute_ex);
        }

        switch ((int)sexi.hInstApp)
        {
            case SE_ERR_FNF:                return ERROR_FILE_NOT_FOUND;
            case SE_ERR_PNF:                return ERROR_PATH_NOT_FOUND;
            case SE_ERR_ACCESSDENIED:       return ERROR_ACCESS_DENIED;
            case SE_ERR_OOM:                return ERROR_OUTOFMEMORY;
            case SE_ERR_DLLNOTFOUND:        return ERROR_DLL_NOT_FOUND;
            case SE_ERR_SHARE:              return ERROR_SHARING_VIOLATION;
            case SE_ERR_ASSOCINCOMPLETE:    return ERROR_NO_ASSOCIATION;
            case SE_ERR_DDETIMEOUT:         return ERROR_DDE_FAIL;
            case SE_ERR_DDEFAIL:            return ERROR_DDE_FAIL;
            case SE_ERR_DDEBUSY:            return ERROR_DDE_FAIL;
            case SE_ERR_NOASSOC:            return ERROR_NO_ASSOCIATION;
            default:                        return ERROR_UNIDENTIFIED_ERROR;
        }
    }

    if (!sexi.hProcess)
    {
        return error::make(ERROR_INVALID_HANDLE, error::cause::shell_execute_ex);
    }

    auto result = WaitForSingleObject(sexi.hProcess, INFINITE);
    if (result != STATUS_WAIT_0)
    {
        if (result == WAIT_FAILED)
        {
            return error::make(GetLastError(), error::cause::wait_for_single_object);
        }

        return error::make(result, error::cause::wait_for_single_object);
    }

    do
    {
        if (!GetExitCodeProcess(sexi.hProcess, &result))
        {
            return error::make(GetLastError(), error::cause::get_exit_code_process);
        }
    } 
    while (result == STILL_ACTIVE);

    return result;
}

namespace fs = std::filesystem;

int tmfwsi::main_do_hosts()
{
    // Calculate the path to the backup file
    char path[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, path, MAX_PATH);

    fs::path path_fs = path;
    fs::path bak_fs = path_fs.parent_path() / "hosts.tmfwsi_bak";
    
    auto bak_str = bak_fs.string();
    auto bak = bak_str.c_str();

    // I will be very sad if you make a directory called "hosts.tmfwsi_bak"
    auto attribs = GetFileAttributesA(bak);
    if (attribs != INVALID_FILE_ATTRIBUTES && attribs & FILE_ATTRIBUTE_DIRECTORY)
    {
        return error::make(ERROR_DIRECTORY_NOT_SUPPORTED, error::cause::delete_file);
    }

    // Delete the old backup file, if any
    if (!DeleteFileA(bak))
    {
        auto gle = GetLastError();

        // If the file wasn't found, we don't care. If deletion failed for any other reason though, bail
        if (gle != ERROR_FILE_NOT_FOUND)
        {
            return error::make(gle, error::cause::delete_file);
        }
    }

    // Make a backup of the hosts file
    if (!CopyFileA(HOSTS, bak, true))
    {
        return error::make(GetLastError(), error::cause::copy_file);
    }

    // Modify the hosts file - make sure our local address replaces the Web Services
    std::ofstream out;
    out.open(HOSTS, std::ios::app);
    if (!out.is_open())
    {
        out.close();
        return error::make(ERROR_FILE_READ_ONLY, error::cause::std_ofstream);
    }

    if (!(out << "\n\n" "// " TMFWSI "\n" DEFAULT_ADDRESS "\t" "ws.trackmania.com"))
    {
        out.close();
        return error::make(ERROR_WRITE_PROTECT, error::cause::std_ofstream);
    }

    out.close();
    return S_OK;
}

int tmfwsi::main_undo_hosts()
{
    // Calculate the path to the backup file
    char path[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, path, MAX_PATH);

    fs::path path_fs = path;
    fs::path bak_fs = path_fs.parent_path() / "hosts.tmfwsi_bak";

    auto bak_str = bak_fs.string();
    auto bak = bak_str.c_str();

    // I will be very sad if you make a directory called "hosts.tmfwsi_bak"
    auto attribs = GetFileAttributesA(bak);
    if (attribs != INVALID_FILE_ATTRIBUTES && attribs & FILE_ATTRIBUTE_DIRECTORY)
    {
        return error::make(ERROR_DIRECTORY_NOT_SUPPORTED, error::cause::delete_file);
    }

    // Replace the 'hosts' file with our backup.
    if (!CopyFileA(bak, HOSTS, false))
    {
        return error::make(GetLastError(), error::cause::copy_file);
    }

    // We don't erase the backup here, in case the user needs it for whatever reason
    return S_OK;
}

int tmfwsi::main::init()
{
    SetConsoleTitleA(TMFWSI " " TMFWSI_VERSION);

    myprint("# -----");
    myprint("# " TMFWSI " " TMFWSI_VERSION " by brokenphilip");
    myprint("# Compiled with 'cURL " << curl_version_info(CURLVERSION_NOW)->version << "', '" OPENSSL_VERSION_TEXT "' and 'zlib " ZLIB_VERSION "'.");
    myprint("# For more information and troubleshooting, please visit: https://github.com/brokenphilip/TMFWSI");
    myprint("# -----");

    curl = curl_easy_init();
    if (!curl)
    {
        myprint("# Error: Failed to initialize cURL!");
        return 1;
    }

    myprint("# Fetching IP address of TrackMania Forever Web Services...");

    curl_easy_setopt(curl, CURLOPT_URL, "http://ws.trackmania.com/");

    // Don't write to stdout
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](void* buffer, size_t size, size_t n_items, void* unused)
    {
        return size * n_items;
    });

    CURLcode res = curl_easy_perform(curl);
    if (res)
    {
        myprint("# Error: " << curl_easy_strerror(res) << " (CURLcode: " << res << ")");
        return 1;
    }

    char* primary_ip = nullptr;
    res = curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &primary_ip);
    if (res)
    {
        myprint("# Error: " << curl_easy_strerror(res) << " (CURLcode: " << res << ")");
        return 1;
    }

    if (!primary_ip)
    {
        myprint("# Error: IP address is blank!");
        return 1;
    }

    myprint("# TrackMania Forever Web Services IP address: " << primary_ip);
    strcpy_s(ip, primary_ip);
    curl_easy_reset(curl);
    return 0;
}

int tmfwsi::main::generate_ssl_certificate()
{
    myprint("# Generating SSL certificate...");

    pkey = EVP_RSA_gen(2048);
    if (!pkey)
    {
        myprint("# Error: Failed to generate RSA key pair!");
        return 1;
    }

    x509 = X509_new();
    if (!x509)
    {
        myprint("# Error: Failed to generate X509 certificate structure! The following errors occurred:");
        error::openssl();
        return 1;
    }

    // Set our certificate's serial number to 1 (default is 0, but sometimes it can be refused?)
    if (!ASN1_INTEGER_set(X509_get_serialNumber(x509), 1))
    {
        myprint("# Error: Failed to set the certificate's serial number!");
        return 1;
    }

    // Our certificate starts now and lasts for a year (which is the maximum as of September 1st, 2020)
    constexpr long one_year = 60L /* seconds */ * 60L /* minutes */ * 24L /* hours */ * 365L /* days */;
    if (!X509_gmtime_adj(X509_get_notBefore(x509), 0))
    {
        myprint("# Error: Failed to set the certificate's begin date!");
        return 1;
    }
    if (!X509_gmtime_adj(X509_get_notAfter(x509), one_year))
    {
        myprint("# Error: Failed to set the certificate's end date!");
        return 1;
    }

    if (!X509_set_pubkey(x509, pkey))
    {
        myprint("# Error: Failed to set the certificate's public key!");
        return 1;
    }

    auto name = X509_get_subject_name(x509);
    if (!X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"RS", -1, -1, 0))
    {
        myprint("# Error: Failed to set the certificate's country!");
        return 1;
    }
    if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"brokenphilip", -1, -1, 0))
    {
        myprint("# Error: Failed to set the certificate's organization!");
        return 1;
    }
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)TMFWSI, -1, -1, 0))
    {
        myprint("# Error: Failed to set the certificate's common name!");
        return 1;
    }

    if (!X509_set_issuer_name(x509, name))
    {
        myprint("# Error: Failed to set the certificate's issuer!");
        return 1;
    }

    if (!X509_sign(x509, pkey, EVP_sha1()))
    {
        myprint("# Error: Failed to sign the certificate!");
        return 1;
    }

    myprint("# SSL certificate generated.");
    return 0;
}

int tmfwsi::main::do_hosts()
{
    myprint("# Modifying and backing up 'hosts' file...");

    auto e_tmfwsi = tmfwsi::run("-do-hosts");
    if (e_tmfwsi)
    {
        auto e = error::parse(e_tmfwsi);
        myprint("# Error: Failed to modify the 'hosts' file - " << error::cause_name(e_tmfwsi) << ": " << error::last(e).message() << " (Code: " << e << ")");
        return 1;
    }

    myprint("# 'hosts' file modified and backed up - it will be reverted once the program shuts down.");
	return 0;
}

BOOL WINAPI tmfwsi::main::control_handler(DWORD ctrl)
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

int tmfwsi::main::ssl_server::loop()
{
    myprint("# Starting SSL server...");
    server = new httplib::SSLServer(x509, pkey);
    SetConsoleCtrlHandler(&main::control_handler, 1);

    if (!server->bind_to_port(DEFAULT_ADDRESS, 443))
    {
        myprint("# Error: Failed to bind to address " DEFAULT_ADDRESS ":443 - make sure it is not in use!");

        SetConsoleCtrlHandler(&main::control_handler, 0);

        delete server;
        server = nullptr;

        return 1;
    }

    server->Get(R"(.*)", ssl_server::get);

    // TODO: custom address launch parameter
    myprint("# SSL Server started - listening to " DEFAULT_ADDRESS ":443...");
    server->listen_after_bind();

    SetConsoleCtrlHandler(&main::control_handler, 0);

    delete server;
    server = nullptr;

    if (!server_stopped)
    {
        myprint("# Error: An error occurred while listening!");
        return 1;
    }

    myprint("# Server has been stopped.");
    return 0;
}

void tmfwsi::main::ssl_server::get(const httplib::Request& request, httplib::Response& response)
{
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

    std::string ip_str = ip;
    std::string url = "https://" + ip_str + request.path + params;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    // Enable cookie engine - might not do anything?
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");

    if (debug)
    {
        myprint("!! Received URL: " << url);

        myprint("!! === Received header START === ");
    }

    // Next, fetch the request headers
    // User-Agent in particular is very important - for reference, TMF uses "GameBox" and MP uses "ManiaPlanet" for their in-game Manialink browsers
    // Authorization is also important, in case the Web Services API is used
    curl_slist* slist = nullptr;
    for (auto& it : request.headers)
    {
        std::string tag = it.first + ":" + it.second;
        curl_slist_append(slist, tag.c_str());

        if (debug)
        {
            std::cout << tag << std::endl;
        }
    }
    if (slist)
    {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
    }

    if (debug)
    {
        myprint("!! === Received header END === ");
    }

    // Do not check for certificates, as they're expired anyways (which is what we're trying to work around in the first place lol)
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);

    // Save the result for later
    std::string data;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](void* buffer, size_t size, size_t n_items, std::string* data)
    {
        data->append(static_cast<char*>(buffer), size * n_items);
        return size * n_items;
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);

    CURLcode res = curl_easy_perform(curl);
    if (res)
    {
        myprint("# Error: " << curl_easy_strerror(res) << " (CURLcode: " << res << ")");
    }
    else
    {
        // Set the HTTP code
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status);

        // Set the content to the result we saved earlier
        response.body = data;

        if (debug)
        {
            myprint("!! === Sent data START === ");
            std::cout << data << std::endl;
            myprint("!! === Sent data END === ");

            myprint("!! === Sent header START === ");
        }

        // Set the headers
        curl_header* prev = nullptr;
        curl_header* header = nullptr;
        while ((header = curl_easy_nextheader(curl, CURLH_HEADER, 0, prev)))
        {
            if (debug)
            {
                std::cout << header->name << ":" << header->value << std::endl;
            }

            response.set_header(header->name, header->value);
            prev = header;
        }

        if (debug)
        {
            myprint("!! === Sent header END === ");
        }

        myprint("# Success!");
    }

    // Done :3
    if (slist)
    {
        curl_slist_free_all(slist);
    }
    curl_easy_reset(curl);
}

int tmfwsi::main::undo_hosts()
{
    myprint("# Reverting 'hosts' file...");

    auto e_tmfwsi = tmfwsi::run("-undo-hosts");
    if (e_tmfwsi)
    {
        auto e = error::parse(e_tmfwsi);
        myprint("# Error: Failed to revert the 'hosts' file - " << error::cause_name(e_tmfwsi) << ": " << error::last(e).message() << " (Code: " << e << ")");
        return 1;
    }

    myprint("# 'hosts' file reverted.");
    return 0;
}

int tmfwsi::main::cleanup(int status)
{
    myprint("# TMFWSI is shutting down... Status: " << (status ? "FAIL" : "OK"));

    if (x509)
    {
        X509_free(x509);
        x509 = nullptr;
    }
    if (pkey)
    {
        EVP_PKEY_free(pkey);
        pkey = nullptr;
    }
    if (curl)
    {
        curl_easy_cleanup(curl);
        curl = nullptr;
    }

    return status;
}
