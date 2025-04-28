#include "tmfwsi.h"
#include "../resource.h"

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

void tmfwsi::error::curl(log_level ll, CURLcode c)
{
    log(ll, std::format("{} (CURLcode: {})", curl_easy_strerror(c), (int)c));
}

void tmfwsi::error::openssl(log_level ll)
{
    unsigned long e = 0L;

    for (int i = 1; e = ERR_get_error(); i++)
    {
        auto error = ERR_error_string(e, nullptr);
        auto lib = ERR_lib_error_string(e);
        auto reason = ERR_reason_error_string(e);

        log(ll, std::format("{}. [{}] {} (lib: {}) (reason: {})", i, e, error, lib, reason));
    }
}

void tmfwsi::error::windows(log_level ll, DWORD gle)
{
    log(ll, std::format("{} (Code: {})", error::last(gle).message(), gle));
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
    constexpr auto unknown_cause = "(unknown)";

    // If the customer bit isn't set, this is already a Windows error, thus there is no known cause
    if ((e_tmfwsi & customer) == 0)
    {
        return unknown_cause;
    }

    auto f = (e_tmfwsi & cause::_mask) >> cause::_bits;

    switch ((cause)f)
    {
        case shell_execute_ex: return "ShellExecuteEx";
        case wait_for_single_object: return "WaitForSingleObject";
        case get_exit_code_process: return "GetExitCodeProcess";
        case delete_file: return "DeleteFile";
        case copy_file: return "CopyFile";
        case std_ofstream: return "std::ofstream";
        default: return unknown_cause;
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

void tmfwsi::log(log_level ll, std::string str)
{
    if (ll == log_level::debug && !debug)
    {
        return;
    }

    SYSTEMTIME time;
    GetLocalTime(&time);
    std::string prefix = std::format("[{:02d}:{:02d}:{:02d} ", time.wHour, time.wMinute, time.wSecond);

    switch (ll)
    {
        case log_level::warn: prefix += "\x1B[93m WARN\x1B[0m]"; break;
        case log_level::error: prefix += "\x1B[91mERROR\x1B[0m]"; break;
        case log_level::debug: prefix += "\x1B[95mDEBUG\x1B[0m]"; break;
        default: prefix += "\x1B[97m INFO\x1B[0m]"; break;
    }

    std::cout << prefix << " " << str << std::endl;
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

size_t tmfwsi::curl_writefn::dummy(void* buffer, size_t size, size_t n_items, void* unused)
{
    return size * n_items;
}

size_t tmfwsi::curl_writefn::string(void* buffer, size_t size, size_t n_items, std::string* str)
{
    str->append(static_cast<char*>(buffer), size * n_items);
    return size * n_items;
}

int tmfwsi::main::init_console()
{
    SetConsoleTitleA(TMFWSI " " TMFWSI_VERSION);

    auto handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (handle == INVALID_HANDLE_VALUE)
    {
        auto gle = GetLastError();
        log(log_level::error, "Failed to get the standard output handle:");
        error::windows(log_level::error, gle);
        return 1;
    }
    else if (!handle)
    {
        log(log_level::error, "No standard output handle was found.");
        return 1;
    }

    DWORD mode;
    if (!GetConsoleMode(handle, &mode))
    {
        auto gle = GetLastError();
        log(log_level::error, "Failed to get the console mode:");
        error::windows(log_level::error, gle);
        return 1;
    }

    if (!SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN))
    {
        auto gle = GetLastError();
        log(log_level::error, "Failed to set the console mode:");
        error::windows(log_level::error, gle);
        return 1;
    }

    log(log_level::info, "----------");
    log(log_level::info, TMFWSI " " TMFWSI_VERSION " by brokenphilip");
    log(log_level::info, std::format("Compiled with 'cURL {}', '" OPENSSL_VERSION_TEXT "' and 'zlib " ZLIB_VERSION "'.", curl_version_info(CURLVERSION_NOW)->version));
    log(log_level::info, "For more information and troubleshooting, please visit: https://github.com/brokenphilip/TMFWSI");
    log(log_level::info, "----------");

    log(log_level::debug, "Debug mode enabled.");
    return 0;
}

int tmfwsi::main::init_resource()
{
    auto resource = FindResourceA(NULL, MAKEINTRESOURCE(IDR_XML1), "XML");
    if (!resource)
    {
        auto gle = GetLastError();
        log(log_level::error, "Failed to find the XML resource:");
        error::windows(log_level::error, gle);
        return 1;
    }

    auto global = LoadResource(NULL, resource);
    if (!global)
    {
        auto gle = GetLastError();
        log(log_level::error, "Failed to load the XML resource:");
        error::windows(log_level::error, gle);
        return 1;
    }

    auto pointer = LockResource(global);
    if (!pointer)
    {
        auto gle = GetLastError();
        log(log_level::error, "Failed to lock the XML resource:");
        error::windows(log_level::error, gle);
        return 1;
    }

    auto xml_len = SizeofResource(NULL, resource);
    if (!xml_len)
    {
        auto gle = GetLastError();
        log(log_level::error, "Failed to get the size of the XML resource:");
        error::windows(log_level::error, gle);
        return 1;
    }

    xml = std::string(static_cast<char*>(pointer), xml_len);
    return 0;
}

int tmfwsi::main::init_curl()
{
    curl = curl_easy_init();
    if (!curl)
    {
        log(log_level::error, "Failed to initialize cURL.");
        return 1;
    }

    return 0;
}

int tmfwsi::main::update_check()
{
    log(log_level::info, "Checking for updates...");

    curl_easy_setopt(curl, CURLOPT_URL, "https://api.github.com/repos/brokenphilip/TMFWSI/tags");

    // Save the result for later
    std::string data;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writefn::string);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);

    // Required for the GitHub REST API
    curl_easy_setopt(curl, CURLOPT_USERAGENT, TMFWSI "/" TMFWSI_VERSION);

    CURLcode res = curl_easy_perform(curl);
    if (res)
    {
        log(log_level::warn, "Failed to perform the network transfer:");
        error::curl(log_level::warn, res);
        curl_easy_reset(curl);
        return 0;
    }

    curl_easy_reset(curl);

    std::stringstream ss(data);
    std::string token;
    for (int i = 0; i < 4 && std::getline(ss, token, '"'); i++)
    {
        if (i == 1 && token != "name")
        {
            break;
        }

        if (i == 3)
        {
            if (token.compare(TMFWSI_VERSION))
            {
                log(log_level::warn, std::format("New version available (download via GitHub): {}", token));
            }
            else
            {
                log(log_level::info, "Already on the latest version");
            }
            return 0;
        }
    }

    log(log_level::warn, "Failed to parse the response.");
    return 0;
}

int tmfwsi::main::get_tmfws_ip()
{
    log(log_level::info, "Fetching IP address of TrackMania Forever Web Services...");

    curl_easy_setopt(curl, CURLOPT_URL, "http://ws.trackmania.com/");

    // Don't write to stdout
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writefn::dummy);

    CURLcode res = curl_easy_perform(curl);
    if (res)
    {
        log(log_level::error, "Failed to perform the network transfer:");
        error::curl(log_level::error, res);
        curl_easy_reset(curl);
        return 1;
    }

    char* primary_ip = nullptr;
    res = curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &primary_ip);
    if (res)
    {
        log(log_level::error, "Failed to get the IP address:");
        error::curl(log_level::error, res);
        curl_easy_reset(curl);
        return 1;
    }

    if (!primary_ip)
    {
        log(log_level::error, "The IP address is blank.");
        curl_easy_reset(curl);
        return 1;
    }

    log(log_level::info, std::format("TrackMania Forever Web Services IP address: {}", primary_ip));
    strcpy_s(ip, primary_ip);
    curl_easy_reset(curl);
    return 0;
}

int tmfwsi::main::generate_ssl_certificate()
{
    log(log_level::info, "Generating SSL certificate...");

    pkey = EVP_RSA_gen(2048);
    if (!pkey)
    {
        log(log_level::error, "Failed to generate RSA key pair.");
        return 1;
    }

    x509 = X509_new();
    if (!x509)
    {
        log(log_level::error, "Failed to generate X509 certificate structure:");
        error::openssl(log_level::error);
        return 1;
    }

    // Set our certificate's serial number to 1 (default is 0, but sometimes it can be refused?)
    if (!ASN1_INTEGER_set(X509_get_serialNumber(x509), 1))
    {
        log(log_level::error, "Failed to set the certificate's serial number.");
        return 1;
    }

    // Our certificate starts now and lasts for a year (which is the maximum as of September 1st, 2020)
    constexpr long one_year = 60L /* seconds */ * 60L /* minutes */ * 24L /* hours */ * 365L /* days */;
    if (!X509_gmtime_adj(X509_get_notBefore(x509), 0))
    {
        log(log_level::error, "Failed to set the certificate's begin date.");
        return 1;
    }
    if (!X509_gmtime_adj(X509_get_notAfter(x509), one_year))
    {
        log(log_level::error, "Failed to set the certificate's end date.");
        return 1;
    }

    if (!X509_set_pubkey(x509, pkey))
    {
        log(log_level::error, "Failed to set the certificate's public key.");
        return 1;
    }

    auto name = X509_get_subject_name(x509);
    if (!X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"RS", -1, -1, 0))
    {
        log(log_level::error, "Failed to set the certificate's country.");
        return 1;
    }
    if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"brokenphilip", -1, -1, 0))
    {
        log(log_level::error, "Failed to set the certificate's organization.");
        return 1;
    }
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)TMFWSI, -1, -1, 0))
    {
        log(log_level::error, "Failed to set the certificate's common name.");
        return 1;
    }

    if (!X509_set_issuer_name(x509, name))
    {
        log(log_level::error, "Failed to set the certificate's issuer.");
        return 1;
    }

    if (!X509_sign(x509, pkey, EVP_sha1()))
    {
        log(log_level::error, "Failed to sign the certificate.");
        return 1;
    }

    log(log_level::info, "SSL certificate generated.");
    return 0;
}

int tmfwsi::main::do_hosts()
{
    log(log_level::info, "Modifying and backing up the 'hosts' file...");

    auto e_tmfwsi = tmfwsi::run("-do-hosts");
    if (e_tmfwsi)
    {
        log(log_level::error, std::format("{} failed:", error::cause_name(e_tmfwsi)));
        error::windows(log_level::error, error::parse(e_tmfwsi));
        return 1;
    }

    log(log_level::info, "The 'hosts' file has been modified and backed up - it will be reverted once the program shuts down.");
	return 0;
}

BOOL WINAPI tmfwsi::main::control_handler(DWORD ctrl)
{
    if (!server_stopped && (ctrl == CTRL_C_EVENT || ctrl == CTRL_CLOSE_EVENT))
    {
        server_stopped = true;
        log(log_level::warn, "Close or CTRL+C event received - stopping server...");
        server->stop();
        return TRUE;
    }

    return FALSE;
}

int tmfwsi::main::ssl_server::loop()
{
    log(log_level::info, "Starting SSL server...");

    SetConsoleCtrlHandler(&main::control_handler, 1);

    server = new httplib::SSLServer(x509, pkey);
    if (!server->bind_to_port(DEFAULT_ADDRESS, 443))
    {
        log(log_level::warn, "SSL server not started - unable to bind to address " DEFAULT_ADDRESS ":443, make sure it is valid and not in use.");

        delete server;
        server = nullptr;

        SetConsoleCtrlHandler(&main::control_handler, 0);

        return 0;
    }
    server->Get(R"(.*)", ssl_server::get);

    // TODO: custom address launch parameter
    log(log_level::info, "SSL Server started - listening to requests on " DEFAULT_ADDRESS ":443...");
    server->listen_after_bind();

    delete server;
    server = nullptr;

    SetConsoleCtrlHandler(&main::control_handler, 0);

    if (!server_stopped)
    {
        log(log_level::warn, "Server has been stopped prematurely.");
        return 0;
    }

    log(log_level::info, "Server has been stopped.");
    return 0;
}

void tmfwsi::main::ssl_server::get(const httplib::Request& request, httplib::Response& response)
{
    log(log_level::info, "Request received, performing...");

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

    // Enable cookie engine - helps with Manialinks
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");

    log(log_level::debug, std::format("Received URL: {}", url));
    log(log_level::debug, "=== Received header START ===");

    // Next, fetch the request headers
    // User-Agent in particular is very important - for reference, TMF uses "GameBox" and MP uses "ManiaPlanet" for their in-game Manialink browsers
    // Authorization is also important, in case the Web Services API is used
    curl_slist* slist = nullptr;
    for (auto& it : request.headers)
    {
        /*
        if (it.first == "LOCAL_ADDR" || it.first == "LOCAL_PORT" || it.first == "REMOTE_ADDR" || it.first == "REMOTE_PORT")
        {
            continue;
        }
        */

        std::string tag = it.first + ":" + it.second;
        curl_slist_append(slist, tag.c_str());

        log(log_level::debug, tag);
    }
    if (slist)
    {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
    }

    log(log_level::debug, "=== Received header END ===");

    // Do not check for certificates, as they're expired anyways
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    //curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_ALLOW_BEAST | CURLSSLOPT_NO_REVOKE);


    // Save the result for later
    std::string data;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writefn::string);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(slist);

    if (res)
    {
        log(log_level::warn, "Failed to perform the network transfer:");
        error::curl(log_level::warn, res);
        curl_easy_reset(curl);
        return;
    }

    // Set the HTTP code
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status);

    // Set the content to the result we saved earlier
    response.body = data;

    log(log_level::debug, std::format("Response code: {}", response.status));
    log(log_level::debug, "=== Sent data START ===");
    log(log_level::debug, data);
    log(log_level::debug, "=== Sent data END ===");
    log(log_level::debug, "=== Sent header START ===");

    // Set the headers
    curl_header* prev = nullptr;
    curl_header* header = nullptr;
    while ((header = curl_easy_nextheader(curl, CURLH_HEADER, 0, prev)))
    {
        // HACK: If the TMFWS wants to redirect us to the Player Page in the Manialink browser, we need to tell the user to log in through their web browser first
        // TODO: Find out why this is broken, I assume this is on TMFWSI's end but there is a possibility this could be on Nadeo's end as well, no idea
        constexpr auto player_page = "https://players.trackmaniaforever.com/";
        constexpr auto player_page_len = std::char_traits<char>::length(player_page);

        bool is_user_agent_gamebox = request.has_header("User-Agent") && request.get_header_value("User-Agent") == "GameBox";

        if (!strcmp(header->name, "Location") && !strncmp(header->value, player_page, player_page_len) && is_user_agent_gamebox)
        {
            response.headers.clear();
            response.status = 200; // OK

            // Maniacode's <show_message> breaks $l links - they won't be opened until the user presses 'OK', so we need to make it a Manialink instead
            response.body = xml;

            response.body = std::regex_replace(response.body, std::regex("%URL1%"), header->value + 8);
            response.body = std::regex_replace(response.body, std::regex("%URL2%"), header->value);
            response.body = std::regex_replace(response.body, std::regex("&"), "&amp;");

            log(log_level::debug, std::format("{}:{}", header->name, header->value));
            log(log_level::debug, "[Headers SKIPPED, due to GameBox User-Agent - sending ManiaLink instead...]");
            log(log_level::debug, "=== Sent header END ===");

            log(log_level::info, "Request performed successfully.");
            curl_easy_reset(curl);
            return;
        }

        log(log_level::debug, std::format("{}:{}", header->name, header->value));

        response.set_header(header->name, header->value);
        prev = header;
    }

    log(log_level::debug, "=== Sent header END ===");

    log(log_level::info, "Request performed successfully.");
    curl_easy_reset(curl);
}

int tmfwsi::main::undo_hosts()
{
    log(log_level::info, "Reverting 'hosts' file...");

    auto e_tmfwsi = tmfwsi::run("-undo-hosts");
    if (e_tmfwsi)
    {
        log(log_level::error, std::format("{} failed:", error::cause_name(e_tmfwsi)));
        error::windows(log_level::error, error::parse(e_tmfwsi));
        return 1;
    }

    log(log_level::info, "'hosts' file reverted.");
    return 0;
}

int tmfwsi::main::cleanup(int status)
{
    log(log_level::info, std::format("TMFWSI is shutting down... Status: {}", (status ? "FAIL" : "OK")));

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
