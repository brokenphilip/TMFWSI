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

tmfwsi::error::error_t tmfwsi::error::make(DWORD e, cause f)
{
    // If our cause bits are already taken by a legitimate Windows error, do nothing...
    // As far as I'm aware, this should never happen, but if it does, it's better to know the correct error than mistakenly erase it.
    if ((e & cause::_mask) != 0)
    {
        return e;
    }

    return e | customer | (f << cause::_bits);
}

DWORD tmfwsi::error::parse(error_t e_tmfwsi)
{
    // If the customer bit isn't set, this is already a Windows error
    if ((e_tmfwsi & customer) == 0)
    {
        return e_tmfwsi;
    }

    return e_tmfwsi & ~(customer) & ~(cause::_mask);
}

const char* tmfwsi::error::cause_name(error_t e_tmfwsi)
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
        case shell_execute_ex:          return "ShellExecuteEx";
        case wait_for_single_object:    return "WaitForSingleObject";
        case get_exit_code_process:     return "GetExitCodeProcess";
        case delete_file:               return "DeleteFile";
        case copy_file:                 return "CopyFile";
        case create_file:               return "CreateFile";
        case write_file:                return "WriteFile";
        case get_file_attributes:       return "GetFileAttributes";
        default:                        return unknown_cause;
    }
}

tmfwsi::file::writer::writer(const char* file)
{
    handle = CreateFileA(file, FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    create_file_gle = GetLastError();

    if (handle == INVALID_HANDLE_VALUE && create_file_gle == ERROR_ACCESS_DENIED)
    {
        auto perms = check_permissions(file);
        if (perms)
        {
            create_file_gle = perms;
        }
    }
}

tmfwsi::file::writer::~writer()
{
    if (handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(handle);
    }
}

tmfwsi::error::error_t tmfwsi::file::writer::write(const char* str, DWORD len)
{
    if (handle == INVALID_HANDLE_VALUE)
    {
        return error::make(create_file_gle, error::cause::create_file);
    }

    DWORD written = 0;
    if (!WriteFile(handle, str, len, &written, NULL))
    {
        return error::make(GetLastError(), error::cause::write_file);
    }

    if (len != written)
    {
        return error::make(ERROR_MORE_DATA, error::cause::write_file);
    }

    return 0;
}

tmfwsi::error::error_t tmfwsi::file::writer::write(std::string const& str)
{
    return write(str.c_str(), str.length());
}

DWORD tmfwsi::file::check_permissions(const char* file)
{
    auto attribs = GetFileAttributesA(file);
    if (attribs == INVALID_FILE_ATTRIBUTES)
    {
        return GetLastError();
    }

    if (attribs & FILE_ATTRIBUTE_DIRECTORY)
    {
        return ERROR_DIRECTORY_NOT_SUPPORTED;
    }
    else if (attribs & FILE_ATTRIBUTE_READONLY)
    {
        return ERROR_FILE_READ_ONLY;
    }
    else if (attribs & FILE_ATTRIBUTE_SYSTEM)
    {
        return ERROR_NOT_ALLOWED_ON_SYSTEM_FILE;
    }

    return 0;
}

DWORD tmfwsi::file::check_permissions(fs::path const& path)
{
    return check_permissions(path.string().c_str());
}

DWORD tmfwsi::file::erase(const char* file, bool must_exist)
{
    auto e_perms = check_permissions(file);
    if (e_perms)
    {
        if (e_perms != ERROR_FILE_NOT_FOUND || must_exist)
        {
            return e_perms;
        }
    }

    if (!DeleteFileA(file))
    {
        auto gle = GetLastError();

        if (gle != ERROR_FILE_NOT_FOUND || must_exist)
        {
            return gle;
        }
    }

    return 0;
}

DWORD tmfwsi::file::erase(fs::path const& path, bool must_exist)
{
    return erase(path.string().c_str(), must_exist);
}

int tmfwsi::main_do_hosts()
{
    auto bak_str = (file::exe_path / "hosts.tmfwsi_bak").string();
    auto bak = bak_str.c_str();

    // First and foremost, check the hosts file's permissions - there's no point in doing anything past this point if it can't even be modified
    auto result = file::check_permissions(HOSTS);
    if (result)
    {
        return error::make(result, error::cause::get_file_attributes);
    }

    // Next, since we know the hosts file is probably okay, it's time to erase the backup
    result = file::erase(bak);
    if (result)
    {
        return error::make(result, error::cause::delete_file);
    }

    // Make a backup of the hosts file. We could be more strict and pass 'true' to bFailIfExists, but the backup file shouldn't exist anymore anyways
    if (!CopyFileA(HOSTS, bak, false))
    {
        return error::make(GetLastError(), error::cause::copy_file);
    }

    // Finally, now that we have a backup, modify the hosts file
    {
        file::writer fw(HOSTS);

        auto result = fw.write(std::format("\r\n\r\n" "// " TMFWSI "\r\n" "{}" "\t" "ws.trackmania.com", server_ip));
        if (result)
        {
            return result;
        }
    }

    return 0;
}

int tmfwsi::main_undo_hosts()
{
    auto bak_str = (file::exe_path / "hosts.tmfwsi_bak").string();
    auto bak = bak_str.c_str();

    // First, check the hosts file's permissions
    auto result = file::check_permissions(HOSTS);
    if (result)
    {
        return error::make(result, error::cause::get_file_attributes);
    }

    // Then, replace the 'hosts' file with our backup
    if (!CopyFileA(bak, HOSTS, false))
    {
        return error::make(GetLastError(), error::cause::copy_file);
    }

    // We don't erase the backup here, in case the user needs it for whatever reason
    return 0;
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

tmfwsi::error::error_t tmfwsi::main::run(const char* args)
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
        if (gle)
        {
            return error::make(gle, error::cause::shell_execute_ex);
        }

        switch ((int)sexi.hInstApp)
        {
            case SE_ERR_FNF:                return error::make(ERROR_FILE_NOT_FOUND, error::cause::shell_execute_ex);
            case SE_ERR_PNF:                return error::make(ERROR_PATH_NOT_FOUND, error::cause::shell_execute_ex);
            case SE_ERR_ACCESSDENIED:       return error::make(ERROR_ACCESS_DENIED, error::cause::shell_execute_ex);
            case SE_ERR_OOM:                return error::make(ERROR_OUTOFMEMORY, error::cause::shell_execute_ex);
            case SE_ERR_DLLNOTFOUND:        return error::make(ERROR_DLL_NOT_FOUND, error::cause::shell_execute_ex);
            case SE_ERR_SHARE:              return error::make(ERROR_SHARING_VIOLATION, error::cause::shell_execute_ex);
            case SE_ERR_ASSOCINCOMPLETE:    return error::make(ERROR_NO_ASSOCIATION, error::cause::shell_execute_ex);
            case SE_ERR_DDETIMEOUT:         return error::make(ERROR_DDE_FAIL, error::cause::shell_execute_ex);
            case SE_ERR_DDEFAIL:            return error::make(ERROR_DDE_FAIL, error::cause::shell_execute_ex);
            case SE_ERR_DDEBUSY:            return error::make(ERROR_DDE_FAIL, error::cause::shell_execute_ex);
            case SE_ERR_NOASSOC:            return error::make(ERROR_NO_ASSOCIATION, error::cause::shell_execute_ex);
            default:                        return error::make(ERROR_UNIDENTIFIED_ERROR, error::cause::shell_execute_ex);
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

    // The (un)do_hosts() subroutines already error::make() for us
    return result;
}

tmfwsi::error::error_t tmfwsi::main::run(std::string const& args)
{
    return run(args.c_str());
}

void tmfwsi::main::log(log_level ll, std::string const& str)
{
    // Since cURL's VERBOSE/DEBUGFUNCTION options are multi-threaded, we must use a mutex here
    static std::mutex mtx;
    std::lock_guard lg(mtx);

    if (ll == log_level::debug && !(logging == log_mode::verbose || debug))
    {
        return;
    }

    SYSTEMTIME time;
    GetLocalTime(&time);
    std::string time_str = std::format("{:02d}:{:02d}:{:02d}", time.wHour, time.wMinute, time.wSecond);

    std::string prefix;
    switch (ll)
    {
        case log_level::warn:   prefix = " WARN"; break;
        case log_level::error:  prefix = "ERROR"; break;
        case log_level::debug:  prefix = "DEBUG"; break;
        default:                prefix = " INFO"; break;
    }

    // If logging is enabled, and either (1) it's not a debug log, or (2) it is a debug log, but we are also verbose logging as well
    if (logging != log_mode::off && (ll != log_level::debug || (ll == log_level::debug && logging == log_mode::verbose)))
    {
        auto month_str = +[](WORD month)
        {
            switch (month)
            {
                case  1: return "Jan";
                case  2: return "Feb";
                case  3: return "Mar";
                case  4: return "Apr";
                case  5: return "May";
                case  6: return "Jun";
                case  7: return "Jul";
                case  8: return "Aug";
                case  9: return "Sep";
                case 10: return "Oct";
                case 11: return "Nov";
                case 12: return "Dec";
                default: return "???";
            }
        };

        std::string date_str = std::format("{:02d}-{}-{:02d}", time.wDay, month_str(time.wMonth), time.wYear % 100);

        logger->write(std::format("[{} {} {}] {}\r\n", date_str, time_str, prefix, str));
    }

    if (ll == log_level::debug && !debug)
    {
        return;
    }

    switch (ll)
    {
        case log_level::warn:   prefix.insert(0, "\x1B[93m"); break;
        case log_level::error:  prefix.insert(0, "\x1B[91m"); break;
        case log_level::debug:  prefix.insert(0, "\x1B[95m"); break;
        default:                prefix.insert(0, "\x1B[97m"); break;
    }

    prefix += "\x1B[0m";

    std::cout << "[" << time_str << " " << prefix << "] " << str << std::endl;
}

void tmfwsi::main::curl_log(log_level ll, CURLcode c)
{
    log(ll, std::format("{} (CURLcode: {})", curl_easy_strerror(c), (int)c));
}

void tmfwsi::main::openssl_log(log_level ll)
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

void tmfwsi::main::windows_log(log_level ll, DWORD gle)
{
    log(ll, std::format("{} (Code: {})", error::last(gle).message(), gle));
}

int tmfwsi::main::curl_debug(CURL* handle, curl_infotype it, char* data, size_t size, void* clientp)
{
    std::string prefix;

    switch (it)
    {
        case CURLINFO_TEXT:         prefix = " T  E  X  T "; break;
        case CURLINFO_HEADER_IN:    prefix = "  HEADER_IN "; break;
        case CURLINFO_HEADER_OUT:   prefix = " HEADER_OUT "; break;
        case CURLINFO_DATA_IN:      prefix = "   DATA_IN  "; break;
        case CURLINFO_DATA_OUT:     prefix = "  DATA_OUT  "; break;
        case CURLINFO_SSL_DATA_IN:  prefix = " SSL_DATA_IN"; break;
        case CURLINFO_SSL_DATA_OUT: prefix = "SSL_DATA_OUT"; break;
        case CURLINFO_END:          prefix = "  E   N   D "; break;
        default:                    prefix = "            "; break;
    }

    // Size minus one to remove the trailing newline
    std::string err(data, size - 1);
    std::stringstream ss(err);
    std::string line;

    while (std::getline(ss, line))
    {
        // We could add a "if (!line.empty())" check here, but i think it's better to print out empty newlines for formatting sake
        log(log_level::debug, std::format("(cURL {}) {}", prefix, line));
    }
    return 0;
}

void tmfwsi::main::curl_cookies_debug()
{
    if (!debug && logging != log_mode::verbose)
    {
        return;
    }

    curl_slist* cookies = nullptr;
    auto res = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
    if (res)
    {
        log(log_level::debug, "Failed to get cookies:");
        curl_log(log_level::debug, res);
        return;
    }

    if (!cookies)
    {
        log(log_level::debug, "No cookies set.");
        return;
    }

    log(log_level::debug, "=== Cookies START ===");
    curl_slist* each = cookies;
    while (each)
    {
        log(log_level::debug, each->data);
        each = each->next;
    }
    log(log_level::debug, "=== Cookies END ===");

    curl_slist_free_all(cookies);
}

int tmfwsi::main::init_console_and_logging()
{
    SetConsoleTitleA(TMFWSI " " TMFWSI_VERSION);

    auto handle = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(handle, &mode);
    SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN);

    error::error_t result = 0;
    if (logging != log_mode::off)
    {
        logger = new file::writer(file::exe_path / "tmfwsi.log");
        result = logger->write("\r\n\r\n\r\n");
        if (result)
        {
            delete logger;
            logger = nullptr;
            logging = log_mode::off;
        }
    }

    auto curl_version = curl_version_info(CURLVERSION_NOW)->version;
    log(log_level::info, "----------");
    log(log_level::info, TMFWSI " " TMFWSI_VERSION " by brokenphilip");
    log(log_level::info, std::format("Compiled with 'cURL {}', '" OPENSSL_VERSION_TEXT "' and 'zlib " ZLIB_VERSION "'.", curl_version));
    log(log_level::info, "For more information and troubleshooting, please visit: https://github.com/brokenphilip/TMFWSI");
    log(log_level::info, "----------");

    log(log_level::debug, "Debug mode enabled.");

    if (result)
    {
        log(log_level::warn, std::format("Logging to file disabled - {} failed:", error::cause_name(result)));
        windows_log(log_level::warn, error::parse(result));
    }
    return 0;
}

int tmfwsi::main::init_mutex()
{
    auto mtx = CreateMutexA(NULL, TRUE, "Global\\TMFWSI");
    auto gle = GetLastError();

    if (!mtx)
    {
        log(log_level::error, "Failed to create mutex:");
        windows_log(log_level::error, gle);
        return 1;
    }
    else if (gle == ERROR_ALREADY_EXISTS)
    {
        log(log_level::error, "TMFWSI is already running - you may only run one instace of TMFWSI at a time.");
        return 1;
    }

    mutex = mtx;
    return 0;
}

int tmfwsi::main::init_resource()
{
    auto resource = FindResourceA(NULL, MAKEINTRESOURCE(IDR_XML1), "XML");
    if (!resource)
    {
        auto gle = GetLastError();
        log(log_level::error, "Failed to find the XML resource:");
        windows_log(log_level::error, gle);
        return 1;
    }

    auto global = LoadResource(NULL, resource);
    if (!global)
    {
        auto gle = GetLastError();
        log(log_level::error, "Failed to load the XML resource:");
        windows_log(log_level::error, gle);
        return 1;
    }

    auto pointer = LockResource(global);
    if (!pointer)
    {
        auto gle = GetLastError();
        log(log_level::error, "Failed to lock the XML resource:");
        windows_log(log_level::error, gle);
        return 1;
    }

    auto xml_len = SizeofResource(NULL, resource);
    if (!xml_len)
    {
        auto gle = GetLastError();
        log(log_level::error, "Failed to get the size of the XML resource:");
        windows_log(log_level::error, gle);
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
        curl_log(log_level::warn, res);
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
        curl_log(log_level::error, res);
        curl_easy_reset(curl);
        return 1;
    }

    char* primary_ip = nullptr;
    res = curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &primary_ip);
    if (res)
    {
        log(log_level::error, "Failed to get the IP address:");
        curl_log(log_level::error, res);
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
    tmfws_ip = primary_ip;

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
        openssl_log(log_level::error);
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

    auto e_tmfwsi = run(std::format("-do-hosts -ip {}", server_ip));
    if (e_tmfwsi)
    {
        log(log_level::error, std::format("{} failed:", error::cause_name(e_tmfwsi)));
        windows_log(log_level::error, error::parse(e_tmfwsi));
        return 1;
    }

    log(log_level::info, "The 'hosts' file has been modified and backed up - it will be reverted once the program shuts down.");
	return 0;
}

BOOL WINAPI tmfwsi::main::control_handler(DWORD ctrl)
{
    if (!ssl_server::stopped && (ctrl == CTRL_C_EVENT || ctrl == CTRL_CLOSE_EVENT))
    {
        log(log_level::warn, "Close or CTRL+C event received - stopping server...");

        ssl_server::stopped = true;
        if (ssl_server::server)
        {
            ssl_server::server->stop();
        }
        else
        {
            log(log_level::error, "Tried to stop a server that doesn't exist.");
        }
        return TRUE;
    }
    return FALSE;
}

int tmfwsi::main::ssl_server::loop()
{
    log(log_level::info, "Starting SSL server...");

    SetConsoleCtrlHandler(&control_handler, 1);

    server = new httplib::SSLServer(x509, pkey);
    if (!server->bind_to_port(server_ip, 443))
    {
        log(log_level::warn, std::format("SSL server not started - unable to bind to address {}:443, make sure it is valid and not in use.", server_ip));

        delete server;
        server = nullptr;

        SetConsoleCtrlHandler(&control_handler, 0);

        return 0;
    }
    server->Get(R"(.*)", get);

    log(log_level::info, std::format("SSL server started - listening to requests on {}:443...", server_ip));
    server->listen_after_bind();

    delete server;
    server = nullptr;

    SetConsoleCtrlHandler(&control_handler, 0);

    if (!stopped)
    {
        log(log_level::warn, "Server has been stopped prematurely.");
        return 0;
    }

    log(log_level::info, "Server has been stopped.");
    return 0;
}

void tmfwsi::main::ssl_server::get(const httplib::Request& request, httplib::Response& response)
{
    // Since httplib is multi-threaded, and we shouldn't use more than one cURL instance (not to break cookie/manialink support), we must use a mutex here
    static std::mutex mtx;
    std::lock_guard lg(mtx);

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

    if (debug || logging == log_mode::verbose)
    {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_debug);
    }

    std::string url = "https://" + tmfws_ip + request.path + params;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    // Enable cookie engine - helps with Manialinks
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");

    log(log_level::debug, std::format("Received URL: {}", url));
    log(log_level::debug, "=== Received header START ===");

    // Next, fetch the request headers
    // User-Agent in particular is very important - for reference, TMF uses "GameBox" and MP uses "ManiaPlanet" for their in-game Manialink browsers
    // Authorization is also important, in case the Web Services API is used (although, for some reason, it's broken (at curl/low-level?) and can't be fixed)
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
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
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
        curl_log(log_level::warn, res);
        curl_easy_reset(curl);
        return;
    }

    // Set the HTTP code
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status);

    // Set the content to the result we saved earlier
    response.body = data;

    log(log_level::debug, std::format("Response code: {}", response.status));
    if (data.empty())
    {
        log(log_level::debug, "Sent data is empty.");
    }
    else
    {
        log(log_level::debug, "=== Sent data START ===");
        log(log_level::debug, data);
        log(log_level::debug, "=== Sent data END ===");
    }
    log(log_level::debug, "=== Sent header START ===");

    // Set the headers
    curl_header* prev = nullptr;
    curl_header* header = nullptr;
    while ((header = curl_easy_nextheader(curl, CURLH_HEADER, 0, prev)))
    {
        log(log_level::debug, std::format("{}:{}", header->name, header->value));

        // HACK: If the TMFWS wants to redirect us to the Player Page in the Manialink browser, we need to tell the user to log in through their web browser first
        constexpr auto player_page = "https://players.trackmaniaforever.com/";
        constexpr auto player_page_len = std::char_traits<char>::length(player_page);

        if (!strcmp(header->name, "Location") && !strncmp(header->value, player_page, player_page_len) && request.get_header_value("User-Agent") == "GameBox")
        {
            log(log_level::debug, "[Headers SKIPPED, due to GameBox User-Agent - sending ManiaLink instead...]");
            log(log_level::debug, "=== Sent header END ===");

            response.headers.clear();
            response.status = 200; // OK

            // Maniacode's <show_message> breaks $l links - they won't be opened until the user presses 'OK', so we need to make it a Manialink instead
            response.body = xml;

            response.body = std::regex_replace(response.body, std::regex("%URL1%"), header->value + 8);
            response.body = std::regex_replace(response.body, std::regex("%URL2%"), header->value);
            response.body = std::regex_replace(response.body, std::regex("&"), "&amp;");

            curl_cookies_debug();

            log(log_level::info, "Request performed successfully.");
            curl_easy_reset(curl);
            return;
        }

        response.set_header(header->name, header->value);
        prev = header;
    }

    log(log_level::debug, "=== Sent header END ===");

    curl_cookies_debug();

    log(log_level::info, "Request performed successfully.");
    curl_easy_reset(curl);
}

int tmfwsi::main::undo_hosts()
{
    log(log_level::info, "Reverting 'hosts' file...");

    auto e_tmfwsi = run("-undo-hosts");
    if (e_tmfwsi)
    {
        log(log_level::error, std::format("{} failed:", error::cause_name(e_tmfwsi)));
        windows_log(log_level::error, error::parse(e_tmfwsi));
        return 1;
    }

    log(log_level::info, "'hosts' file reverted.");
    return 0;
}

int tmfwsi::main::cleanup(int status)
{
    log(log_level::info, std::format("TMFWSI is shutting down with code {}... Status: {}", status, (status ? "FAIL" : "OK")));

    if (pause)
    {
        log(log_level::info, "Press ENTER to close the program.");
        std::cin.get();
    }

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
    if (logger)
    {
        delete logger;
        logger = nullptr;
    }
    if (mutex)
    {
        ReleaseMutex(mutex);
        CloseHandle(mutex);
        mutex = nullptr;
    }

    return status;
}
