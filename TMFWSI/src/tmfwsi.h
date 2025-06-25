#pragma once

#include <filesystem>
#include <regex>

#define CURL_STATICLIB
#include "../ext/curl/curl.h"

#include "../ext/zlib/zlib.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../ext/httplib.h"

#define TMFWSI "TrackMania Forever Web Services Interceptor"

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! MAKE SURE TO UPDATE THE VERSION RESOURCE AS WELL !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#define TMFWSI_VERSION "1.0"

#define HOSTS_PATH	"C:\\Windows\\system32\\drivers\\etc\\"
#define HOSTS		HOSTS_PATH "hosts"

namespace fs = std::filesystem;

namespace tmfwsi
{
	// 127 WSI
	inline std::string server_ip = "127.87.83.73";

	namespace error
	{
		// Simple RAII implementation of GetLastError
		class last
		{
			LPSTR msg = nullptr;
		public:
			last(DWORD last_error);
			last() : last(GetLastError()) {}

			~last();

			const char* message();
		};

		constexpr int customer = 1 << 29;

		using error_t = DWORD;

		/* TMFWSI Error Causes (0 - 15) */
		enum cause : int
		{
			shell_execute_ex = 1,
			wait_for_single_object,
			get_exit_code_process,
			delete_file,
			copy_file,
			create_file,
			write_file,
			get_file_attributes,

			_last = 15,
			_bits = 24,

			_mask = _last << _bits
		};

		// Windows to TMFWSI
		error_t make(DWORD e, cause f);

		// TMFWSI to Windows
		DWORD parse(error_t e_tmfwsi);

		const char* cause_name(error_t e_tmfwsi);
	}

	namespace file
	{
		inline fs::path exe_path = []()
		{
			char path[MAX_PATH] = { 0 };
			GetModuleFileNameA(NULL, path, MAX_PATH);
			return fs::path(path).parent_path();
		}();

		class writer
		{
			HANDLE handle = INVALID_HANDLE_VALUE;
			DWORD create_file_gle = 0;
		public:
			writer(const char* file);
			writer(fs::path const& path) : writer(path.string().c_str()) {}
			~writer();

			tmfwsi::error::error_t write(const char* str, DWORD len);
			tmfwsi::error::error_t write(std::string const& str);
		};

		DWORD check_permissions(const char* file);
		DWORD check_permissions(fs::path const& path);

		DWORD erase(const char* file, bool must_exist = false);
		DWORD erase(fs::path const& path, bool must_exist = false);
	}

	int main_do_hosts();
	int main_undo_hosts();

	namespace curl_writefn
	{
		template <typename T>
		using writefn_t = size_t(void* buffer, size_t size, size_t n_items, T* data);

		writefn_t<void> dummy;
		writefn_t<std::string> string;
	}

	namespace main
	{
#if defined(_DEBUG)
		inline bool debug = true;
#else
		inline bool debug = false;
#endif

		enum class log_mode
		{
			off,
			on,
			verbose
		};
		inline log_mode logging = log_mode::off;

		inline bool pause = true;

		inline HANDLE mutex = nullptr;

		inline std::string tmfws_ip = "";

		inline std::string xml = "";

		inline CURL* curl = nullptr;
		inline EVP_PKEY* pkey = nullptr;
		inline X509* x509 = nullptr;

		inline file::writer* logger = nullptr;

		// Starts a new hidden TMFWSI instance as admin with the specified arguments
		tmfwsi::error::error_t run(const char* args);
		tmfwsi::error::error_t run(std::string const& args);

		enum class log_level
		{
			info,
			warn,
			error,
			debug
		};

		void log(log_level ll, std::string const& str);

		void curl_log(log_level ll, CURLcode c);
		void openssl_log(log_level ll);
		void windows_log(log_level ll, DWORD gle);

		int curl_debug(CURL* handle, curl_infotype it, char* data, size_t size, void* clientp);
		void curl_cookies_debug();

		int init_console_and_logging();
		int init_mutex();
		int init_resource();
		int init_curl();
		int update_check();
		int get_tmfws_ip();
		int generate_ssl_certificate();
		int do_hosts();

		BOOL WINAPI control_handler(DWORD ctrl);

		namespace ssl_server
		{
			inline httplib::SSLServer* server = nullptr;
			inline bool stopped = false;

			int loop();

			void get(const httplib::Request& request, httplib::Response& response);
		}

		int undo_hosts();

		int cleanup(int status);
	}
}