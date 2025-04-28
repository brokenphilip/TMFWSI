#pragma once

#include <iostream>
#include <filesystem>
#include <fstream>
#include <regex>

#define CURL_STATICLIB
#include "../ext/curl/curl.h"

#include "../ext/zlib/zlib.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../ext/httplib.h"

#define TMFWSI "TrackMania Forever Web Services Interceptor"
#define TMFWSI_VERSION "1.0"

// 127 :3c
#define DEFAULT_ADDRESS "127.58.51.99"

#define HOSTS_PATH	"C:\\Windows\\system32\\drivers\\etc\\"
#define HOSTS		HOSTS_PATH "hosts"

namespace tmfwsi
{
	inline char ip[16] = { 0 };

	inline std::string xml = "";

	inline CURL* curl = nullptr;
	inline EVP_PKEY* pkey = nullptr;
	inline X509* x509 = nullptr;
	
	inline httplib::SSLServer* server = nullptr;
	inline bool server_stopped = false;

	// TODO: maybe this should be a launch option?
#if defined(_DEBUG)
	inline bool debug = true;
#else
	inline bool debug = false;
#endif

	enum class log_level
	{
		info,
		warn,
		error,
		debug
	};

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

		void curl(log_level ll, CURLcode c);
		void openssl(log_level ll);
		void windows(log_level ll, DWORD gle);

		constexpr int customer = 1 << 29;

		/* TMFWSI Error Causes (0 - 15) */
		enum cause : int
		{
			shell_execute_ex = 1,
			wait_for_single_object,
			get_exit_code_process,
			delete_file,
			copy_file,
			std_ofstream,

			_last = 15,
			_bits = 24,

			_mask = _last << _bits
		};

		// Windows to TMFWSI
		DWORD make(DWORD e, cause f);

		// TMFWSI to Windows
		DWORD parse(DWORD e_tmfwsi);

		const char* cause_name(int e_tmfwsi);
	}

	// Starts a new hidden TMFWSI instance as admin with the specified arguments
	DWORD run(LPCSTR args);

	void log(log_level ll, std::string str);

	int main_do_hosts();
	int main_undo_hosts();

	namespace main
	{
		int init_console();
		int update_check();
		int init_resource();
		int init_curl();
		int generate_ssl_certificate();
		int do_hosts();

		BOOL WINAPI control_handler(DWORD ctrl);

		namespace ssl_server
		{
			int loop();
			void reset_curl(curl_slist* slist);

			void get(const httplib::Request& request, httplib::Response& response);
		}

		int undo_hosts();

		int cleanup(int status);
	}
}