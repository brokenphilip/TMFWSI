#pragma once

#include <iostream>
#include <filesystem>
#include <fstream>

#define CURL_STATICLIB
#include "../ext/curl/curl.h"

#include "../ext/zlib/zlib.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../ext/httplib.h"

#define myprint(stream) std::cout << stream << std::endl

#define TMFWSI "TrackMania Forever Web Services Interceptor"
#define TMFWSI_VERSION "1.0"

// 127 :3c
#define DEFAULT_ADDRESS "127.58.51.99"

#define HOSTS_PATH	"C:\\Windows\\system32\\drivers\\etc\\"
#define HOSTS		HOSTS_PATH "hosts"

namespace tmfwsi
{
	inline char ip[16] = { 0 };

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

		void openssl();

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

	int main_do_hosts();
	int main_undo_hosts();

	namespace main
	{
		int init();
		int generate_ssl_certificate();
		int do_hosts();

		BOOL WINAPI control_handler(DWORD ctrl);

		namespace ssl_server
		{
			int loop();

			void get(const httplib::Request& request, httplib::Response& response);
		}

		int undo_hosts();

		int cleanup(int status);
	}
}