#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <iostream>

#include "pam_exception.hpp"
#include "pam_utils.hpp"
#include "so_utils.hpp"

// PAM authentication function
extern "C" [[maybe_unused]] int pam_sm_authenticate(pam_handle_t* pamh, [[maybe_unused]] int flags,
                                                    [[maybe_unused]] int argc, [[maybe_unused]] const char** argv) {
	try {
		auto auth = pam_ease::getLoginCredentials(pamh);

		std::clog << "Username: " << auth.first;
		if (auth.second) std::clog << " - Password: " << *auth.second;
		std::clog << std::endl;

		return PAM_IGNORE;
	} catch (pam_ease::pam_exception& e) {
		std::cerr << "Error in " << pam_ease::get_so_name() << ": " << e.what() << std::endl;

		return e.pam_code();
	} catch (std::exception& e) {
		std::cerr << "Unexpected error in " << pam_ease::get_so_name() << ": " << e.what() << std::endl;

		return PAM_SERVICE_ERR;
	} catch (...) {
		std::cerr << "Unknown error in " << pam_ease::get_so_name() << std::endl;

		return PAM_SERVICE_ERR;
	}
}
