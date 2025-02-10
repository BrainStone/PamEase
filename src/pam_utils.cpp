#include "pam_utils.hpp"

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include <iostream>

#include "pam_exception.hpp"
#include "so_utils.hpp"

namespace pam_ease {

int handle_pam_exceptions(const std::function<int()>& func) {
	try {
		// Execute the provided code.
		return func();
	} catch (pam_ease::pam_exception& e) {
		if (e.has_message()) std::cerr << "Error in " << pam_ease::get_so_name() << ": " << e.what() << std::endl;

		return e.pam_code();
	} catch (std::exception& e) {
		std::cerr << "Unexpected error in " << pam_ease::get_so_name() << ": " << e.what() << std::endl;

		return PAM_SERVICE_ERR;
	} catch (...) {
		std::cerr << "Unknown error in " << pam_ease::get_so_name() << std::endl;

		return PAM_SERVICE_ERR;
	}
}

std::pair<std::string_view, std::optional<std::string_view>> getLoginCredentials(pam_handle_t* pamh) {
	const char* username;
	const char* password;

	// Retrieve username
	if (pam_get_user(pamh, &username, nullptr) != PAM_SUCCESS) {
		throw pam_exception(PAM_CRED_UNAVAIL, "Can't determine username");
	}

	// Retrieve password
	if (pam_get_authtok(pamh, PAM_AUTHTOK, &password, nullptr) != PAM_SUCCESS) {
		// No message, because canceling the login attempt, causes this function fail, which is ok. We just fail the
		// auth attempt and move on.
		throw pam_exception(PAM_AUTH_ERR);
	}

	return {username, (password == nullptr) ? std::nullopt : std::make_optional(password)};
}

}  // namespace pam_ease
