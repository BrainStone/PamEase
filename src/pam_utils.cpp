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
	} catch (const pam_ease::pam_exception& e) {
		// We're using `std::endl` here (and in all further catch blocks) on purpose to flush the stream before exiting
		if (e.has_message()) MODULE_LOG(std::cerr) << "Error: " << e.what() << std::endl;

		return e.pam_code();
	} catch (const std::exception& e) {
		MODULE_LOG(std::cerr) << "Unexpected error: " << pam_ease::get_unmangled_type_name(e) << ": " << e.what()
		                      << std::endl;

		return PAM_SERVICE_ERR;
	} catch (...) {
		MODULE_LOG(std::cerr) << "Unknown error" << std::endl;

		return PAM_SERVICE_ERR;
	}
}

std::pair<std::string_view, std::optional<std::string_view>> get_login_credentials(pam_handle_t* pamh) {
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
