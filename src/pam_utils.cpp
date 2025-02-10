#include "pam_utils.hpp"

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "pam_exception.hpp"

namespace pam_ease {

std::pair<std::string_view, std::optional<std::string_view>> getLoginCredentials(pam_handle_t* pamh) {
	const char* username;
	const char* password;

	// Retrieve username
	if (pam_get_user(pamh, &username, nullptr) != PAM_SUCCESS) {
		throw pam_exception(PAM_CRED_UNAVAIL, "Can't determine username");
	}

	// Retrieve password
	if (pam_get_authtok(pamh, PAM_AUTHTOK, &password, nullptr) != PAM_SUCCESS) {
		throw pam_exception(PAM_CRED_UNAVAIL, "Can't determine authtok");
	}

	return {username, (password == nullptr) ? std::nullopt : std::make_optional(password)};
}

}  // namespace pam_ease
