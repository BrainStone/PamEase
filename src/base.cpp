#include "base.hpp"

#include <security/pam_ext.h>
#include <security/pam_modules.h>

std::pair<std::string, std::string> getLoginCredentials(pam_handle_t* pamh) {
	const char* username;
	const char* password;

	// Retrieve username
	if (pam_get_user(pamh, &username, nullptr) != PAM_SUCCESS) {
		// return PAM_AUTH_ERR;
	}

	// Retrieve password
	if (pam_get_authtok(pamh, PAM_AUTHTOK, &password, nullptr) != PAM_SUCCESS) {
		// return PAM_AUTH_ERR;
	}

	return {username, password};
}
