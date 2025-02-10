#include <crypt.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <shadow.h>

#include <iostream>

#include "pam_exception.hpp"
#include "pam_utils.hpp"

using namespace std::string_literals;

bool check_password(std::string_view password, std::string_view stored_hash) {
	thread_local crypt_data data{};

	char* computed_hash = crypt_r(password.data(), stored_hash.data(), &data);
	return computed_hash != nullptr && computed_hash == stored_hash;
}

// PAM authentication function
PAM_EXPORT int pam_sm_authenticate(pam_handle_t* pamh, [[maybe_unused]] int flags, [[maybe_unused]] int argc,
                                   [[maybe_unused]] const char** argv) {
	return pam_ease::handle_pam_exceptions([&]() -> int {
		auto auth = pam_ease::get_login_credentials(pamh);

		// Check if the password is set
		if (!auth.second) return PAM_AUTH_ERR;

		std::string_view& username = auth.first;
		std::string_view& password = *auth.second;

		struct spwd* shadow_entry;
		shadow_entry = getspnam(username.data());
		if (!shadow_entry || !shadow_entry->sp_pwdp) {
			throw pam_ease::pam_exception(PAM_CRED_UNAVAIL,
			                              "Can't determine hashed password of user "s + username.data());
		}
		std::string_view stored_hash = shadow_entry->sp_pwdp;

		if (check_password(password, stored_hash)) {
			return PAM_SUCCESS;
		}

		return PAM_IGNORE;
	});
}

// Required to exist, but does nothing
PAM_EXPORT int pam_sm_setcred([[maybe_unused]] pam_handle_t* pamh, [[maybe_unused]] int flags,
                              [[maybe_unused]] int argc, [[maybe_unused]] const char** argv) {
	return PAM_SUCCESS;
}
