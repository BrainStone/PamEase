#include <crypt.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <shadow.h>

#include <generator>
#include <iostream>

#include "pam_exception.hpp"
#include "pam_utils.hpp"

using namespace std::string_literals;

constexpr std::string_view ALLOWED_CHARS =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:'\",.<>?/\\|`~";

bool check_password(std::string_view password, std::string_view stored_hash) {
	thread_local crypt_data data{};

	char* computed_hash = crypt_r(password.data(), stored_hash.data(), &data);
	return computed_hash != nullptr && computed_hash == stored_hash;
}

std::generator<std::string> levenshtein_variants(std::string_view password) {
	// Storage. Attempt to avoid changing buffer size as much as possible
	std::string variant;
	variant.reserve(password.size() + 1);

	// Deletions
	{
		variant.resize(password.size() - 1);
		std::copy(password.begin() + 1, password.end(), variant.begin());

		co_yield variant;

		auto p_it = password.begin();
		const auto v_end = variant.end();
		for (auto v_it = variant.begin(); v_it != v_end; ++p_it, ++v_it) {
			*v_it = *p_it;

			co_yield variant;
		}
	}

	// Substitutions
	{
		variant = password;

		const auto v_end = variant.end();
		for (auto v_it = variant.begin(); v_it != v_end; ++v_it) {
			char original = *v_it;

			for (char c : ALLOWED_CHARS) {
				if (original != c) {
					*v_it = c;

					co_yield variant;
				}
			}

			*v_it = original;
		}
	}

	// Insertions
	{
		variant.resize(password.size() + 1);

		const auto v_end = variant.rend();
		auto v_it = variant.rbegin();
		while (true) {
			for (char c : ALLOWED_CHARS) {
				*v_it = c;

				co_yield variant;
			}

			if (++v_it == v_end) break;
			*(v_it - 1) = *v_it;
		}
	}
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

		if (check_password(password, stored_hash)) return PAM_SUCCESS;

		for (const auto& password_variant : levenshtein_variants(password)) {
			if (check_password(password_variant, stored_hash)) return PAM_SUCCESS;
		}

		return PAM_AUTH_ERR;
	});
}

// Required to exist, but does nothing
PAM_EXPORT int pam_sm_setcred([[maybe_unused]] pam_handle_t* pamh, [[maybe_unused]] int flags,
                              [[maybe_unused]] int argc, [[maybe_unused]] const char** argv) {
	return PAM_SUCCESS;
}
