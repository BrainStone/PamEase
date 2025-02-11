#include <crypt.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <shadow.h>

#include <atomic>
#include <generator>
#include <iomanip>
#include <iostream>
#include <thread>
#include <vector>

#include "pam_exception.hpp"
#include "pam_utils.hpp"
#include "so_utils.hpp"
#include "sync_generator.hpp"

using namespace std::string_literals;

#if defined(DEBUG) || !defined(NDEBUG)
constexpr bool debug = true;
#else
constexpr bool debug = false;
#endif

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

void worker_function(pam_ease::sync_generator<std::string>& generator, std::string_view stored_hash,
                     std::atomic<bool>& found) {
	while (!found.load(std::memory_order_relaxed)) {
		auto password_opt = generator.next();
		if (!password_opt) break;

		if (check_password(*password_opt, stored_hash)) {
			found.store(true, std::memory_order_relaxed);
			break;
		}
	}
}

// PAM authentication function
PAM_EXPORT int pam_sm_authenticate(pam_handle_t* pamh, [[maybe_unused]] int flags, [[maybe_unused]] int argc,
                                   [[maybe_unused]] const char** argv) {
	return pam_ease::handle_pam_exceptions([&]() -> int {
		// Time the fuzzing
		// TODO: Read from argv
		const bool time = debug;

		auto auth = pam_ease::get_login_credentials(pamh);

		// Check if the password is set
		if (!auth.second) {
			if (time) MODULE_LOG(std::clog) << "No password set!\n";

			return PAM_AUTH_ERR;
		}

		// Start timing here, because
		const std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();

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
			if (time) MODULE_LOG(std::clog) << "Password matched directly.\n";

			return PAM_SUCCESS;
		}

		const std::size_t thread_count = std::thread::hardware_concurrency();
		std::atomic<bool> found{false};
		std::vector<std::thread> threads;
		pam_ease::sync_generator<std::string> generator{levenshtein_variants(password)};

		threads.reserve(thread_count);
		for (std::size_t i = 0; i < thread_count; ++i) {
			threads.emplace_back(worker_function, std::ref(generator), stored_hash, std::ref(found));
		}

		for (std::thread& thread : threads) {
			thread.join();
		}

		if (time) {
			const std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
			const double duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - begin).count();

			MODULE_LOG(std::clog) << "Took " << std::fixed << std::setprecision(3) << duration << "s to "
			                      << (found.load() ? "successfully" : "unsuccessfully")
			                      << " find a matching password.\n";
		}

		return found.load() ? PAM_SUCCESS : PAM_AUTH_ERR;
	});
}

// Required to exist, but does nothing
PAM_EXPORT int pam_sm_setcred([[maybe_unused]] pam_handle_t* pamh, [[maybe_unused]] int flags,
                              [[maybe_unused]] int argc, [[maybe_unused]] const char** argv) {
	return PAM_SUCCESS;
}
