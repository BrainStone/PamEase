#include <crypt.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <shadow.h>

#include <atomic>
#include <boost/process.hpp>
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

constexpr std::string_view CHAR_GROUPS[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789",
                                            "!@#$%^&*()-_=+[]{};:'\",.<>?/\\|`~"};

bool check_password_with_hash(std::string_view stored_hash, std::string_view password) {
	thread_local crypt_data data{};

	char* computed_hash = crypt_r(password.data(), stored_hash.data(), &data);
	return computed_hash != nullptr && computed_hash == stored_hash;
}

bool check_password_with_unix_chkpwd(std::string_view user, std::string_view password) {
	boost::process::opstream child_in;
	boost::process::child proc("/usr/sbin/unix_chkpwd", user.data(), "nonull",
	                           boost::process::std_in<child_in, boost::process::std_out> boost::process::null,
	                           boost::process::std_err > boost::process::null);

	child_in.pipe().write(password.data(), static_cast<boost::process::pipe::int_type>(password.size() + 1));
	child_in.pipe().close();

	proc.wait();
	return proc.exit_code() == PAM_SUCCESS;
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

	for (const auto& chars_to_check : CHAR_GROUPS) {
		// Substitutions
		{
			variant = password;

			const auto v_end = variant.end();
			for (auto v_it = variant.begin(); v_it != v_end; ++v_it) {
				char original = *v_it;

				for (char c : chars_to_check) {
					if (original == c) [[unlikely]]
						continue;

					*v_it = c;

					co_yield variant;
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
				for (char c : chars_to_check) {
					*v_it = c;

					co_yield variant;
				}

				if (++v_it == v_end) [[unlikely]]
					break;
				*(v_it - 1) = *v_it;
			}
		}
	}
}

void worker_function(pam_ease::sync_generator<std::string>& generator, std::atomic<bool>& found,
                     const std::function<bool(std::string_view)>& password_checker) {
	while (!found.load(std::memory_order_relaxed)) {
		auto password = generator.next();
		if (!password) break;

		if (password_checker(*password)) {
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
		std::function<bool(std::string_view)> password_checker;

		{
			struct spwd* shadow_entry;
			shadow_entry = getspnam(username.data());
			if (shadow_entry && shadow_entry->sp_pwdp) {
				std::string_view stored_hash = shadow_entry->sp_pwdp;

				password_checker = [stored_hash](std::string_view&& pasword) {
					return check_password_with_hash(stored_hash, std::forward<std::string_view>(pasword));
				};
			} else {
				password_checker = [username](std::string_view&& pasword) {
					return check_password_with_unix_chkpwd(username, std::forward<std::string_view>(pasword));
				};
			}
		}

		if (password_checker(password)) {
			if (time) MODULE_LOG(std::clog) << "Password matched directly.\n";

			return PAM_SUCCESS;
		}

		const std::size_t thread_count = std::thread::hardware_concurrency();
		std::atomic<bool> found{false};
		std::vector<std::thread> threads;
		pam_ease::sync_generator<std::string> generator{levenshtein_variants(password)};

		threads.reserve(thread_count);
		for (std::size_t i = 0; i < thread_count; ++i) {
			threads.emplace_back(worker_function, std::ref(generator), std::ref(found), password_checker);
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
