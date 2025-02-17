#pragma once

#include <stdexcept>
#include <system_error>

namespace pam_ease {

// pam_exception is already taken by a preprocessor macro, so even namespacing doesn't help...
class pam_exception : public std::runtime_error {
protected:
	static constexpr char EMPTY_MESSAGE[] = "No error message";

	int _pam_code;

public:
	explicit pam_exception(int pam_code);
	pam_exception(int pam_code, const std::string& what_arg);
	pam_exception(int pam_code, const char* what_arg);

	pam_exception(const pam_exception& other) noexcept = default;
	pam_exception(pam_exception&& other) noexcept = default;

	~pam_exception() noexcept override = default;

	pam_exception& operator=(const pam_exception&) noexcept = default;
	pam_exception& operator=(pam_exception&&) noexcept = default;

	[[nodiscard]] int pam_code() const noexcept;
	[[nodiscard]] bool has_message() const noexcept;
};

}  // namespace pam_ease
