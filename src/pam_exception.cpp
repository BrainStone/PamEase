#include "pam_exception.hpp"

namespace pam_ease {

pam_exception::pam_exception(int pam_code) : std::runtime_error{""}, _pam_code{pam_code} {}

pam_exception::pam_exception(int pam_code, const std::string& what_arg)
    : std::runtime_error{what_arg}, _pam_code{pam_code} {}

pam_exception::pam_exception(int pam_code, const char* what_arg) : std::runtime_error{what_arg}, _pam_code{pam_code} {}

[[nodiscard]] int pam_exception::pam_code() const noexcept {
	return _pam_code;
}

}  // namespace pam_ease
