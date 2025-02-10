#include "so_utils.hpp"

#include <cxxabi.h>
#include <dlfcn.h>

namespace pam_ease {

std::filesystem::path get_so_path(void* func) {
	if (func == nullptr) func = reinterpret_cast<void*>(pam_ease::get_so_path);

	Dl_info info;

	if (!dladdr(func, &info)) {
		return "unknown";
	}

	return info.dli_fname;
}

std::string get_so_name(void* func) {
	return get_so_path(func).filename();
}

std::string unmangle(const std::type_info& type_info) {
	return unmangle(type_info.name());
}

std::string unmangle(const char* mangled) {
	int error;
	char* raw_name = abi::__cxa_demangle(mangled, nullptr, nullptr, &error);
	std::string name{raw_name};
	std::free(raw_name);

	if (!error)
		return name;
	else if (error == -1)
		throw std::runtime_error{"unmangle: memory allocation failed"};
	else if (error == -2)
		throw std::runtime_error{"unmangle: not a valid mangled name"};
	else if (error == -3)
		throw std::invalid_argument{"unmangle: memory allocation failed"};
	else
		throw std::runtime_error{"unmangle: unknown error code: " + std::to_string(error)};
}

}  // namespace pam_ease
