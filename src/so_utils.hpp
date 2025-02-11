#pragma once

#include <filesystem>
#include <string>
#include <typeinfo>

#define MODULE_LOG(stream) stream << pam_ease::get_so_name() << ": "

namespace pam_ease {

std::filesystem::path get_so_path(void* func = nullptr);
std::string get_so_name(void* func = nullptr);

std::string unmangle(const std::type_info& type_info);
std::string unmangle(const char* mangled);

template <typename T>
std::string get_unmangled_type_name(const T& val) {
	return pam_ease::unmangle(typeid(val));
}

}  // namespace pam_ease
