#include "so_utils.hpp"

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

}  // namespace pam_ease
