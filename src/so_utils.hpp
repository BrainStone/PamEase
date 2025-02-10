#pragma once

#include <filesystem>
#include <string>

namespace pam_ease {

std::filesystem::path get_so_path(void* func = nullptr);
std::string get_so_name(void* func = nullptr);

}  // namespace pam_ease
