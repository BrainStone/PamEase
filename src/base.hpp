#pragma once

#include <security/_pam_types.h>

#include <string>
#include <utility>

std::pair<std::string, std::string> getLoginCredentials(pam_handle_t* pamh);
