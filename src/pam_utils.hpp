#pragma once

#include <security/_pam_types.h>

#include <optional>
#include <string_view>
#include <utility>

namespace pam_ease {

std::pair<std::string_view, std::optional<std::string_view>> getLoginCredentials(pam_handle_t* pamh);

}
