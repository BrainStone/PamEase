#pragma once

#include <security/_pam_types.h>

#include <optional>
#include <string_view>
#include <utility>
#include <functional>

namespace pam_ease {

int handle_pam_exceptions(const std::function<int()>& func);
std::pair<std::string_view, std::optional<std::string_view>> getLoginCredentials(pam_handle_t* pamh);

}
