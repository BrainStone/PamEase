#pragma once

#include <security/_pam_types.h>

#include <optional>
#include <string_view>
#include <utility>
#include <functional>

#define PAM_EXPORT extern "C" __attribute__((visibility("default"))) [[maybe_unused]]

namespace pam_ease {

int handle_pam_exceptions(const std::function<int()>& func);
std::pair<std::string_view, std::optional<std::string_view>> get_login_credentials(pam_handle_t* pamh);

}
