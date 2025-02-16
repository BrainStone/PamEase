#pragma once

extern "C" {
#include <security/_pam_types.h>
}

#include <functional>
#include <optional>
#include <string_view>
#include <utility>

#define PAM_EXPORT extern "C" __attribute__((visibility("default"))) [[maybe_unused]]

namespace pam_ease {

int handle_pam_exceptions(const std::function<int()>& func);
std::pair<std::string_view, std::optional<std::string_view>> get_login_credentials(pam_handle_t* pamh);
void set_password(pam_handle_t* pamh, std::string_view password);

}  // namespace pam_ease
