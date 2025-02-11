#pragma once

#include "sync_generator.hpp"

namespace pam_ease {

template <typename T>
sync_generator<T>::sync_generator(std::generator<T>&& generator)
    : generator(std::move(generator)), it(this->generator.begin()), end(this->generator.end()) {}

template <typename T>
std::optional<T> sync_generator<T>::next() {
	std::lock_guard<std::mutex> lock(mutex);

	if (it == end) return std::nullopt;

	T value = *it;
	++it;
	
	return value;
}

}  // namespace pam_ease
