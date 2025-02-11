#pragma once

#include <generator>
#include <mutex>
#include <type_traits>

namespace pam_ease {

template <typename T>
class sync_generator {
private:
	using generator_iterator = decltype(std::declval<std::generator<T>>().begin());
	using generator_iterator_sentinel = decltype(std::declval<std::generator<T>>().end());

	std::generator<T> generator;
	generator_iterator it;
	generator_iterator_sentinel end;
	std::mutex mutex;

public:
	// Construct by moving in a generator.
	explicit sync_generator(std::generator<T>&& gen);

	sync_generator(const sync_generator<T>& other) = delete;
	sync_generator(sync_generator<T>&& other) = default;

	sync_generator& operator=(const sync_generator<T>& other) = delete;
	sync_generator& operator=(sync_generator<T>&& other) = default;

	// Returns the next value, or std::nullopt if finished.
	std::optional<T> next();
};

}  // namespace pam_ease

#include "sync_generator.inc"
