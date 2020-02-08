
#ifndef __RATELIMITER__HH__
#define __RATELIMITER__HH__

#include <string>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>

class RateLimiter {
private:
	std::unordered_map<uint64_t, uint32_t> limiters;
	mutable std::shared_mutex m;  // Mutex for hashmap updates
	uint32_t hits_per_second;
	std::thread refiller;
	volatile bool end;

public:
	// Checks whether we hit the limit
	bool check(uint64_t iphash) const {
		std::shared_lock lock(m);
		return (limiters.count(iphash) && limiters.at(iphash) > hits_per_second);
	}
	// Accounts one access to the given access ID
	void consume(uint64_t iphash) {
		std::unique_lock lock(m);
		limiters[iphash]++;
	}

	RateLimiter(unsigned maxhps)
	 : hits_per_second(maxhps), end(false) {
		refiller = std::thread([this] {
			while (!this->end) {
				sleep(1);
				if (!this->end) {
					std::unique_lock lock(m);
					this->limiters.clear();
				}
			}
		});
	}

	~RateLimiter() {
		end = true;
		refiller.join();
	}
};

#endif

