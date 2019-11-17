
#include <atomic>
#include <mutex>
#include <condition_variable>

template<typename T>
class ConcurrentQueue {
public:
	ConcurrentQueue() : nowriter(false) {}

	void close() {
		std::unique_lock<std::mutex> lock(mutex_);
		nowriter = true;
		condvar.notify_all();
	}

	void push(T item) {
		std::unique_lock<std::mutex> lock(mutex_);
		q.push_back(std::move(item));
		lock.unlock();
		condvar.notify_one();
	}

	bool pop(T *item) noexcept {
		std::unique_lock<std::mutex> lock(mutex_);
		while (q.empty() && !nowriter)
			condvar.wait(lock);

		// Writer signaled end already
		if (nowriter)
			return false;

		*item = std::move(q.front());
		q.pop_front();
		return true;
	}

private:
	std::list<T> q;     // list of items
	std::mutex mutex_;  // protection mutex
	std::condition_variable condvar; // Wait variable
	std::atomic<bool> nowriter;      // Indicates no more writes will happen
};


