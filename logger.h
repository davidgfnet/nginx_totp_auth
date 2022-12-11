
#ifndef __LOGGING__HH__
#define __LOGGING__HH__

#include <mutex>
#include <ctime>
#include <thread>
#include <condition_variable>
#include <unistd.h>
#include <fcntl.h>

static time_t last_midnight() {
	time_t t = time(NULL);
	t -= (t % 86400);
	return t;
}

static std::string logts(bool date = false) {
	char fmtime[128];

	std::chrono::duration<long>seccnt(time(NULL));
	std::chrono::time_point<std::chrono::system_clock> tp(seccnt);

	const std::time_t t = std::chrono::system_clock::to_time_t(tp);
	std::tm utctm;
	gmtime_r(&t, &utctm);
	std::strftime(fmtime, sizeof(fmtime), date ? "%Y%m%d" : "%Y%m%d-%H%M%S", &utctm);
	return fmtime;
}

class Logger {
public:
	Logger(std::string logfile)
	 : logfile(logfile) {
		// Create/append first log file
		rotatelog();

		// Create thread and start
		flusher = std::thread(&Logger::flushthread, this);
	}

	~Logger() {
		// Set end and wake flush thread
		{
			std::unique_lock<std::mutex> lock(waitmu);
			end = true;
		}
		waitcond.notify_all();

		// Wait for thread
		flusher.join();
	}

	void log(std::string line) {
		// Add line to memory buffer
		std::lock_guard<std::mutex> guard(mu);
		logbuffer += logts() + " " + line + "\n";

		// Tell flusher to flush this (lazily)
		waitcond.notify_all();
	}

private:

	void rotatelog() {
		// Try to rotate the log
		std::string localtime = logts(true);
		if (this->logdate == localtime && logfd >= 0)
			return;   // Already using that log

		this->logdate = localtime;
		if (logfd >= 0)
			close(logfd);

		std::string fn = logfile + "_" + this->logdate;
		logfd = open(fn.c_str(), O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR);

		// Next run
		next_rotation = last_midnight() + 24*60*60;
	}

	void flushthread() {
		// Keeps flushing logs to disk periodically
		while (true) {
			std::unique_lock<std::mutex> lock(waitmu);
			waitcond.wait(lock);

			bool empty = false;
			do {
				// Read buffer we want to write
				std::string chunk;
				{
					std::lock_guard<std::mutex> guard(mu);
					chunk = logbuffer.substr(0, 256*1024);
				}

				// Try to write as much as possible
				int writtenbytes = 0;
				while (!chunk.empty()) {
					int w = write(logfd, &chunk[writtenbytes], chunk.size() - writtenbytes);
					if (w > 0)
						writtenbytes += w;
					else
						break;
				}

				// Remove the written bits
				{
					std::lock_guard<std::mutex> guard(mu);
					logbuffer = logbuffer.substr(writtenbytes);
					empty = logbuffer.empty();
				}

				// Check log rotation
				if (time(NULL) > next_rotation && empty)
					rotatelog();
			} while (!empty);

			if (end)
				break;
		}
	}

	// List of stuff to be flushed
	std::string logbuffer;
	std::mutex mu;

	// Thread that sits in the background flushing stuff
	std::thread flusher;
	std::mutex waitmu;
	std::condition_variable waitcond;
	std::string logdate;
	bool end = false;

	// Log management
	std::string logfile;
	int logfd = -1;
	time_t next_rotation = 0;
};

#endif

