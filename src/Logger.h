#ifndef LOGGER_H
#define LOGGER_H

#define LOG_FILE "/var/log/openentropyd"

#include <iostream>
#include <fstream>

class Logger {
private:
	time_t ltime;
	std::ofstream logFile;
public:
	void logToFile(const char *logEntry);
	Logger();
};

#endif
