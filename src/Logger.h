#ifndef LOGGER_H
#define LOGGER_H

#define LOG_FILE "/var/log/openentropyd"

#include <iostream>
#include <fstream>
#include <time.h>

class Logger {
public:
	static void logToFile(const char *logEntry);
};

#endif
