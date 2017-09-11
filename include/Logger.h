#ifndef LOGGER_H
#define LOGGER_H

#define LOG_FILE "/var/log/openentropyd"

#include <iostream>
#include <fstream>
#include <time.h>
#include <sstream>

template <class T>
class Logger {
public:
	static void logToFile(T logEntry);
};

template <class T>
void Logger<T>::logToFile(T logEntry) {

	std::stringstream ss;
	ss << logEntry;

	time_t ltime;
	std::ofstream logFile(LOG_FILE, std::ios::app);
	if (logFile.is_open()) {
		time(&ltime);
		char time_buf[26];
		struct tm *tm_info = localtime(&ltime);

		strftime(time_buf, 25, "%m-%d-%Y %H:%M:%S", tm_info);

		logFile << "[" << time_buf << "] " << ss.str() << std::endl << std::flush;
		std::cout << "[" << time_buf << "] " << ss.str() << std::endl << std::flush;
		logFile.close();
	}
	else {
		std::cerr << "[ERROR] Unable to open " << LOG_FILE << std::endl;
	}
}

#endif
