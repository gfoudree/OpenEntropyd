#include "Logger.h"

void Logger::logToFile(const char *logEntry) {
	time_t ltime;
	std::ofstream logFile(LOG_FILE, std::ios::app);
	if (logFile.is_open()) {
		time(&ltime);
		char time_buf[26];
		struct tm *tm_info = localtime(&ltime);

		strftime(time_buf, 25, "%m-%d-%Y %H:%M:%S", tm_info);

		logFile << "[" << time_buf << "] " << logEntry << std::endl;
		std::cout << "[" << time_buf << "] " << logEntry << std::endl;
		logFile.close();
	}
}
