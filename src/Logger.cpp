#include "Logger.h"

void Logger::logToFile(const char *logEntry) {
	if (logFile.is_open()) {
		time(&ltime);

		logFile << "[" << ctime(&ltime) << "] " << logEntry << std::endl;
		logFile.close();
	}
}

Logger::Logger() {
	std::ofstream logFile(LOG_FILE, std::ios::app);
}
