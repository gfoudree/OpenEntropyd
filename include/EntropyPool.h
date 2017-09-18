#ifndef ENTROPYPOOL_H
#define ENTROPYPOOL_H

#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/random.h>
#include <sys/syscall.h>
#include <memory>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <queue>
#include <strings.h>
#include <functional>
#include <thread>
#include <future>
typedef struct cpuid_struct {
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
} cpuid_t;

typedef struct entropy_queue {
  uint8_t priority;
  uint8_t size;

  bool operator> (const entropy_queue &b) const {
    return size > b.size;
  }
} entropy_queue;

class EntropyPool {
private:
  std::priority_queue<struct entropy_queue> peers;
  std::unique_ptr<unsigned char[]> getRandomBlock(const unsigned int size);

public:
  EntropyPool();

  static unsigned int getAvailEntropy();
  std::unique_ptr<unsigned char[]> requestEntropy(entropy_queue &eq);
  static uint32_t getIntelRandom();
};

#endif
