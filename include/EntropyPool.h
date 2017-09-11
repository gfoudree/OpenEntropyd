#ifndef ENTROPYPOOL_H
#define ENTROPYPOOL_H

#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/random.h>
#include <memory>
#include <time.h>
#include <queue>
#include <functional>
#include <thread>
#include <future>

typedef struct entropy_queue {
  uint8_t priority;
  uint8_t size;
  //std::promise<std::unique_ptr<unsigned char[]> > hPromise;
  bool operator> (const entropy_queue &b) const {
    return size > b.size;
  }
} entropy_queue;

class EntropyPool {
private:
  std::priority_queue<struct entropy_queue> peers;
  std::unique_ptr<unsigned char[]> getRandomBlock(const unsigned int size);
  void workerThread();

public:
  EntropyPool();

  static unsigned int getAvailEntropy();
  void requestEntropy(entropy_queue &eq);
};

#endif
