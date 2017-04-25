#ifndef ENTROPYPOOL_H
#define ENTROPYPOOL_H

#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/random.h>
#include <memory>
#include <time.h>

class EntropyPool {
public:
  EntropyPool();

  static unsigned int getAvailEntropy();
  std::unique_ptr<unsigned char[]> getRandomBlock(const unsigned int size);
};

#endif
