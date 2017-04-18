#ifndef ENTROPYPOOL_H
#define ENTROPYPOOL_H

#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/random.h>

class EntropyPool {
public:
  EntropyPool();

  unsigned int getAvailEntropy();
};

#endif
