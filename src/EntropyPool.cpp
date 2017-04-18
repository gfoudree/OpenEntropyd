#include "EntropyPool.h"

EntropyPool::EntropyPool()
{

}

unsigned int EntropyPool::getAvailEntropy()
{
  unsigned int availEnt;
  int sysRand = open("/dev/random", O_RDONLY | O_NONBLOCK);
  if (sysRand == -1)
  {
    throw "Error opening /dev/random to get available entropy.";
  }

  if (ioctl(sysRand, RNDGETENTCNT, &availEnt) == -1)
  {
    throw "Error getting entropy count (ioctl:RNDGETENTCNT).";
  }
  return availEnt;
}
