#include "EntropyPool.h"

EntropyPool::EntropyPool()
{

}

unsigned int EntropyPool::getAvailEntropy()
{
  unsigned int availEnt;
  int sysRand = open("/dev/random", O_RDONLY | O_NONBLOCK); //Open fd to /dev/random
  if (sysRand == -1)
  {
    throw "Error opening /dev/random to get available entropy.";
  }

  if (ioctl(sysRand, RNDGETENTCNT, &availEnt) == -1) //Call IOCTL to get available entropy
  {
    throw "Error getting entropy count (ioctl:RNDGETENTCNT).";
  }
  return availEnt;
}

std::unique_ptr<unsigned char[]> EntropyPool::getRandomBlock(const unsigned int size)
{
  std::unique_ptr<unsigned char[]> entBlock(new unsigned char[size]);
  while (EntropyPool::getAvailEntropy() < size + 128) { //While we don't have the required entropy + 128, wait...
    struct timespec ts;
    ts.tv_sec = 300/1000; //Sleep 300ms
    ts.tv_nsec = 0;
    if (nanosleep(&ts, NULL) != 0) //Sleep!
      throw "Error sleeping while waiting for entropy!";
  }
  return entBlock;
}
