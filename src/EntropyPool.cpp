#include "EntropyPool.h"

EntropyPool::EntropyPool()
{
}

std::unique_ptr<unsigned char[]> EntropyPool::requestEntropy(struct entropy_queue &eq)
{
  return getRandomBlock(eq.size);
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
  bzero(entBlock.get(), size);
  while (EntropyPool::getAvailEntropy() < size + 128) { //While we don't have the required entropy + 128, wait...
    struct timespec ts;
    ts.tv_sec = 300/1000; //Sleep 300ms
    ts.tv_nsec = 0;
    if (nanosleep(&ts, NULL) != 0) //Sleep!
      throw "Error sleeping while waiting for entropy!";
  }

  if (syscall(SYS_getrandom, entBlock.get(), size, GRND_NONBLOCK) != size) {  //TODO: Change this to GRND_RANDOM for production!
  	throw "Error getrandom() did not give us enough entropy";
  }
  return entBlock;
}

uint32_t EntropyPool::getIntelRandom() {
	cpuid_t cpu;
	asm volatile (
		"mov $0, %%rax\t\n"
		"mov $0, %%rcx\t\n"
		"cpuid\t\n"
		 : "=a" (cpu.eax), "=b" (cpu.ebx), "=c" (cpu.ecx), "=d" (cpu.edx): :);

	if (memcmp((char*)&cpu.ebx, "Genu", 4) == 0 && memcmp((char*)&cpu.edx, "ineI", 4) == 0 && memcmp((char*)&cpu.ecx, "ntel", 4) == 0) {
		uint32_t r = 0;
		asm volatile(
			"getrnd:\t\n"
			"clc\t\n"		//Clear CF
			"rdrandl %0\t\n"
			"jnc getrnd"		//If CF not set, it failed...
			: "=r" (r)::);
		return r;
	}
	else {
		throw "Unsupported CPU!";
	}
}
