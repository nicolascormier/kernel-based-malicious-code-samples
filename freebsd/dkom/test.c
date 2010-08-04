#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char** argv)
{
  if (argc > 1) syscall(210, atoi(argv[1]));
  
  return !argc > 1;
}
