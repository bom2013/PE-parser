#include <iostream>
#include <Windows.h>

using namespace std;

void exitWithError(DWORD errorCode)
{
	cout << "Error code: " << errorCode << endl;
	system("pause");
	ExitProcess(0);
}

LPVOID getHandleToMappendFile(char* path)
{
	//Get handle to PE file
	HANDLE hPEFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	//Check errors
	if (hPEFile == INVALID_HANDLE_VALUE)
	{
		exitWithError(GetLastError());
	}

	//Map file to memory
	HANDLE hPEFileMapped = CreateFileMappingA(hPEFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	//Check errors
	if (hPEFileMapped == INVALID_HANDLE_VALUE)
	{
		exitWithError(GetLastError());
	}

	//Get IMAGE_BASE
	LPVOID fileWiew = MapViewOfFile(hPEFileMapped, FILE_MAP_READ, 0, 0, 0);
	return fileWiew;
}

int main(int argc, char** args)
{
	//check that we have path
	if (argc < 2)
	{
		cout << "Path is missing";
		return 0;
	}
	char* path = args[1];
	cout << "Exploring " << path << endl;

	//Get IMAGE_BASE of the PE header after mapping it to the memory
	DWORD imageBase = (DWORD)getHandleToMappendFile(path);
}
