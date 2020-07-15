#include <iostream>
#include <Windows.h>

using namespace std;

/// <summary>Print error and exit the program</summary>
/// <param name="errorCode">The error code</param>   
void exitWithError(DWORD errorCode)
{
	cout << "Error code: " << errorCode << endl;
	system("pause");
	ExitProcess(0);
}

/// <summary>Get handle to mapped file</summary>
/// <param name="path">Path to executable file</param>  
/// <returns>Handle to the mapped file</returns>  
LPVOID getHandleToMappedFile(char* path)
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

/// <summary>Print the image file header metadata</summary>
/// <param name="printImageFileHeaderMetadata">Pointer to the image file header</param>  
/// <returns>Handle to the mapped file</returns>  
void printImageFileHeaderMetadata(PIMAGE_FILE_HEADER ptrImageFileHeader)
{
	cout << "FileHeader.Machine: " << ptrImageFileHeader->Machine << endl;
	cout << "FileHeader.TimeDateStamp: " << ptrImageFileHeader->TimeDateStamp << endl;
	cout << "FileHeader.NumberOfSections: " << ptrImageFileHeader->NumberOfSections << endl;

}

/// <summary>Print the image optional header metadata</summary>
/// <param name="ptrImageOptionalHeader">Pointer to the imageOptionHeader</param>  
void printImageOptionalHeaderMetadata(PIMAGE_OPTIONAL_HEADER ptrImageOptionalHeader)
{
	cout << "OptionalHeader.Magic: " << ptrImageOptionalHeader->Magic << endl;
	cout << "OptionalHeader.AddressOfEntryPoint: " << ptrImageOptionalHeader->AddressOfEntryPoint << endl;
	cout << "OptionalHeader.SizeOfImage: " << ptrImageOptionalHeader->SizeOfImage << endl;
	cout << "OptionalHeader.SectionAlignment: " << ptrImageOptionalHeader->SectionAlignment << endl;
	cout << "OptionalHeader.FileAlignment: " << ptrImageOptionalHeader->FileAlignment << endl;
	cout << "OptionalHeader.ImageBase: " << ptrImageOptionalHeader->ImageBase << endl;
}

/// <summary>Print the meta data of PE file</summary>
/// <param name="imageBase">Image Base of the file</param>  
void printPEMetaData(DWORD imageBase)
{
	PIMAGE_DOS_HEADER ptrImageDosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS32 ptrImageNTHeader = (PIMAGE_NT_HEADERS32)(ptrImageDosHeader->e_lfanew + imageBase);
	PIMAGE_FILE_HEADER ptrImageFileHeader = (PIMAGE_FILE_HEADER)& ptrImageNTHeader->FileHeader;
	PIMAGE_OPTIONAL_HEADER32 ptrImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)& ptrImageNTHeader->OptionalHeader;
	cout << "File header metadata:" << endl;
	printImageFileHeaderMetadata(ptrImageFileHeader);
	cout << "Optional header metadata:" << endl;
	printImageOptionalHeaderMetadata(ptrImageOptionalHeader);
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
	DWORD imageBase = (DWORD)getHandleToMappedFile(path);
	cout << "-------------------Exploring headers-------------------" << endl;
	printPEMetaData(imageBase);
	cout << "-------------------Exploring imports-------------------" << endl;
	printPEImports(imageBase);
	cout << "-------------------Exploring Exports-------------------" << endl;
	printPEExports(imageBase);
	cout << "Done!" << endl;
	return 0;
}
