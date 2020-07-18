/*
Auther: Noam Ben Shlomo(Bom2013)
This code is written by a code written by Uri Haddad,
the original code can be found at the following link: https://drive.google.com/file/d/1jxf3JU0qv8wdsscpB9gW5_raDhmy2q0u/view
credit to him(Uri haddad)
*/
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
void printImageFileHeaderMetadata(PIMAGE_FILE_HEADER ptrImageFileHeader)
{
	cout << "\tFileHeader.Machine: " << ptrImageFileHeader->Machine << endl;
	cout << "\tFileHeader.TimeDateStamp: " << ptrImageFileHeader->TimeDateStamp << endl;
	cout << "\tFileHeader.NumberOfSections: " << ptrImageFileHeader->NumberOfSections << endl;

}

/// <summary>Print the image optional header metadata</summary>
/// <param name="ptrImageOptionalHeader">Pointer to the imageOptionHeader</param>  
void printImageOptionalHeaderMetadata(PIMAGE_OPTIONAL_HEADER ptrImageOptionalHeader)
{
	cout << "\tOptionalHeader.Magic: " << ptrImageOptionalHeader->Magic << endl;
	cout << "\tOptionalHeader.AddressOfEntryPoint: " << ptrImageOptionalHeader->AddressOfEntryPoint << endl;
	cout << "\tOptionalHeader.SizeOfImage: " << ptrImageOptionalHeader->SizeOfImage << endl;
	cout << "\tOptionalHeader.SectionAlignment: " << ptrImageOptionalHeader->SectionAlignment << endl;
	cout << "\tOptionalHeader.FileAlignment: " << ptrImageOptionalHeader->FileAlignment << endl;
	cout << "\tOptionalHeader.ImageBase: " << ptrImageOptionalHeader->ImageBase << endl;
}

void printExportMetaData(PIMAGE_EXPORT_DIRECTORY ptrImageExportDirectory)
{
	cout << "Exports:" << endl;
	cout << "\tExports.Name: " << ptrImageExportDirectory->Name << endl;
	cout << "\tExports.Base: " << ptrImageExportDirectory->Base << endl;
	cout << "\tExports.NumberOfFunctions: " << ptrImageExportDirectory->NumberOfFunctions << endl;
	cout << "\tExports.NumberOfNames: " << ptrImageExportDirectory->NumberOfNames << endl;
}
void printExportFunctionsData(DWORD imageBase, PIMAGE_EXPORT_DIRECTORY ptrImageExportDirectory, DWORD exportStartRVA, DWORD exportEndRVA)
{
	//Get pointers to arrays
	PDWORD ptrExportsFunctions = (PDWORD)(imageBase + ptrImageExportDirectory->AddressOfFunctions);
	PDWORD ptrExportsNames = (PDWORD)(imageBase + ptrImageExportDirectory->AddressOfNames);
	PWORD ptrExportsNameOrdinals = (PWORD)(imageBase + ptrImageExportDirectory->AddressOfNameOrdinals);

	//print functions
	cout << "\tExport functions: " << endl;
	cout << "\t\tEntryPoint\tOrdinal\tName" << endl;

	//Print all export functions data
	for (int i = 0; i < ptrImageExportDirectory->NumberOfFunctions; i++)
	{
		if (ptrExportsFunctions[i] == 0)
			continue;
		cout << "\t\t" << ptrExportsFunctions[i] << '\t' << i + ptrImageExportDirectory->Base << '\t';

		//Print name if needed
		for (DWORD j = 0; j < ptrImageExportDirectory->NumberOfNames; j++)
		{
			//Check if needed
			if (ptrExportsNameOrdinals[j] == i)
				cout << (char*)(imageBase + ptrExportsNames[j]);
		}

		//Check if the function is forwarded functions(address inside export RVA) and print if so
		if ((ptrExportsFunctions[i] >= exportStartRVA) && (ptrExportsFunctions[i] <= exportEndRVA))
			cout << "[Forwarded function -> " << imageBase + ptrExportsFunctions[i] << "]";
		cout << endl;
	}
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

PIMAGE_SECTION_HEADER getSectionHeaderByRVA(DWORD RVA, PIMAGE_NT_HEADERS ptrImageNTHeader)
{
	//Get pointer to the first section
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ptrImageNTHeader);

	for (int i = 0; i < ptrImageNTHeader->FileHeader.NumberOfSections; i++, section++)
	{
		//Check if RVA inside the section range and return this section if so
		if ((RVA >= section->VirtualAddress) && (section->VirtualAddress + section->Misc.VirtualSize))
			return section;
	}
	return 0;
}

DWORD getDataDirectoryPtr(DWORD imageBase, int dataDirectoryIndex)
{
	// Get the headers of the PE
	PIMAGE_DOS_HEADER ptrDosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS32 ptrNtHeaders = (PIMAGE_NT_HEADERS32)(ptrDosHeader->e_lfanew + imageBase);
	PIMAGE_OPTIONAL_HEADER32 ptrOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)& ptrNtHeaders->OptionalHeader;

	// If the data directory index is false, then the function returns the optional header virtual address.
	if (!dataDirectoryIndex) {
		return (DWORD)ptrOptionalHeader;
	}

	// Get the vitual address of the requested data directory and return it.
	PIMAGE_DATA_DIRECTORY ptrDataDirectory = &ptrOptionalHeader->DataDirectory[dataDirectoryIndex];
	return (DWORD)ptrDataDirectory;
}

void printPEImports(DWORD imageBase)
{
	PIMAGE_DOS_HEADER ptrImageDosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS32 ptrImageNTHeader = (PIMAGE_NT_HEADERS32)(ptrImageDosHeader->e_lfanew + imageBase);
	//Get import start RVA
	DWORD importStartRVA = ptrImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	//Get import header
	PIMAGE_SECTION_HEADER ptrImageImportHeader = getSectionHeaderByRVA(importStartRVA, ptrImageNTHeader);

	// Check if no imports
	if (!ptrImageImportHeader) {
		cout << "No imports" << endl;
		return;
	}

	// Get the first import descriptor
	PIMAGE_DATA_DIRECTORY ptrImportsDataDirectory = (PIMAGE_DATA_DIRECTORY)getDataDirectoryPtr(imageBase, IMAGE_DIRECTORY_ENTRY_IMPORT);
	PIMAGE_IMPORT_DESCRIPTOR ptrImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(ptrImportsDataDirectory->VirtualAddress + imageBase);

	cout << "Imports: " << endl;
	cout << "Imports.Section: " << ptrImageImportHeader->Name << endl;
	//Run over each import descripter
	while (ptrImportDescriptor->Name != NULL)
	{
		cout << "\t" << ptrImportDescriptor->Name << endl;
		cout << "\tTimeDateStamp: " << ptrImportDescriptor->TimeDateStamp << endl;
		cout << "\tForwarderChain:  " << ptrImportDescriptor->ForwarderChain << endl;
		cout << "\tFirst thunk RVA: " << ptrImportDescriptor->FirstThunk << endl;

		// Get the IAT and INT
		PIMAGE_THUNK_DATA32 thunkINT = (PIMAGE_THUNK_DATA32)(ptrImportDescriptor->OriginalFirstThunk + imageBase);
		if (!thunkINT)
			return;

		PIMAGE_THUNK_DATA32 thunkIAT = (PIMAGE_THUNK_DATA32)(ptrImportDescriptor->FirstThunk + imageBase);

		cout << "\tOrdinal  Name" << endl;

		// Run over each function belongs the current dll
		while (thunkIAT->u1.AddressOfData != 0) {
			if (thunkIAT->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				cout << "\t" << IMAGE_ORDINAL(thunkINT->u1.Ordinal);
			else {
				PIMAGE_IMPORT_BY_NAME ptrOrdinalName = PIMAGE_IMPORT_BY_NAME(thunkINT->u1.AddressOfData + imageBase);
				cout << "	" << ptrOrdinalName->Hint << "  " << ptrOrdinalName->Name << " (Bound to: " << thunkIAT->u1.Function << ")";
			}
			printf("\n");
			thunkINT++;
			thunkIAT++;
		}
		printf("\n");
		ptrImportDescriptor++;
	}
	return;
}

void printPEExports(DWORD imageBase)
{
	// Get the export section.
	PIMAGE_DOS_HEADER ptrDosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS32 ptrNtHeaders = (PIMAGE_NT_HEADERS32)(ptrDosHeader->e_lfanew + imageBase);
	//Get export
	DWORD exportsStartRVA = ptrNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportsEndRVA = exportsStartRVA + ptrNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	PIMAGE_SECTION_HEADER ptrExportsHeader = getSectionHeaderByRVA(exportsStartRVA, ptrNtHeaders);

	//Check that the header isnt empty
	if (!ptrExportsHeader)
	{
		cout << "No exports" << endl;
		return;
	}

	//Get export dir pointer
	PIMAGE_EXPORT_DIRECTORY ptrImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(imageBase + exportsStartRVA);

	//Print export metadata
	printExportMetaData(ptrImageExportDirectory);
	printExportFunctionsData(imageBase, ptrImageExportDirectory, exportsStartRVA, exportsEndRVA);

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
	//printPEImports(imageBase);
	cout << "-------------------Exploring Exports-------------------" << endl;
	printPEExports(imageBase);
	cout << "Done!" << endl;
	return 0;
}
