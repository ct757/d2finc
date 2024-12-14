package main

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const (
	IMAGE_DIRECTORY_ENTRY_EXPORT = 0

	// IMAGE_EXPORT_DIRECTORY structure (from WinNT.h)
	// typedef struct _IMAGE_EXPORT_DIRECTORY {
	//   DWORD Characteristics;
	//   DWORD TimeDateStamp;
	//   WORD  MajorVersion;
	//   WORD  MinorVersion;
	//   DWORD Name;
	//   DWORD Base;
	//   DWORD NumberOfFunctions;
	//   DWORD NumberOfNames;
	//   DWORD AddressOfFunctions;     // RVA of array of function addresses
	//   DWORD AddressOfNames;         // RVA of array of name RVA
	//   DWORD AddressOfNameOrdinals;  // RVA of array of WORD ordinals
	// } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
)

type imageExportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

// readNullTerminatedString reads a null-terminated ASCII string from r at the given offset.
func readNullTerminatedString(r io.ReaderAt, offset int64) (string, error) {
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 1)
	for {
		_, err := r.ReadAt(tmp, offset)
		if err != nil {
			return "", err
		}
		offset++
		if tmp[0] == 0 {
			break
		}
		buf = append(buf, tmp[0])
	}
	return string(buf), nil
}

// rvaToFileOffset converts an RVA to a file offset using the sections in the PE file.
func rvaToFileOffset(rva uint32, f *pe.File) (int64, error) {
	for _, sect := range f.Sections {
		start := sect.VirtualAddress
		end := sect.VirtualAddress + sect.VirtualSize
		if rva >= start && rva < end {
			off := int64(rva - start + sect.Offset)
			return off, nil
		}
	}
	return 0, fmt.Errorf("RVA 0x%x not found in any section", rva)
}

func main() {
	fmt.Printf("d2finc (DLL to FASM .inc) v0.1")

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <pefile>\n", os.Args[0])
		os.Exit(1)
	}
	filename := os.Args[1]

	f, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer f.Close()

	peFile, err := pe.NewFile(f)
	if err != nil {
		log.Fatalf("Failed to parse PE file: %v", err)
	}
	defer peFile.Close()

	var exportDirRVA uint32
	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		exportDirRVA = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	case *pe.OptionalHeader64:
		exportDirRVA = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	default:
		log.Fatalf("Unsupported optional header type")
	}

	if exportDirRVA == 0 {
		fmt.Println("No export directory found.")
		return
	}

	exportDirOffset, err := rvaToFileOffset(exportDirRVA, peFile)
	if err != nil {
		log.Fatalf("Failed to convert export directory RVA: %v", err)
	}

	// Read IMAGE_EXPORT_DIRECTORY
	var exportDir imageExportDirectory
	if err := binary.Read(io.NewSectionReader(f, exportDirOffset, int64(binary.Size(exportDir))), binary.LittleEndian, &exportDir); err != nil {
		log.Fatalf("Failed to read export directory: %v", err)
	}

	// Print some basic info
	// fmt.Printf("Number of functions: %d\n", exportDir.NumberOfFunctions)
	// fmt.Printf("Number of names: %d\n", exportDir.NumberOfNames)

	if exportDir.NumberOfNames == 0 {
		fmt.Println("No named exports.")
		return
	}

	// Read arrays
	// AddressOfFunctions is an array of DWORD RVAs of the exported functions.
	// AddressOfNames is an array of DWORD RVAs to the exported names (strings).
	// AddressOfNameOrdinals is an array of WORDs, each associated with a name entry.

	namesOffset, err := rvaToFileOffset(exportDir.AddressOfNames, peFile)
	if err != nil {
		log.Fatalf("Failed to convert names RVA: %v", err)
	}

	nameOrdinalsOffset, err := rvaToFileOffset(exportDir.AddressOfNameOrdinals, peFile)
	if err != nil {
		log.Fatalf("Failed to convert name ordinals RVA: %v", err)
	}

	functionsOffset, err := rvaToFileOffset(exportDir.AddressOfFunctions, peFile)
	if err != nil {
		log.Fatalf("Failed to convert functions RVA: %v", err)
	}

	// Each name entry is a DWORD RVA to a string.
	nameRVAs := make([]uint32, exportDir.NumberOfNames)
	if err := binary.Read(io.NewSectionReader(f, namesOffset, int64(4*exportDir.NumberOfNames)), binary.LittleEndian, &nameRVAs); err != nil {
		log.Fatalf("Error reading name RVAs: %v", err)
	}

	// Each ordinal entry is a WORD
	nameOrdinals := make([]uint16, exportDir.NumberOfNames)
	if err := binary.Read(io.NewSectionReader(f, nameOrdinalsOffset, int64(2*exportDir.NumberOfNames)), binary.LittleEndian, &nameOrdinals); err != nil {
		log.Fatalf("Error reading name ordinals: %v", err)
	}

	// Functions array
	functionRVAs := make([]uint32, exportDir.NumberOfFunctions)
	if err := binary.Read(io.NewSectionReader(f, functionsOffset, int64(4*exportDir.NumberOfFunctions)), binary.LittleEndian, &functionRVAs); err != nil {
		log.Fatalf("Error reading function RVAs: %v", err)
	}

	fmt.Printf("import %s,\\\n", strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename)))

	// Print out each named export
	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		nameRVA := nameRVAs[i]
		nameOff, err := rvaToFileOffset(nameRVA, peFile)
		if err != nil {
			log.Printf("Error converting name RVA: %v", err)
			continue
		}

		funcName, err := readNullTerminatedString(f, nameOff)
		if err != nil {
			log.Printf("Error reading export name: %v", err)
			continue
		}

		if i < exportDir.NumberOfNames-1 {
			fmt.Printf("       %s,\"%s\",\\\n", funcName, funcName)
		} else {
			fmt.Printf("       %s,\"%s\"\n", funcName, funcName)
		}
	}
}
