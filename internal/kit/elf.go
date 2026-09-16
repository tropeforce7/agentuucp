package kit

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
)

// The relay binary is checked, not trusted: the maker passes what they
// cross-compiled, and a kit for a Linux host must hold a static Linux
// executable for one of the two architectures a relay is deployed on. The
// architecture in the kit's README is read from the file, never from a flag.

// notStaticLinux begins every refusal of the binary.
const notStaticLinux = "the relay binary is not a static Linux executable for amd64 or arm64: "

// architecture reports the Go architecture of a static Linux executable,
// amd64 or arm64, and refuses anything else by what it is: a Mach-O and a
// dynamically linked build are named as such, since those are the two
// mistakes a maker on a Mac makes.
func architecture(bin []byte) (string, error) {
	if what := whatElse(bin); what != "" {
		return "", errors.New(notStaticLinux + what)
	}
	f, err := elf.NewFile(bytes.NewReader(bin))
	if err != nil {
		return "", fmt.Errorf("%snot an executable this kit can read (%v)", notStaticLinux, err)
	}
	if f.Class != elf.ELFCLASS64 {
		return "", errors.New(notStaticLinux + "a 32-bit ELF")
	}
	if f.OSABI != elf.ELFOSABI_NONE && f.OSABI != elf.ELFOSABI_LINUX {
		return "", fmt.Errorf("%san ELF for another operating system (%v)", notStaticLinux, f.OSABI)
	}
	var arch string
	switch f.Machine {
	case elf.EM_X86_64:
		arch = "amd64"
	case elf.EM_AARCH64:
		arch = "arm64"
	default:
		return "", fmt.Errorf("%san ELF for %v", notStaticLinux, f.Machine)
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return "", fmt.Errorf("%sa dynamically linked Linux executable for %s; build it with CGO_ENABLED=0",
				notStaticLinux, arch)
		}
	}
	return arch, nil
}

// whatElse names a file that is plainly not an ELF, from its first bytes:
// empty, a Mach-O (macOS), a Windows executable, or something else. Empty
// for a file that begins as an ELF does.
func whatElse(bin []byte) string {
	switch {
	case len(bin) == 0:
		return "an empty file"
	case bytes.HasPrefix(bin, []byte(elf.ELFMAG)):
		return ""
	case len(bin) >= 4 && isMachO(bin[:4]):
		return "a Mach-O executable, built for macOS; build it with CGO_ENABLED=0 GOOS=linux GOARCH=amd64 (or arm64)"
	case bytes.HasPrefix(bin, []byte("MZ")):
		return "a Windows executable"
	default:
		return "not an executable at all"
	}
}

// isMachO recognises the four Mach-O magics, thin and fat, either byte
// order.
func isMachO(magic []byte) bool {
	for _, m := range [][]byte{
		{0xfe, 0xed, 0xfa, 0xce}, {0xce, 0xfa, 0xed, 0xfe}, // 32-bit
		{0xfe, 0xed, 0xfa, 0xcf}, {0xcf, 0xfa, 0xed, 0xfe}, // 64-bit
		{0xca, 0xfe, 0xba, 0xbe}, {0xbe, 0xba, 0xfe, 0xca}, // fat
	} {
		if bytes.Equal(magic, m) {
			return true
		}
	}
	return false
}
