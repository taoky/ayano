package analyze

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"
)

type SizeFlag uint64

func (s SizeFlag) String() string {
	return humanize.Bytes(uint64(s))
}

func (s *SizeFlag) Set(value string) error {
	// First try parsing as a plain number
	size, err := strconv.ParseUint(value, 10, 64)
	if err == nil {
		*s = SizeFlag(size)
		return nil
	}

	size, err = humanize.ParseBytes(value)
	if err != nil {
		return err
	}
	*s = SizeFlag(size)
	return nil
}

func (s SizeFlag) Type() string {
	return "size"
}

type SortByFlag string

const (
	SortBySize      SortByFlag = "size"
	SortByRequests  SortByFlag = "requests"
	SortByDirectory SortByFlag = "directory"
)

func (s SortByFlag) String() string {
	return string(s)
}

func (s *SortByFlag) Set(value string) error {
	switch value {
	case "size":
		*s = SortBySize
	case "requests", "reqs":
		*s = SortByRequests
	case "directory", "dir":
		*s = SortByDirectory
	default:
		return errors.New(`must be one of "size", "requests" or "directory"`)
	}
	return nil
}

func (s SortByFlag) Type() string {
	return "string"
}

func GetFirstDirectory(url string) string {
	if url == "" {
		return ""
	}
	// Remove query parameters
	if idx := strings.Index(url, "?"); idx >= 0 {
		url = url[:idx]
	}
	// Split the path
	parts := strings.Split(strings.Trim(url, "/"), "/")
	if len(parts) == 0 {
		return "/"
	}
	return "/" + parts[0]
}

func (a *Analyzer) IPPrefix(ip netip.Addr) netip.Prefix {
	var clientPrefix netip.Prefix
	if ip.Is4() {
		clientPrefix = netip.PrefixFrom(ip, a.Config.PrefixV4)
	} else {
		clientPrefix = netip.PrefixFrom(ip, a.Config.PrefixV6)
	}
	return clientPrefix.Masked()
}

func AdjacentPrefix(p netip.Prefix) netip.Prefix {
	bits := p.Bits()
	if bits == 0 {
		return p
	}
	a := p.Addr()
	if a.Is4() {
		addr := a.As4()
		addr[(bits-1)/8] ^= uint8(1 << (7 - (bits-1)%8))
		return netip.PrefixFrom(netip.AddrFrom4(addr), bits)
	} else {
		addr := a.As16()
		addr[(bits-1)/8] ^= uint8(1 << (7 - (bits-1)%8))
		return netip.PrefixFrom(netip.AddrFrom16(addr), bits)
	}
}

func TruncateURLPath(input string) string {
	parts := strings.SplitN(input, "?", 2)
	path := filepath.Clean(parts[0])
	if strings.HasSuffix(parts[0], "/") {
		// filepath.Clean removes trailing slash
		// Add it back to preserve directory notation
		path += "/"
	}
	args := ""
	if len(parts) == 2 {
		args = "?..."
	}
	count := strings.Count(path, "/")
	if count <= 2 {
		return path + args
	}
	parts = strings.Split(path, "/")
	if parts[len(parts)-1] == "" {
		if count == 3 {
			return path + args
		}
		count--
		parts[count] += "/"
	}
	return fmt.Sprintf("/%s/.../%s%s", parts[1], parts[count], args)
}

func TruncateURLPathLen(input string, target int) string {
	stub := TruncateURLPath(input)
	if len(stub) <= target {
		return stub
	}

	// if removing query string suffices, do it
	parts := strings.SplitN(stub, "?", 2)
	stub = parts[0]
	if len(stub) < target {
		return stub + "?"
	} else if len(stub) == target {
		return stub
	}

	// stub contains at most 3 slashes
	parts = strings.SplitN(stub, "/", 4)
	filename := parts[len(parts)-1]
	isDirectory := false
	if filename == "" {
		isDirectory = true
		filename = parts[len(parts)-2]
	}
	filenameTarget := len(filename) - (len(stub) - target)
	if filenameTarget > 0 {
		filename = TruncateFilenameLen(filename, filenameTarget)
		if isDirectory {
			parts[len(parts)-2] = filename
		} else {
			parts[len(parts)-1] = filename
		}
		return strings.Join(parts, "/")
	}

	// give up and truncate directly
	return stub[:target]
}

var compressionSuffixes = []string{".gz", ".bz2", ".xz", ".zst"}

func TruncateFilenameLen(input string, target int) string {
	if len(input) <= target {
		return input
	}
	ext := filepath.Ext(input)
	if slices.Contains(compressionSuffixes, ext) {
		ext = filepath.Ext(strings.TrimSuffix(input, ext)) + ext
	}
	basename := strings.TrimSuffix(input, ext)
	if len(basename) > len(input)-target {
		toTruncate := len(basename) - (len(input) - target)
		if ext != "" && toTruncate > 2 {
			// ext will begin with a dot already
			return basename[:toTruncate-2] + ".." + ext
		} else if toTruncate > 3 {
			return basename[:toTruncate-3] + "..."
		} else {
			// basename too short, keep just an asterisk
			return "*" + ext
		}
	}
	// truncating basename alone would not suffice, keep characters from end
	return input[len(input)-target:]
}
