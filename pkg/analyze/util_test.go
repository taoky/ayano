package analyze

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAdjacentPrefix(t *testing.T) {
	testCases := [][2]string{
		{"1.2.3.0/24", "1.2.2.0/24"},
		{"1.2.2.0/23", "1.2.0.0/23"},
		{"2001:db8:114:514::/64", "2001:db8:114:515::/64"},
		{"2001:db8:114:514::/63", "2001:db8:114:516::/63"},
	}
	for _, c := range testCases {
		assert.Equal(t, netip.MustParsePrefix(c[1]), AdjacentPrefix(netip.MustParsePrefix(c[0])))
		assert.Equal(t, netip.MustParsePrefix(c[0]), AdjacentPrefix(netip.MustParsePrefix(c[1])))
	}
}

func TestTruncateURLPath(t *testing.T) {
	testCases := [][2]string{
		{"/example/a/b/c/d/e/file.ext", "/example/.../file.ext"},
		{"///example//merge/slashes///file.ext", "/example/.../file.ext"},
		{"/example/a/b/c/d/e/dir/", "/example/.../dir/"},
		{"/short/", "/short/"},
		{"/short/file.ext", "/short/file.ext"},
		{"/short/dir/", "/short/dir/"},
		{"/with/args/?a=1&b=2", "/with/args/?..."},
	}
	for _, c := range testCases {
		assert.Equal(t, c[1], TruncateURLPath(c[0]))
	}
}

func TestTruncateURLPathLen(t *testing.T) {
	type testCase struct {
		input    string
		target   int
		expected string
	}
	testCases := []testCase{
		{"/example/a/b/c/d/e/file.ext", 30, "/example/.../file.ext"},
		{"/example/a/b/c/d/e/dir/", 30, "/example/.../dir/"},
		{"///example//merge/slashes///dir/", 30, "/example/.../dir/"},
		{"/with/args/?a=1&b=2", 30, "/with/args/?..."},
		{"/with/args/?a=1&b=2", 13, "/with/args/?"},
		{"/with/args/?a=1&b=2", 12, "/with/args/?"},
		{"/with/args/?a=1&b=2", 11, "/with/args/"},
		{"/with/args/?a=1&b=2", 8, "/with/*/"},
		{"/with/args/?a=1&b=2", 4, "/wit"},
		{"///with//args/?a=1&b=2", 4, "/wit"},

		{"/example/a/b/c/d/e/file.with.long.name.ext", 30, "/example/.../file.with.l...ext"},
		{"/example/file.with.very.long.name.ext", 30, "/example/file.with.very....ext"},
	}
	for _, c := range testCases {
		assert.Equal(t, c.expected, TruncateURLPathLen(c.input, c.target))
	}
}

func TestTruncateFilenameLen(t *testing.T) {
	type testCase struct {
		input    string
		target   int
		expected string
	}
	testCases := []testCase{
		{"file.ext", 8, "file.ext"},
		{"file.ext", 10, "file.ext"},
		{"file.ext", 80, "file.ext"},
		{"file.long.long.ext", 8, "fi...ext"},
		{"file.long.long.ext", 10, "file...ext"},
		{"file.long.long.ext.gz", 10, "f...ext.gz"},
		// short basename = asterisk
		{"file.long.long.ext.bz2", 10, "*.ext.bz2"},
		// very short basename = keep ext only
		{"file.long.long.ext.bz2", 6, "xt.bz2"},
	}
	for _, c := range testCases {
		assert.Equal(t, c.expected, TruncateFilenameLen(c.input, c.target))
	}
}
