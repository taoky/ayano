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
		{"/example/a/b/c/d/e/dir/", "/example/.../dir/"},
		{"/short/", "/short/"},
		{"/short/file.ext", "/short/file.ext"},
		{"/short/dir/", "/short/dir/"},
	}
	for _, c := range testCases {
		assert.Equal(t, c[1], TruncateURLPath(c[0]))
	}
}
