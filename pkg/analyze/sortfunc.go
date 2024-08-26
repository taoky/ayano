package analyze

import (
	"net/netip"
	"slices"
)

type SortFunc func(l, r KeyIndex) int

var sortFuncs = map[string]func(a map[string]map[netip.Prefix]IPStats) SortFunc{
	"size": func(i map[string]map[netip.Prefix]IPStats) SortFunc {
		return func(l, r KeyIndex) int {
			return int(i[r.Server][r.Prefix].Size - i[l.Server][l.Prefix].Size)
		}
	},
	"requests": func(i map[string]map[netip.Prefix]IPStats) SortFunc {
		return func(l, r KeyIndex) int {
			return int(i[r.Server][r.Prefix].Requests - i[l.Server][l.Prefix].Requests)
		}
	},
}

func init() {
	sortFuncs["reqs"] = sortFuncs["requests"]
}

func GetSortFunc(name string, i map[string]map[netip.Prefix]IPStats) SortFunc {
	fn, ok := sortFuncs[name]
	if !ok {
		return nil
	}
	return fn(i)
}

func ListSortFuncs() []string {
	ret := make([]string, 0, len(sortFuncs))
	for key := range sortFuncs {
		ret = append(ret, key)
	}
	slices.Sort(ret)
	return ret
}
