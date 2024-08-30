package analyze

import (
	"net/netip"
	"slices"
)

type SortFunc func(l, r netip.Prefix) int

var sortFuncs = map[string]func(a map[netip.Prefix]IPStats) SortFunc{
	"size": func(i map[netip.Prefix]IPStats) SortFunc {
		return func(l, r netip.Prefix) int {
			return int(i[r].Size - i[l].Size)
		}
	},
	"requests": func(i map[netip.Prefix]IPStats) SortFunc {
		return func(l, r netip.Prefix) int {
			return int(i[r].Requests - i[l].Requests)
		}
	},
}

func init() {
	sortFuncs["reqs"] = sortFuncs["requests"]
}

func GetSortFunc(name string, i map[netip.Prefix]IPStats) SortFunc {
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
