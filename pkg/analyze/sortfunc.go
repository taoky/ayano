package analyze

import (
	"slices"
)

type SortFunc func(l, r serverPrefix) int

var sortFuncs = map[string]func(a map[serverPrefix]IPStats) SortFunc{
	"size": func(i map[serverPrefix]IPStats) SortFunc {
		return func(l, r serverPrefix) int {
			return int(i[r].Size - i[l].Size)
		}
	},
	"requests": func(i map[serverPrefix]IPStats) SortFunc {
		return func(l, r serverPrefix) int {
			return int(i[r].Requests - i[l].Requests)
		}
	},
}

func init() {
	sortFuncs["reqs"] = sortFuncs["requests"]
}

func GetSortFunc(name string, i map[serverPrefix]IPStats) SortFunc {
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
