package analyze

import (
	"slices"
)

type SortFunc func(l, r StatKey) int

var sortFuncs = map[string]func(a map[StatKey]IPStats) SortFunc{
	"size": func(i map[StatKey]IPStats) SortFunc {
		return func(l, r StatKey) int {
			return int(i[r].Size - i[l].Size)
		}
	},
	"requests": func(i map[StatKey]IPStats) SortFunc {
		return func(l, r StatKey) int {
			return int(i[r].Requests - i[l].Requests)
		}
	},
}

func init() {
	sortFuncs["reqs"] = sortFuncs["requests"]
}

func GetSortFunc(name string, i map[StatKey]IPStats) SortFunc {
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
