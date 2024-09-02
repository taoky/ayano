package analyze

import (
	"slices"
)

type SortFunc func(l, r StatKey) int

var sortFuncs = map[SortByFlag]func(a map[StatKey]IPStats) SortFunc{
	SortBySize: func(i map[StatKey]IPStats) SortFunc {
		return func(l, r StatKey) int {
			return int(i[r].Size - i[l].Size)
		}
	},
	SortByRequests: func(i map[StatKey]IPStats) SortFunc {
		return func(l, r StatKey) int {
			return int(i[r].Requests - i[l].Requests)
		}
	},
}

func GetSortFunc(name SortByFlag, i map[StatKey]IPStats) SortFunc {
	fn, ok := sortFuncs[name]
	if !ok {
		return nil
	}
	return fn(i)
}

func ListSortFuncs() []SortByFlag {
	ret := make([]SortByFlag, 0, len(sortFuncs))
	for key := range sortFuncs {
		ret = append(ret, key)
	}
	slices.Sort(ret)
	return ret
}
