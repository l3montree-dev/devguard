package statistics

type flawAggregationState struct {
	Open  int `json:"open"`
	Fixed int `json:"fixed"`
}

type flawAggregationStateAndChange struct {
	Now flawAggregationState `json:"now"`
	Was flawAggregationState `json:"was"`
}
