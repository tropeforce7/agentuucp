package client

// For the tests in package client_test, which may import internal/relay
// where this package's own tests may not (relay imports client).
var (
	RaceEnabled              = raceEnabled
	PageCostMeasure          = pageCostMeasure
	PageCostMeasureCollected = pageCostMeasureCollected
)
