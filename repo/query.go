package repo

type QueryBody struct {
	Filters struct{ 
		Severity string `json:"severity"`
	} `json:"filters"`
}