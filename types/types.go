// Package types contains the API types
package types

// ExportResp is a response to an export request
type ExportResp struct {
	TaskID string `json:"taskId"`
}

// ExportRequest is a request to export
type ExportRequest struct {
	Task Task `json:"task"`
}

// Task is used to describe the export request
type Task struct {
	EventName string  `json:"eventName"`
	Request   Request `json:"request"`
}

// Request describes the export request
type Request struct {
	BlockID       string        `json:"blockId"`
	ExportOptions ExportOptions `json:"exportOptions"`
	Recursive     bool          `json:"recursive"`
}

// ExportOptions contains the export options
type ExportOptions struct {
	ExportType string `json:"exportType"`
	Locale     string `json:"locale"`
	TimeZone   string `json:"timeZone"`
}

// TaskRequest is a request to get tasks
type TaskRequest struct {
	TaskIds []string `json:"taskIds"`
}

// TaskResp is a response to a task request
type TaskResp struct {
	Results []struct {
		ID        string  `json:"id"`
		EventName string  `json:"eventName"`
		Request   Request `json:"request"`
		Actor     struct {
			Table string `json:"table"`
			ID    string `json:"id"`
		} `json:"actor"`
		State  string `json:"state"`
		Status struct {
			Type          string `json:"type"`
			PagesExported int    `json:"pagesExported"`
			ExportURL     string `json:"exportURL"`
		} `json:"status"`
	} `json:"results"`
}
