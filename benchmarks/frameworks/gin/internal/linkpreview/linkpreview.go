// Package linkpreview fetches remote pages for link previews.
package linkpreview

import (
	"io"
	"net/http"
)

func Fetch(target string) (int, string, error) {
	resp, err := http.Get(target) // EVAL-SINK
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, string(body), nil
}
