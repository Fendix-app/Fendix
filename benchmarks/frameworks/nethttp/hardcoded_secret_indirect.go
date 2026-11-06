package main

import (
	"context"
	"io"
	"net/http"
)

type githubSettings struct {
	APIBaseURL string
	Token      string
}

var githubConfig = githubSettings{
	APIBaseURL: "https://api.github.com",
	Token:      "__EVAL_GITHUB_TOKEN__", // EVAL-SINK
}

func handleHardcodedSecretIndirect(w http.ResponseWriter, r *http.Request) {
	repos, err := fetchGitHubRepos(r.Context())
	if err != nil {
		http.Error(w, "github request failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(repos)
}

func fetchGitHubRepos(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubConfig.APIBaseURL+"/user/repos", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+githubConfig.Token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
