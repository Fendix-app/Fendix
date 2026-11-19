package main

import (
	"context"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

type githubSettings struct {
	APIBaseURL string
	Token      string
}

var githubConfig = githubSettings{
	APIBaseURL: "https://api.github.com",
	Token:      "__EVAL_GITHUB_TOKEN__", // EVAL-SINK
}

func handleHardcodedSecretIndirect(c *gin.Context) {
	repos, err := fetchGitHubRepos(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "github request failed"})
		return
	}
	c.Data(http.StatusOK, "application/json", repos)
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
