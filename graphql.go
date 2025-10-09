package main

import (
	"net/http"
	"sync"

	"github.com/machinebox/graphql"
)

const (
	cfGraphQLEndpoint = "https://api.cloudflare.com/client/v4/graphql/"
	gqlQueryLimit     = 9999
)

type GraphQL struct {
	Client *graphql.Client
	Mu     *sync.RWMutex
}

func NewGraphQLClient(http_client *http.Client) *GraphQL {
	if http_client == nil {
		http_client = http.DefaultClient
	}
	return &GraphQL{
		Client: graphql.NewClient(cfGraphQLEndpoint, graphql.WithHTTPClient(http_client)),
		Mu:     &sync.RWMutex{},
	}
}
