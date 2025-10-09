package main

import (
	"net/http"
	"sync"

	"github.com/machinebox/graphql"
)

const (
	cfGraphQLEndpoint = "https://api.cloudflare.com/client/v4/graphql/"
	gqlQueryLimit     = 9999
	cfgraphqlreqlimit = 10 // 10 is the maximum amount of zones you can request at once
)

type GraphQL struct {
	Client *graphql.Client
	Mu     *sync.RWMutex
}

func NewGraphQLClient(http_client *http.Client) *GraphQL {
	if http_client == nil {
		http_client = http.DefaultClient
	}
	gql_client := graphql.NewClient(cfGraphQLEndpoint, graphql.WithHTTPClient(http_client))
	gql_client.Log = func(s string) { log.Debug(s) }
	return &GraphQL{
		Client: gql_client,
		Mu:     &sync.RWMutex{},
	}
}
