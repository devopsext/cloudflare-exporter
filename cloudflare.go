package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	cf "github.com/cloudflare/cloudflare-go/v4"
	cfaccounts "github.com/cloudflare/cloudflare-go/v4/accounts"
	cfrulesets "github.com/cloudflare/cloudflare-go/v4/rulesets"
	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
	"github.com/machinebox/graphql"
	"github.com/spf13/viper"
)

const (
	freePlanId      = "0feeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	apiPerPageLimit = 1000
	gqlQueryLimit   = 9999
)

var (
	cfGraphQLEndpoint = "https://api.cloudflare.com/client/v4/graphql/"
	gql               = &GQL{
		Client: graphql.NewClient(cfGraphQLEndpoint),
	}
)

type GQL struct {
	Client *graphql.Client
	Mu     sync.RWMutex
}

type cloudflareResponse struct {
	Viewer struct {
		Zones []zoneResp `json:"zones"`
	} `json:"viewer"`
}

type cloudflareResponseAccts struct {
	Viewer struct {
		Accounts []accountResp `json:"accounts"`
	} `json:"viewer"`
}

type cloudflareResponseColo struct {
	Viewer struct {
		Zones []zoneRespColo `json:"zones"`
	} `json:"viewer"`
}

type cloudflareResponseLb struct {
	Viewer struct {
		Zones []lbResp `json:"zones"`
	} `json:"viewer"`
}

type cloudflareResponseLogpushAccount struct {
	Viewer struct {
		Accounts []logpushResponse `json:"accounts"`
	} `json:"viewer"`
}

type cloudflareResponseLogpushZone struct {
	Viewer struct {
		Zones []logpushResponse `json:"zones"`
	} `json:"viewer"`
}

type logpushResponse struct {
	LogpushHealthAdaptiveGroups []struct {
		Count uint64 `json:"count"`

		Dimensions struct {
			Datetime        string `json:"datetime"`
			DestinationType string `json:"destinationType"`
			JobID           int    `json:"jobId"`
			Status          int    `json:"status"`
			Final           int    `json:"final"`
		}
	} `json:"logpushHealthAdaptiveGroups"`
}

type accountResp struct {
	WorkersInvocationsAdaptive []struct {
		Dimensions struct {
			ScriptName string `json:"scriptName"`
			Status     string `json:"status"`
		}

		Sum struct {
			Requests uint64  `json:"requests"`
			Errors   uint64  `json:"errors"`
			Duration float64 `json:"duration"`
		} `json:"sum"`

		Quantiles struct {
			CPUTimeP50   float32 `json:"cpuTimeP50"`
			CPUTimeP75   float32 `json:"cpuTimeP75"`
			CPUTimeP99   float32 `json:"cpuTimeP99"`
			CPUTimeP999  float32 `json:"cpuTimeP999"`
			DurationP50  float32 `json:"durationP50"`
			DurationP75  float32 `json:"durationP75"`
			DurationP99  float32 `json:"durationP99"`
			DurationP999 float32 `json:"durationP999"`
		} `json:"quantiles"`
	} `json:"workersInvocationsAdaptive"`
}

type zoneRespColo struct {
	ColoGroups []struct {
		Dimensions struct {
			Datetime string `json:"datetime"`
			ColoCode string `json:"coloCode"`
			Host     string `json:"clientRequestHTTPHost"`
		} `json:"dimensions"`
		Count uint64 `json:"count"`
		Sum   struct {
			EdgeResponseBytes uint64 `json:"edgeResponseBytes"`
			Visits            uint64 `json:"visits"`
		} `json:"sum"`
		Avg struct {
			SampleInterval float64 `json:"sampleInterval"`
		} `json:"avg"`
	} `json:"httpRequestsAdaptiveGroups"`

	ZoneTag string `json:"zoneTag"`
}

type zoneResp struct {
	HTTP1mGroups []struct {
		Dimensions struct {
			Datetime string `json:"datetime"`
		} `json:"dimensions"`
		Unique struct {
			Uniques uint64 `json:"uniques"`
		} `json:"uniq"`
		Sum struct {
			Bytes          uint64 `json:"bytes"`
			CachedBytes    uint64 `json:"cachedBytes"`
			CachedRequests uint64 `json:"cachedRequests"`
			Requests       uint64 `json:"requests"`
			BrowserMap     []struct {
				PageViews       uint64 `json:"pageViews"`
				UaBrowserFamily string `json:"uaBrowserFamily"`
			} `json:"browserMap"`
			ClientHTTPVersion []struct {
				Protocol string `json:"clientHTTPProtocol"`
				Requests uint64 `json:"requests"`
			} `json:"clientHTTPVersionMap"`
			ClientSSL []struct {
				Protocol string `json:"clientSSLProtocol"`
			} `json:"clientSSLMap"`
			ContentType []struct {
				Bytes                   uint64 `json:"bytes"`
				Requests                uint64 `json:"requests"`
				EdgeResponseContentType string `json:"edgeResponseContentTypeName"`
			} `json:"contentTypeMap"`
			Country []struct {
				Bytes             uint64 `json:"bytes"`
				ClientCountryName string `json:"clientCountryName"`
				Requests          uint64 `json:"requests"`
				Threats           uint64 `json:"threats"`
			} `json:"countryMap"`
			EncryptedBytes    uint64 `json:"encryptedBytes"`
			EncryptedRequests uint64 `json:"encryptedRequests"`
			IPClass           []struct {
				Type     string `json:"ipType"`
				Requests uint64 `json:"requests"`
			} `json:"ipClassMap"`
			PageViews      uint64 `json:"pageViews"`
			ResponseStatus []struct {
				EdgeResponseStatus int    `json:"edgeResponseStatus"`
				Requests           uint64 `json:"requests"`
			} `json:"responseStatusMap"`
			ThreatPathing []struct {
				Name     string `json:"threatPathingName"`
				Requests uint64 `json:"requests"`
			} `json:"threatPathingMap"`
			Threats uint64 `json:"threats"`
		} `json:"sum"`
	} `json:"httpRequests1mGroups"`

	FirewallEventsAdaptiveGroups []struct {
		Count      uint64 `json:"count"`
		Dimensions struct {
			Action                string `json:"action"`
			Source                string `json:"source"`
			RuleID                string `json:"ruleId"`
			ClientCountryName     string `json:"clientCountryName"`
			ClientRequestHTTPHost string `json:"clientRequestHTTPHost"`
		} `json:"dimensions"`
	} `json:"firewallEventsAdaptiveGroups"`

	HTTPRequestsAdaptiveGroups []struct {
		Count      uint64 `json:"count"`
		Dimensions struct {
			OriginResponseStatus  uint16 `json:"originResponseStatus"`
			ClientCountryName     string `json:"clientCountryName"`
			ClientRequestHTTPHost string `json:"clientRequestHTTPHost"`
		} `json:"dimensions"`
	} `json:"httpRequestsAdaptiveGroups"`

	HTTPRequestsEdgeCountryHost []struct {
		Count      uint64 `json:"count"`
		Dimensions struct {
			EdgeResponseStatus    uint16 `json:"edgeResponseStatus"`
			ClientCountryName     string `json:"clientCountryName"`
			ClientRequestHTTPHost string `json:"clientRequestHTTPHost"`
		} `json:"dimensions"`
	} `json:"httpRequestsEdgeCountryHost"`

	HealthCheckEventsAdaptiveGroups []struct {
		Count      uint64 `json:"count"`
		Dimensions struct {
			HealthStatus  string `json:"healthStatus"`
			OriginIP      string `json:"originIP"`
			FailureReason string `json:"failureReason"`
			Region        string `json:"region"`
			Fqdn          string `json:"fqdn"`
		} `json:"dimensions"`
	} `json:"healthCheckEventsAdaptiveGroups"`

	ZoneTag string `json:"zoneTag"`
}

type lbResp struct {
	LoadBalancingRequestsAdaptiveGroups []struct {
		Count      uint64 `json:"count"`
		Dimensions struct {
			LbName               string `json:"lbName"`
			Proxied              uint8  `json:"proxied"`
			Region               string `json:"region"`
			SelectedOriginName   string `json:"selectedOriginName"`
			SelectedPoolAvgRttMs uint64 `json:"selectedPoolAvgRttMs"`
			SelectedPoolHealthy  uint8  `json:"selectedPoolHealthy"`
			SelectedPoolName     string `json:"selectedPoolName"`
			SteeringPolicy       string `json:"steeringPolicy"`
		} `json:"dimensions"`
	} `json:"loadBalancingRequestsAdaptiveGroups"`

	LoadBalancingRequestsAdaptive []struct {
		LbName                string `json:"lbName"`
		Proxied               uint8  `json:"proxied"`
		Region                string `json:"region"`
		SelectedPoolHealthy   uint8  `json:"selectedPoolHealthy"`
		SelectedPoolID        string `json:"selectedPoolID"`
		SelectedPoolName      string `json:"selectedPoolName"`
		SessionAffinityStatus string `json:"sessionAffinityStatus"`
		SteeringPolicy        string `json:"steeringPolicy"`
		SelectedPoolAvgRttMs  uint64 `json:"selectedPoolAvgRttMs"`
		Pools                 []struct {
			AvgRttMs uint64 `json:"avgRttMs"`
			Healthy  uint8  `json:"healthy"`
			ID       string `json:"id"`
			PoolName string `json:"poolName"`
		} `json:"pools"`
		Origins []struct {
			OriginName string `json:"originName"`
			Health     uint8  `json:"health"`
			IPv4       string `json:"ipv4"`
			Selected   uint8  `json:"selected"`
		} `json:"origins"`
	} `json:"loadBalancingRequestsAdaptive"`

	ZoneTag string `json:"zoneTag"`
}

func fetchZones(accounts []cfaccounts.Account) []cfzones.Zone {

	var zones []cfzones.Zone

	for _, account := range accounts {
		ctx, cancel := context.WithTimeout(context.Background(), cftimeout)
		z, err := cfclient.Zones.List(ctx, cfzones.ZoneListParams{
			Account: cf.F(cfzones.ZoneListParamsAccount{ID: cf.F(account.ID)}),
			PerPage: cf.F(float64(apiPerPageLimit)),
		})

		if err != nil {
			log.Error(err)
			cancel()
			continue
		}
		zones = append(zones, z.Result...)
		cancel()
	}
	return zones
}

func fetchFirewallRules(zoneID string) map[string]string {

	ctx, cancel := context.WithTimeout(context.Background(), cftimeout)
	defer cancel()

	listOfRulesets, err := cfclient.Rulesets.List(ctx, cfrulesets.RulesetListParams{
		ZoneID: cf.F(zoneID),
	})
	if err != nil {
		log.Errorf("ZoneID:%s, Err:%s", zoneID, err)
		return map[string]string{}
	}

	firewallRulesMap := make(map[string]string)

	for _, rulesetDesc := range listOfRulesets.Result {
		if rulesetDesc.Phase == cfrulesets.PhaseHTTPRequestFirewallManaged {
			ctx, cancel := context.WithTimeout(context.Background(), cftimeout)
			ruleset, err := cfclient.Rulesets.Get(ctx, rulesetDesc.ID, cfrulesets.RulesetGetParams{
				ZoneID: cf.F(zoneID),
			})
			if err != nil {
				log.Errorf("ZoneID:%s, RulesetID:%s, Err:%s", zoneID, rulesetDesc.ID, err)
				cancel()
				continue
			}
			cancel()
			for _, rule := range ruleset.Rules {
				firewallRulesMap[rule.ID] = rule.Description
			}
		}
	}

	return firewallRulesMap
}

func fetchAccounts() []cfaccounts.Account {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), cftimeout)
	defer cancel()
	a, err := cfclient.Accounts.List(ctx, cfaccounts.AccountListParams{PerPage: cf.F(float64(apiPerPageLimit))})
	if err != nil {
		log.Error(err)
		return []cfaccounts.Account{}
	}

	return a.Result
}

func fetchZoneTotals(zoneIDs []string) (*cloudflareResponse, error) {
	now := time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()
	s := 60 * time.Second
	now = now.Truncate(s)
	now1mAgo := now.Add(-60 * time.Second)

	request := graphql.NewRequest(`
query ($zoneIDs: [String!], $mintime: Time!, $maxtime: Time!, $limit: Int!) {
	viewer {
		zones(filter: { zoneTag_in: $zoneIDs }) {
			zoneTag
			httpRequests1mGroups(limit: $limit filter: { datetime: $maxtime }) {
				uniq {
					uniques
				}
				sum {
					browserMap {
						pageViews
						uaBrowserFamily
					}
					bytes
					cachedBytes
					cachedRequests
					clientHTTPVersionMap {
						clientHTTPProtocol
						requests
					}
					clientSSLMap {
						clientSSLProtocol
						requests
					}
					contentTypeMap {
						bytes
						requests
						edgeResponseContentTypeName
					}
					countryMap {
						bytes
						clientCountryName
						requests
						threats
					}
					encryptedBytes
					encryptedRequests
					ipClassMap {
						ipType
						requests
					}
					pageViews
					requests
					responseStatusMap {
						edgeResponseStatus
						requests
					}
					threatPathingMap {
						requests
						threatPathingName
					}
					threats
				}
				dimensions {
					datetime
				}
			}
			firewallEventsAdaptiveGroups(limit: $limit, filter: { datetime_geq: $mintime, datetime_lt: $maxtime }) {
				count
				dimensions {
				  action
				  source
				  ruleId
				  clientRequestHTTPHost
				  clientCountryName
				}
			}
			httpRequestsAdaptiveGroups(limit: $limit, filter: { datetime_geq: $mintime, datetime_lt: $maxtime, cacheStatus_notin: ["hit"] }) {
				count
				dimensions {
					originResponseStatus
					clientCountryName
					clientRequestHTTPHost
				}
			}
			httpRequestsEdgeCountryHost: httpRequestsAdaptiveGroups(limit: $limit, filter: { datetime_geq: $mintime, datetime_lt: $maxtime }) {
				count
				dimensions {
					edgeResponseStatus
					clientCountryName
					clientRequestHTTPHost
				}
			}
			healthCheckEventsAdaptiveGroups(limit: $limit, filter: { datetime_geq: $mintime, datetime_lt: $maxtime }) {
				count
				dimensions {
					healthStatus
					originIP
					region
					fqdn
				}
			}
		}
	}
}
`)
	if len(viper.GetString("cf_api_token")) > 0 {
		request.Header.Set("Authorization", "Bearer "+viper.GetString("cf_api_token"))
	} else {
		request.Header.Set("X-AUTH-EMAIL", viper.GetString("cf_api_email"))
		request.Header.Set("X-AUTH-KEY", viper.GetString("cf_api_key"))
	}
	request.Var("limit", gqlQueryLimit)
	request.Var("maxtime", now)
	request.Var("mintime", now1mAgo)
	request.Var("zoneIDs", zoneIDs)

	ctx := context.Background()

	var resp cloudflareResponse
	gql.Mu.RLock()
	defer gql.Mu.RUnlock()
	if err := gql.Client.Run(ctx, request, &resp); err != nil {
		log.Error(err)
		return nil, err
	}

	return &resp, nil
}

func fetchColoTotals(zoneIDs []string) (*cloudflareResponseColo, error) {
	now := time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()
	s := 60 * time.Second
	now = now.Truncate(s)
	now1mAgo := now.Add(-60 * time.Second)

	request := graphql.NewRequest(`
	query ($zoneIDs: [String!], $mintime: Time!, $maxtime: Time!, $limit: Int!) {
		viewer {
			zones(filter: { zoneTag_in: $zoneIDs }) {
				zoneTag
				httpRequestsAdaptiveGroups(
					limit: $limit
					filter: { datetime_geq: $mintime, datetime_lt: $maxtime }
					) {
						count
						avg {
							sampleInterval
						}
						dimensions {
							clientRequestHTTPHost
							coloCode
							datetime
						}
						sum {
							edgeResponseBytes
							visits
						}
					}
				}
			}
		}
`)
	if len(viper.GetString("cf_api_token")) > 0 {
		request.Header.Set("Authorization", "Bearer "+viper.GetString("cf_api_token"))
	} else {
		request.Header.Set("X-AUTH-EMAIL", viper.GetString("cf_api_email"))
		request.Header.Set("X-AUTH-KEY", viper.GetString("cf_api_key"))
	}
	request.Var("limit", gqlQueryLimit)
	request.Var("maxtime", now)
	request.Var("mintime", now1mAgo)
	request.Var("zoneIDs", zoneIDs)

	ctx := context.Background()
	var resp cloudflareResponseColo
	gql.Mu.RLock()
	defer gql.Mu.RUnlock()
	if err := gql.Client.Run(ctx, request, &resp); err != nil {
		log.Error(err)
		return nil, err
	}

	return &resp, nil
}

func fetchWorkerTotals(accountID string) (*cloudflareResponseAccts, error) {
	now := time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()
	s := 60 * time.Second
	now = now.Truncate(s)
	now1mAgo := now.Add(-60 * time.Second)

	request := graphql.NewRequest(`
	query ($accountID: String!, $mintime: Time!, $maxtime: Time!, $limit: Int!) {
		viewer {
			accounts(filter: {accountTag: $accountID} ) {
				workersInvocationsAdaptive(limit: $limit, filter: { datetime_geq: $mintime, datetime_lt: $maxtime}) {
					dimensions {
						scriptName
						status
						datetime
					}

					sum {
						requests
						errors
						duration
					}

					quantiles {
						cpuTimeP50
						cpuTimeP75
						cpuTimeP99
						cpuTimeP999
						durationP50
						durationP75
						durationP99
						durationP999
					}
				}
			}
		}
	}
`)
	if len(viper.GetString("cf_api_token")) > 0 {
		request.Header.Set("Authorization", "Bearer "+viper.GetString("cf_api_token"))
	} else {
		request.Header.Set("X-AUTH-EMAIL", viper.GetString("cf_api_email"))
		request.Header.Set("X-AUTH-KEY", viper.GetString("cf_api_key"))
	}
	request.Var("limit", gqlQueryLimit)
	request.Var("maxtime", now)
	request.Var("mintime", now1mAgo)
	request.Var("accountID", accountID)

	ctx := context.Background()
	var resp cloudflareResponseAccts
	gql.Mu.RLock()
	defer gql.Mu.RUnlock()
	if err := gql.Client.Run(ctx, request, &resp); err != nil {
		log.Error(err)
		return nil, err
	}

	return &resp, nil
}

func fetchLoadBalancerTotals(zoneIDs []string) (*cloudflareResponseLb, error) {
	now := time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()
	s := 60 * time.Second
	now = now.Truncate(s)
	now1mAgo := now.Add(-60 * time.Second)

	request := graphql.NewRequest(`
	query ($zoneIDs: [String!], $mintime: Time!, $maxtime: Time!, $limit: Int!) {
		viewer {
			zones(filter: { zoneTag_in: $zoneIDs }) {
				zoneTag
				loadBalancingRequestsAdaptiveGroups(
					filter: { datetime_geq: $mintime, datetime_lt: $maxtime},
					limit: $limit) {
					count
					dimensions {
						region
						lbName
						selectedPoolName
						proxied
						selectedOriginName
						selectedPoolAvgRttMs
						selectedPoolHealthy
						steeringPolicy
					}
				}
				loadBalancingRequestsAdaptive(
					filter: { datetime_geq: $mintime, datetime_lt: $maxtime},
					limit: $limit) {
					lbName
					proxied
					region
					selectedPoolHealthy
					selectedPoolId
					selectedPoolName
					sessionAffinityStatus
					steeringPolicy
					selectedPoolAvgRttMs
					pools {
						id
						poolName
						healthy
						avgRttMs
					}
					origins {
						originName
						health
						ipv4
						selected
					}
				}
			}
		}
	}
`)
	if len(viper.GetString("cf_api_token")) > 0 {
		request.Header.Set("Authorization", "Bearer "+viper.GetString("cf_api_token"))
	} else {
		request.Header.Set("X-AUTH-EMAIL", viper.GetString("cf_api_email"))
		request.Header.Set("X-AUTH-KEY", viper.GetString("cf_api_key"))
	}
	request.Var("limit", gqlQueryLimit)
	request.Var("maxtime", now)
	request.Var("mintime", now1mAgo)
	request.Var("zoneIDs", zoneIDs)

	ctx := context.Background()
	var resp cloudflareResponseLb
	gql.Mu.RLock()
	defer gql.Mu.RUnlock()
	if err := gql.Client.Run(ctx, request, &resp); err != nil {
		log.Error(err)
		return nil, err
	}
	return &resp, nil
}

func fetchLogpushAccount(accountID string) (*cloudflareResponseLogpushAccount, error) {
	now := time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()
	s := 60 * time.Second
	now = now.Truncate(s)
	now1mAgo := now.Add(-60 * time.Second)

	request := graphql.NewRequest(`query($accountID: String!, $limit: Int!, $mintime: Time!, $maxtime: Time!) {
		viewer {
		  accounts(filter: {accountTag : $accountID }) {
			logpushHealthAdaptiveGroups(
			  filter: {
				datetime_geq: $mintime
				datetime_lt: $maxtime
				status_neq: 200
			  }
			  limit: $limit
			) {
			  count
			  dimensions {
				jobId
				status
				destinationType
				datetime
				final
			  }
			}
		  }
		}
	  }`)

	if len(viper.GetString("cf_api_token")) > 0 {
		request.Header.Set("Authorization", "Bearer "+viper.GetString("cf_api_token"))
	} else {
		request.Header.Set("X-AUTH-EMAIL", viper.GetString("cf_api_email"))
		request.Header.Set("X-AUTH-KEY", viper.GetString("cf_api_key"))
	}

	request.Var("accountID", accountID)
	request.Var("limit", gqlQueryLimit)
	request.Var("maxtime", now)
	request.Var("mintime", now1mAgo)

	ctx := context.Background()
	var resp cloudflareResponseLogpushAccount
	gql.Mu.RLock()
	defer gql.Mu.RUnlock()
	if err := gql.Client.Run(ctx, request, &resp); err != nil {
		log.Error(err)
		return nil, err
	}
	return &resp, nil
}

func fetchLogpushZone(zoneIDs []string) (*cloudflareResponseLogpushZone, error) {
	now := time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()
	s := 60 * time.Second
	now = now.Truncate(s)
	now1mAgo := now.Add(-60 * time.Second)

	request := graphql.NewRequest(`query($zoneIDs: String!, $limit: Int!, $mintime: Time!, $maxtime: Time!) {
		viewer {
			zones(filter: {zoneTag_in : $zoneIDs }) {
			logpushHealthAdaptiveGroups(
			  filter: {
				datetime_geq: $mintime
				datetime_lt: $maxtime
				status_neq: 200
			  }
			  limit: $limit
			) {
			  count
			  dimensions {
				jobId
				status
				destinationType
				datetime
				final
			  }
			}
		  }
		}
	  }`)

	if len(viper.GetString("cf_api_token")) > 0 {
		request.Header.Set("Authorization", "Bearer "+viper.GetString("cf_api_token"))
	} else {
		request.Header.Set("X-AUTH-EMAIL", viper.GetString("cf_api_email"))
		request.Header.Set("X-AUTH-KEY", viper.GetString("cf_api_key"))
	}

	request.Var("zoneIDs", zoneIDs)
	request.Var("limit", gqlQueryLimit)
	request.Var("maxtime", now)
	request.Var("mintime", now1mAgo)

	ctx := context.Background()
	var resp cloudflareResponseLogpushZone
	gql.Mu.RLock()
	defer gql.Mu.RUnlock()
	if err := gql.Client.Run(ctx, request, &resp); err != nil {
		log.Error(err)
		return nil, err
	}

	return &resp, nil
}

func findZoneAccountName(zones []cfzones.Zone, ID string) (string, string) {
	for _, z := range zones {
		if z.ID == ID {
			return z.Name, strings.ToLower(strings.ReplaceAll(z.Account.Name, " ", "-"))
		}
	}

	return "", ""
}

func extractZoneIDs(zones []cfzones.Zone) []string {
	var IDs []string

	for _, z := range zones {
		IDs = append(IDs, z.ID)
	}

	return IDs
}

func filterNonFreePlanZones(zones []cfzones.Zone) (filteredZones []cfzones.Zone) {

	var zoneIDs []string

	for _, z := range zones {
		extraFields, err := extractExtraFields(z.JSON.ExtraFields["plan"].Raw())
		if err != nil {
			log.Error(err)
			continue
		}
		if extraFields["id"] == freePlanId {
			continue
		}
		if !contains(zoneIDs, z.ID) {
			zoneIDs = append(zoneIDs, z.ID)
			filteredZones = append(filteredZones, z)
		}
	}
	return
}

func extractExtraFields(fields string) (map[string]interface{}, error) {
	var extraFields map[string]interface{}
	err := json.Unmarshal([]byte(fields), &extraFields)
	return extraFields, err
}
