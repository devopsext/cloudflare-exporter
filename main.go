package main

import (
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/nelkinda/health-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	cf "github.com/cloudflare/cloudflare-go/v4"
	cfoption "github.com/cloudflare/cloudflare-go/v4/option"
	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
	"github.com/sirupsen/logrus"
)

const (
	cfgraphqlreqlimit = 10 // 10 is the maximum amount of zones you can request at once
)

var (
	cfclient  *cf.Client
	cftimeout = 10 * time.Second
	log       = logrus.New()
)

// var (
// 	cfgListen          = ":8080"
// 	cfgCfAPIKey        = ""
// 	cfgCfAPIEmail      = ""
// 	cfgCfAPIToken      = ""
// 	cfgMetricsPath     = "/metrics"
// 	cfgZones           = ""
// 	cfgExcludeZones    = ""
// 	cfgScrapeDelay     = 300
// 	cfgFreeTier        = false
// 	cfgMetricsDenylist = ""
// )

func getTargetZones() []string {
	var zoneIDs []string

	if len(viper.GetString("cf_zones")) > 0 {
		zoneIDs = strings.Split(viper.GetString("cf_zones"), ",")
	} else {
		// deprecated
		for _, e := range os.Environ() {
			if strings.HasPrefix(e, "ZONE_") {
				split := strings.SplitN(e, "=", 2)
				zoneIDs = append(zoneIDs, split[1])
			}
		}
	}
	return zoneIDs
}

func getExcludedZones() []string {
	var zoneIDs []string

	if len(viper.GetString("cf_exclude_zones")) > 0 {
		zoneIDs = strings.Split(viper.GetString("cf_exclude_zones"), ",")
	}
	return zoneIDs
}

func filterZones(all []cfzones.Zone, target []string) []cfzones.Zone {
	var filtered []cfzones.Zone

	if (len(target)) == 0 {
		return all
	}

	for _, tz := range target {
		for _, z := range all {
			if tz == z.ID {
				filtered = append(filtered, z)
				log.Info("Filtering zone: ", z.ID, " ", z.Name)
			}
		}
	}

	return filtered
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func filterExcludedZones(all []cfzones.Zone, exclude []string) []cfzones.Zone {
	var filtered []cfzones.Zone

	if (len(exclude)) == 0 {
		return all
	}

	for _, z := range all {
		if contains(exclude, z.ID) {
			log.Info("Exclude zone: ", z.ID, " ", z.Name)
		} else {
			filtered = append(filtered, z)
		}
	}

	return filtered
}

func fetchMetrics() {
	var wg sync.WaitGroup
	accounts := fetchAccounts()

	for _, a := range accounts {
		go fetchWorkerAnalytics(a, &wg)
		go fetchLogpushAnalyticsForAccount(a, &wg)
		go fetchLoadblancerPoolsHealth(a, &wg)
	}

	zones := fetchZones(accounts)
	tzones := getTargetZones()
	fzones := filterZones(zones, tzones)
	ezones := getExcludedZones()
	filteredZones := filterExcludedZones(fzones, ezones)
	if !viper.GetBool("free_tier") {
		filteredZones = filterNonFreePlanZones(filteredZones)
	}

	zoneCount := len(filteredZones)
	if zoneCount > 0 && zoneCount <= cfgraphqlreqlimit {
		go fetchZoneAnalytics(filteredZones, &wg)
		go fetchZoneColocationAnalytics(filteredZones, &wg)
		go fetchLoadBalancerAnalytics(filteredZones, &wg)
		go fetchLogpushAnalyticsForZone(filteredZones, &wg)
	} else if zoneCount > cfgraphqlreqlimit {
		for s := 0; s < zoneCount; s += cfgraphqlreqlimit {
			e := s + cfgraphqlreqlimit
			if e > zoneCount {
				e = zoneCount
			}
			go fetchZoneAnalytics(filteredZones[s:e], &wg)
			go fetchZoneColocationAnalytics(filteredZones[s:e], &wg)
			go fetchLoadBalancerAnalytics(filteredZones[s:e], &wg)
			go fetchLogpushAnalyticsForZone(filteredZones[s:e], &wg)
		}
	}

	wg.Wait()
}

func runExpoter() {
	// fmt.Println(" :", viper.GetString("cf_api_email"))
	// fmt.Println(" :", viper.GetString("cf_api_key"))

	// fmt.Println(" :", viper.GetString("metrics_path"))

	// fmt.Println(":ASD :", viper.GetString("listen"))

	// fmt.Println(" :", cfgListen)

	cfgMetricsPath := viper.GetString("metrics_path")

	if !(len(viper.GetString("cf_api_token")) > 0 || (len(viper.GetString("cf_api_email")) > 0 && len(viper.GetString("cf_api_key")) > 0)) {
		log.Fatal("Please provide CF_API_KEY+CF_API_EMAIL or CF_API_TOKEN")
	}

	metricsDenylist := []string{}
	if len(viper.GetString("metrics_denylist")) > 0 {
		metricsDenylist = strings.Split(viper.GetString("metrics_denylist"), ",")
	}
	deniedMetricsSet, err := buildDeniedMetricsSet(metricsDenylist)
	if err != nil {
		log.Fatal(err)
	}
	mustRegisterMetrics(deniedMetricsSet)

	go func() {
		for ; true; <-time.NewTicker(60 * time.Second).C {
			go fetchMetrics()
		}
	}()

	// This section will start the HTTP server and expose
	// any metrics on the /metrics endpoint.
	if !strings.HasPrefix(viper.GetString("metrics_path"), "/") {
		cfgMetricsPath = "/" + viper.GetString("metrics_path")
	}

	http.Handle(cfgMetricsPath, promhttp.Handler())
	h := health.New(health.Health{})
	http.HandleFunc("/health", h.Handler)

	log.Info("Beginning to serve metrics on ", viper.GetString("listen"), cfgMetricsPath)

	server := &http.Server{
		Addr:              viper.GetString("listen"),
		ReadHeaderTimeout: 3 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}

func main() {
	var cmd = &cobra.Command{
		Use:   "viper-test",
		Short: "testing viper",
		Run: func(_ *cobra.Command, _ []string) {
			runExpoter()
		},
	}

	//vip := viper.New()
	viper.AutomaticEnv()

	flags := cmd.Flags()

	flags.String("listen", ":8080", "listen on addr:port ( default :8080), omit addr to listen on all interfaces")
	viper.BindEnv("listen")
	viper.SetDefault("listen", ":8080")

	flags.String("metrics_path", "/metrics", "path for metrics, default /metrics")
	viper.BindEnv("metrics_path")
	viper.SetDefault("metrics_path", "/metrics")

	flags.String("cf_api_key", "", "cloudflare api key, works with api_email flag")
	viper.BindEnv("cf_api_key")

	flags.String("cf_api_email", "", "cloudflare api email, works with api_key flag")
	viper.BindEnv("cf_api_email")

	flags.String("cf_api_token", "", "cloudflare api token (preferred)")
	viper.BindEnv("cf_api_token")

	flags.String("cf_zones", "", "cloudflare zones to export, comma delimited list")
	viper.BindEnv("cf_zones")
	viper.SetDefault("cf_zones", "")

	flags.String("cf_exclude_zones", "", "cloudflare zones to exclude, comma delimited list")
	viper.BindEnv("cf_exclude_zones")
	viper.SetDefault("cf_exclude_zones", "")

	flags.Int("scrape_delay", 300, "scrape delay in seconds, defaults to 300")
	viper.BindEnv("scrape_delay")
	viper.SetDefault("scrape_delay", 300)

	flags.Bool("free_tier", false, "scrape only metrics included in free plan")
	viper.BindEnv("free_tier")
	viper.SetDefault("free_tier", false)

	flags.String("metrics_denylist", "", "metrics to not expose, comma delimited list")
	viper.BindEnv("metrics_denylist")
	viper.SetDefault("metrics_denylist", "")

	flags.String("log_level", "", "log level")
	viper.BindEnv("log_level")
	viper.SetDefault("log_level", "error")

	viper.BindPFlags(flags)

	logLevel := viper.GetString("log_level")
	if logLevel == "debug" {
		log.Level = logrus.DebugLevel
		log.SetReportCaller(true)
	} else if logLevel == "warn" {
		log.Level = logrus.WarnLevel
	} else if logLevel == "error" {
		log.Level = logrus.ErrorLevel
		log.SetReportCaller(true)
	} else {
		log.Level = logrus.InfoLevel
	}

	log.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			funcPath := strings.Split(f.File, "/")
			file := funcPath[len(funcPath)-1]
			return file, f.Function
		},
	})

	if len(viper.GetString("cf_api_token")) > 0 {
		cfclient = cf.NewClient(
			cfoption.WithAPIToken(viper.GetString("cf_api_token")),
			cfoption.WithRequestTimeout(cftimeout*2),
		)
	} else {
		cfclient = cf.NewClient(
			cfoption.WithAPIKey(viper.GetString("cf_api_key")),
			cfoption.WithAPIEmail(viper.GetString("cf_api_email")),
			cfoption.WithRequestTimeout(cftimeout*2),
		)
	}
	cmd.Execute()

}
