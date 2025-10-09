package main

import (
	"time"

	"github.com/spf13/viper"
)

func GetTimeRange() (now time.Time, now1mAgo time.Time) {

	now = time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()
	s := 60 * time.Second
	now = now.Truncate(s)
	now1mAgo = now.Add(-60 * time.Second)

	return now, now1mAgo
}
