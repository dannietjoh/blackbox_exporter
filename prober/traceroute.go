// Copyright 2018 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

// roundTripTrace holds timings for a single HTTP roundtrip.
type traceRouteStats struct {
	hops  int
	start time.Time
	end   time.Time
}

// ProbeTraceRoute function
func ProbeTraceRoute(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {

	fmt.Println("initializing traceroute probe")
	var (
		durationGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_traceroute_duration_seconds",
			Help: "Duration of the traceroute",
		}, []string{"traceroute"})

		hopsGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_traceroute_hops",
			Help: "The number of hops",
		})
	)

	for _, lv := range []string{"duration"} {
		durationGaugeVec.WithLabelValues(lv)
	}

	registry.MustRegister(durationGaugeVec)
	registry.MustRegister(hopsGauge)

	targetAddress, targetPort, err := net.SplitHostPort(target)
	if err != nil {
		level.Error(logger).Log("msg", "Error splitting target address and port", "err", err)
		return false
	}

	ip, _, err := chooseProtocol(module.TRACEROUTE.PreferredIPProtocol, targetAddress, registry, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error resolving address", "err", err)
		return false
	}

	var dialProtocol string
	if ip.IP.To4() == nil {
		dialProtocol = "tcp6"
	} else {
		dialProtocol = "tcp4"
	}

	fmt.Println("traceroute:", target, "targetAddress:", targetAddress, "targetPort:", targetPort, "ip:", ip, "dialProtocol:", dialProtocol)

	return true
}
