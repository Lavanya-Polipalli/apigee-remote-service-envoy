// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/analytics"
	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	als "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	gatewaySource        = "envoy"
	datacaptureNamespace = "envoy.filters.http.apigee.datacapture"
)

// AccessLogServer server
type AccessLogServer struct {
	handler       *Handler
	streamTimeout time.Duration // the duration for a stream to live
}

// Register registers
func (a *AccessLogServer) Register(s *grpc.Server, handler *Handler, d time.Duration) {
	als.RegisterAccessLogServiceServer(s, a)
	a.handler = handler
	a.streamTimeout = d
}

// StreamAccessLogs streams
func (a *AccessLogServer) StreamAccessLogs(stream als.AccessLogService_StreamAccessLogsServer) error {
	// set the expiring time
	endTime := time.Now().Add(a.streamTimeout)
	log.Debugf("started stream") // Simplified log
	defer log.Debugf("closed stream") // Simplified log

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			log.Debugf("client closed stream")
			// Client is done sending. Send a response and close the server side.
			return stream.SendAndClose(&als.StreamAccessLogsResponse{})
		}
		if err != nil {
			return err
		}

		if msg.GetHttpLogs() == nil && msg.GetTcpLogs() == nil {
			log.Errorf("received empty StreamAccessLogsMessage")
			return status.Errorf(codes.InvalidArgument, "received empty StreamAccessLogsMessage")
		}

		switch logs := msg.GetLogEntries().(type) {
		case *als.StreamAccessLogsMessage_HttpLogs:
			status := "ok"
			if err := a.handleHTTPLogs(logs); err != nil {
				status = "error"
				log.Errorf("handleHTTPLogs: %v", err)
				// continue to process stream even if one batch has issues
			}
			prometheusAnalyticsRequests.WithLabelValues(a.handler.orgName, status).Inc()

		case *als.StreamAccessLogsMessage_TcpLogs:
			log.Infof("TcpLogs not supported: %#v", logs)
		}

		// close the client stream once the timeout reaches
		if endTime.Before(time.Now()) {
			log.Debugf("stream timeout reached")
			return stream.SendAndClose(&als.StreamAccessLogsResponse{})
		}
	}
}

func (a *AccessLogServer) handleHTTPLogs(msg *als.StreamAccessLogsMessage_HttpLogs) error {
	if len(msg.HttpLogs.LogEntry) == 0 {
		return fmt.Errorf("no HTTP log entries found in message")
	}

	for _, v := range msg.HttpLogs.LogEntry {
		req := v.Request
		if req == nil {
			log.Debugf("Request is nil, skipped accesslog")
			continue
		}

		getMetadata := func(namespace string) *structpb.Struct {
			props := v.GetCommonProperties()
			if props == nil {
				return nil
			}
			metadata := props.GetMetadata()
			if metadata == nil {
				return nil
			}
			return metadata.GetFilterMetadata()[namespace]
		}

		var api string
		var authContext *auth.Context

		extAuthzMetadata := getMetadata(extAuthzFilterNamespace)
		if extAuthzMetadata != nil {
			api, authContext = a.handler.decodeExtAuthzMetadata(extAuthzMetadata.GetFields())
		} else if a.handler.appendMetadataHeaders {
			log.Debugf("No dynamic metadata for ext_authz filter, falling back to headers")
			api, authContext = a.handler.decodeMetadataHeaders(req.GetRequestHeaders())
		} else {
			log.Debugf("No dynamic metadata for ext_authz filter, skipped accesslog: %#v", v.Request)
			continue
		}

		if api == "" {
			log.Debugf("Unknown target, skipped accesslog: %#v", v.Request)
			continue
		}

		var attributes []analytics.Attribute
		attributesMetadata := getMetadata(datacaptureNamespace)
		if attributesMetadata != nil && len(attributesMetadata.Fields) > 0 {
			for k, v := range attributesMetadata.Fields {
				attr := analytics.Attribute{
					Name: k,
				}
				switch v.GetKind().(type) {
				case *structpb.Value_NumberValue:
					attr.Value = v.GetNumberValue()
				case *structpb.Value_StringValue:
					attr.Value = v.GetStringValue()
				case *structpb.Value_BoolValue:
					attr.Value = v.GetBoolValue()
				default:
					log.Debugf("attribute %s is unsupported type: %s", k, v.GetKind())
					continue
				}
				attributes = append(attributes, attr)
			}
		}

		var responseCode int
		if v.Response != nil && v.Response.ResponseCode != nil {
			responseCode = int(v.Response.ResponseCode.Value)
		}

		cp := v.CommonProperties
		requestPath := strings.SplitN(req.Path, "?", 2)[0]
		record := analytics.Record{
			ClientReceivedStartTimestamp: pbTimestampToApigee(cp.GetStartTime()),
			ClientReceivedEndTimestamp:   pbTimestampAddDurationApigee(cp.GetStartTime(), cp.GetTimeToLastRxByte()),
			TargetSentStartTimestamp:     pbTimestampAddDurationApigee(cp.GetStartTime(), cp.GetTimeToFirstUpstreamTxByte()),
			TargetSentEndTimestamp:       pbTimestampAddDurationApigee(cp.GetStartTime(), cp.GetTimeToLastUpstreamTxByte()),
			TargetReceivedStartTimestamp: pbTimestampAddDurationApigee(cp.GetStartTime(), cp.GetTimeToFirstUpstreamRxByte()),
			TargetReceivedEndTimestamp:   pbTimestampAddDurationApigee(cp.GetStartTime(), cp.GetTimeToLastUpstreamRxByte()),
			ClientSentStartTimestamp:     pbTimestampAddDurationApigee(cp.GetStartTime(), cp.GetTimeToFirstDownstreamTxByte()),
			ClientSentEndTimestamp:       pbTimestampAddDurationApigee(cp.GetStartTime(), cp.GetTimeToLastDownstreamTxByte()),
			APIProxy:                     api,
			RequestURI:                   req.Path,
			RequestPath:                  requestPath,
			RequestVerb:                  req.RequestMethod.String(),
			UserAgent:                    req.UserAgent,
			ResponseStatusCode:           responseCode,
			GatewaySource:                gatewaySource,
			ClientIP:                     req.GetForwardedFor(),
			Attributes:                   attributes,
		}

		records := []analytics.Record{record}
		err := a.handler.analyticsMan.SendRecords(authContext, records)
		if err != nil {
			log.Warnf("Unable to send ax: %v", err)
			// Do not return error, continue processing other entries
		}
	}
	return nil
}

// returns ms since epoch
func pbTimestampToApigee(ts *timestamppb.Timestamp) int64 {
	if ts == nil {
		return 0
	}
	if err := ts.CheckValid(); err != nil {
		log.Debugf("invalid timestamp: %s", err)
		return 0
	}
	return timeToApigeeInt(ts.AsTime())
}

// returns ms since epoch
func pbTimestampAddDurationApigee(ts *timestamppb.Timestamp, d *durationpb.Duration) int64 {
	if ts == nil {
		return 0
	}
	if err := ts.CheckValid(); err != nil {
		log.Debugf("invalid timestamp: %s", err)
		return 0
	}
	targetTime := ts.AsTime()
	if d != nil {
		if err := d.CheckValid(); err == nil {
			du := d.AsDuration()
			targetTime = targetTime.Add(du)
		}
	}
	return timeToApigeeInt(targetTime)
}

var (
	prometheusAnalyticsRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Subsystem: "analytics",
		Name:      "analytics_requests_count",
		Help:      "Total number of analytics streaming requests received",
	}, []string{"org", "status"})
)

// format time as ms since epoch
func timeToApigeeInt(t time.Time) int64 {
	return t.UnixMilli()
}
