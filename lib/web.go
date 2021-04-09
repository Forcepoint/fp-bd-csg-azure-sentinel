package lib

import (
	"fmt"
	"github.com/spf13/viper"
	"strconv"
	"strings"
	"time"
)

func WebLogsFilter() (map[string][]string, map[string][]string) {
	include := make(map[string][]string)
	exclude := make(map[string][]string)
	if viper.GetString("CSG_WEB_LOGS_INCLUDE") != "" {
		includeParts := strings.Split(viper.GetString("CSG_WEB_LOGS_INCLUDE"), ",")
		for _, v := range includeParts {
			vParts := strings.Split(v, "=")
			if len(vParts) == 2 {
				include[strings.TrimSpace(vParts[0])] = append(include[strings.TrimSpace(vParts[0])], strings.TrimSpace(vParts[1]))
			}
		}
	}
	if viper.GetString("CSG_WEB_LOGS_EXCLUDE") != "" {
		excludeParts := strings.Split(viper.GetString("CSG_WEB_LOGS_EXCLUDE"), ",")
		for _, v := range excludeParts {
			vParts := strings.Split(v, "=")
			if len(vParts) == 2 {
				exclude[strings.TrimSpace(vParts[0])] = append(exclude[strings.TrimSpace(vParts[0])], strings.TrimSpace(vParts[1]))
			}
		}
	}
	return include, exclude
}

func CreateCommonEventFormatWeb(csgLogWeb CsgLogWeb) (string, error) {

	severity := 0
	switch strings.ToLower(GetLast(csgLogWeb.Severity)) {
	case "low":
		severity = 3
	case "medium":
		severity = 6
	case "high":
		severity = 9
	case "critical":
		severity = 10
	}
	f := fmt.Sprintf("CEF:0|Forcepoint CSG|Web|%s|%s|%s|%d|",
		viper.GetString("CSG_VERSION"), GetLast(csgLogWeb.RiskClass), GetLast(csgLogWeb.CloudAppName), severity)
	if GetLast(csgLogWeb.Action) != "" {
		f = fmt.Sprintf("%sact=%s ", f, GetLast(csgLogWeb.Action))
	}
	if GetLast(csgLogWeb.Protocol) != "" {
		f = fmt.Sprintf("%sapp=%s ", f, GetLast(csgLogWeb.Protocol))
	}

	if csgLogWeb.BytesSent != "" {
		sent, _ := strconv.Atoi(csgLogWeb.BytesSent)
		f = fmt.Sprintf("%sout=%d ", f, sent)
	}
	if csgLogWeb.BytesReceived != "" {
		recv, _ := strconv.Atoi(csgLogWeb.BytesReceived)
		f = fmt.Sprintf("%sin=%d ", f, recv)
	}
	if GetLast(csgLogWeb.CategoryName) != "" {
		f = fmt.Sprintf("%scs1=%s cs1Label=Category Name ", f, GetLast(csgLogWeb.CategoryName))
	}
	if GetLast(csgLogWeb.Domain) != "" {
		f = fmt.Sprintf("%scs2=%s cs2Label=Domain name of the destination site ", f, GetLast(csgLogWeb.Domain))
	}
	if GetLast(csgLogWeb.PolicyName) != "" {
		f = fmt.Sprintf("%scs3=%s cs3Label=Policy Name ", f, GetLast(csgLogWeb.PolicyName))
	}

	if csgLogWeb.DestinationIP != "" {
		f = fmt.Sprintf("%sdst=%s ", f, csgLogWeb.DestinationIP)
	}
	if GetLast(csgLogWeb.URLFull) != "" {
		f = fmt.Sprintf("%srequest=%s ", f, setScp(GetLast(csgLogWeb.URLFull)))
	}
	if csgLogWeb.FileName != "" {
		f = fmt.Sprintf("%sfname=%s ", f, setScp(csgLogWeb.FileName))
	}
	if csgLogWeb.ConnectionIP != "" {
		f = fmt.Sprintf("%scs4=%s cs4Label=IP address of connection to the cloud service. ", f, csgLogWeb.ConnectionIP)
	}
	if csgLogWeb.DataCenter != "" {
		f = fmt.Sprintf("%sflexString1=%s flexString1Label=The cloud service data center that processed therequest. ",
			f, setScp(csgLogWeb.DataCenter))
	}

	if csgLogWeb.SourceIP != "Not available" {
		f = fmt.Sprintf("%ssrc=%s ", f, setScp(csgLogWeb.SourceIP))
	} else {
		f = fmt.Sprintf("%ssrc=%s ", f, setScp(csgLogWeb.ConnectionIP))
	}
	if GetLast(csgLogWeb.CloudAppRiskLevel) != "" {
		f = fmt.Sprintf("%scs5=%s cs5Label=Cloud App Risk Level ", f, GetLast(csgLogWeb.CloudAppRiskLevel))
	}
	if csgLogWeb.RequestMethod != "" {
		f = fmt.Sprintf("%srequestMethod=%s ", f, setScp(csgLogWeb.RequestMethod))
	}
	if csgLogWeb.UserAgent != "" {
		f = fmt.Sprintf("%srequestClientApplication=%s ", f, setScp(csgLogWeb.UserAgent))
	}

	if csgLogWeb.FileType != "" {
		f = fmt.Sprintf("%sfileType=%s ", f, setScp(csgLogWeb.FileType))
	}
	if csgLogWeb.User != "" {
		f = fmt.Sprintf("%ssuid=%s ", f, csgLogWeb.User)
	}
	if csgLogWeb.DateTime != "" {
		dateTime := strings.ReplaceAll(csgLogWeb.DateTime, "\"", "")
		dateTime = strings.ReplaceAll(dateTime, "/", "-")
		timeTrack, _ := time.Parse(LayoutFormat, dateTime)
		dateTime = timeTrack.Format("2006-01-02T15:04:05.000Z")
		f = fmt.Sprintf("%sdeviceCustomDate1=%s deviceCustomDate1Label=Log Created Time ", f, setScp(dateTime))
	}

	return f, nil

}
