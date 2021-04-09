package lib

import (
	"fmt"
	"github.com/spf13/viper"
	"strconv"
	"time"

	"strings"
)

func EmailLogsFilter() (map[string][]string, map[string][]string) {
	include := make(map[string][]string)
	exclude := make(map[string][]string)
	if viper.GetString("CSG_EMAIL_LOGS_INCLUDE") != "" {
		includeParts := strings.Split(viper.GetString("CSG_EMAIL_LOGS_INCLUDE"), ",")
		for _, v := range includeParts {
			vParts := strings.Split(v, "=")
			if len(vParts) == 2 {
				include[strings.TrimSpace(vParts[0])] = append(include[strings.TrimSpace(vParts[0])], strings.TrimSpace(vParts[1]))
			}
		}
	}
	if viper.GetString("CSG_EMAIL_LOGS_EXCLUDE") != "" {
		excludeParts := strings.Split(viper.GetString("CSG_EMAIL_LOGS_EXCLUDE"), ",")
		for _, v := range excludeParts {
			vParts := strings.Split(v, "=")
			if len(vParts) == 2 {
				exclude[strings.TrimSpace(vParts[0])] = append(exclude[strings.TrimSpace(vParts[0])], strings.TrimSpace(vParts[1]))
			}
		}
	}
	return include, exclude

}

func CreateCommonEventFormatEmail(csgLogEmail CsgLogEmail) (string, error) {

	severity := 0
	switch strings.ToLower(GetLast(csgLogEmail.EmbURLSeverity)) {
	case "low":
		severity = 3
	case "medium":
		severity = 6
	case "high":
		severity = 9
	case "critical":
		severity = 10
	}
	f := fmt.Sprintf("CEF:0|Forcepoint CSG|Email|%s|%s|%s|%d|",
		viper.GetString("CSG_VERSION"), GetLast(csgLogEmail.EmbURLRiskClass), "CSG EMail", severity)
	if GetLast(csgLogEmail.Action) != "" {
		f = fmt.Sprintf("%sact=%s ", f, GetLast(csgLogEmail.Action))
	}
	if GetLast(csgLogEmail.RecipientAddress) != "" {
		f = fmt.Sprintf("%sduser=%s ", f, GetLast(csgLogEmail.RecipientAddress))
	}
	if GetLast(csgLogEmail.FromAddress) != "" {
		f = fmt.Sprintf("%ssuser=%s ", f, GetLast(csgLogEmail.FromAddress))
	}
	direction := -1
	if csgLogEmail.Direction != "" {
		if strings.ToLower(csgLogEmail.Direction) == "inbound" {
			direction = 0
		}
		if strings.ToLower(csgLogEmail.Direction) == "outbound" {
			direction = 1
		}
	}
	if direction != -1 {
		f = fmt.Sprintf("%sdeviceDirection=%d ", f, direction)
	}
	if GetLast(csgLogEmail.Subject) != "" {
		f = fmt.Sprintf("%smsg=%s ", f, GetLast(csgLogEmail.Subject))
	}

	if GetLast(csgLogEmail.BlackWhitelisted) != "" {
		f = fmt.Sprintf("%scs1=%s cs1Label=Black/white listed ", f, GetLast(csgLogEmail.BlackWhitelisted))
	}
	if GetLast(csgLogEmail.VirusName) != "" {
		f = fmt.Sprintf("%scs2=%s cs2Label=Virus Name ", f, GetLast(csgLogEmail.VirusName))
	}
	if GetLast(csgLogEmail.PolicyName) != "" {
		f = fmt.Sprintf("%scs3=%s cs3Label=Policy Name ", f, GetLast(csgLogEmail.PolicyName))
	}

	if csgLogEmail.SpamScore != "" {
		score, _ := strconv.ParseFloat(csgLogEmail.SpamScore, 32)
		f = fmt.Sprintf("%scfp1=%.1f cfp1Label=Spam Score ", f, score)
	}

	if csgLogEmail.MessageSize != "" {
		size, _ := strconv.Atoi(csgLogEmail.MessageSize)
		f = fmt.Sprintf("%scn1=%d cn1Label=Message Size ", f, size)
	}
	if GetLast(csgLogEmail.AttachmentSize) != "" {
		size, _ := strconv.Atoi(csgLogEmail.AttachmentSize)
		f = fmt.Sprintf("%sfsize=%d ", f, size)
	}
	if csgLogEmail.AttachmentFilename != "" {
		f = fmt.Sprintf("%sfname=%s ", f, setScp(csgLogEmail.AttachmentFilename))
	}
	if csgLogEmail.AdvancedEncryption != "" {
		f = fmt.Sprintf("%scs4=%s cs4Label=Advanced Encryption ", f, csgLogEmail.AdvancedEncryption)
	}
	if csgLogEmail.FilteringReason != "" {
		f = fmt.Sprintf("%sflexString1=%s flexString1Label=Filtering Reason ", f, setScp(csgLogEmail.FilteringReason))
	}

	if csgLogEmail.SenderIP != "" {
		f = fmt.Sprintf("%ssrc=%s ", f, setScp(csgLogEmail.SenderIP))
	}
	if GetLast(csgLogEmail.AttachmentFileType) != "" {
		f = fmt.Sprintf("%sfileType=%s ", f, GetLast(csgLogEmail.AttachmentFileType))
	}
	if csgLogEmail.SenderName != "" {
		f = fmt.Sprintf("%ssuid=%s ", f, csgLogEmail.SenderName)
	}
	if csgLogEmail.DateTime != "" {
		dateTime := strings.ReplaceAll(csgLogEmail.DateTime, "\"", "")
		dateTime = strings.ReplaceAll(dateTime, "/", "-")
		timeTrack, _ := time.Parse(LayoutFormat, dateTime)
		dateTime = timeTrack.Format("2006-01-02T15:04:05.000Z")
		f = fmt.Sprintf("%sdeviceCustomDate1=%s deviceCustomDate1Label=Log Created Time ", f, setScp(dateTime))
	}

	return f, nil

}
