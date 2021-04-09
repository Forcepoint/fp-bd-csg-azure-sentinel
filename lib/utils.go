package lib

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func GunzipData(data []byte) (resData []byte, err error) {
	b := bytes.NewBuffer(data)

	var r io.Reader
	r, err = gzip.NewReader(b)
	if err != nil {
		return
	}

	var resB bytes.Buffer
	_, err = resB.ReadFrom(r)
	if err != nil {
		return
	}
	resData = resB.Bytes()

	return
}

func CsvToMap(lines []string) []map[string]string {
	var csvToMaps []map[string]string
	header := lines[0]
	lines = lines[1:]
	header = strings.ReplaceAll(header, "\"", "")
	headerParts := strings.Split(strings.TrimSpace(header), ",")
	for i, v := range headerParts {
		value := strings.ReplaceAll(v, "-", "")
		value = strings.ReplaceAll(value, " ", "")
		value = strings.ReplaceAll(value, "(Downstream)", "")
		value = strings.ReplaceAll(value, "/", "")
		value = strings.ReplaceAll(value, ":", "")
		value = strings.ReplaceAll(value, ".", "")
		value = strings.ReplaceAll(value, "&", "")

		headerParts[i] = value
	}
	for _, v := range lines {
		var mapCSV = make(map[string]string)
		csv := strings.ReplaceAll(v, "\",\"", "|")
		csvValues := strings.Split(csv, "|")
		if len(csvValues) == len(headerParts) {
			for j, k := range csvValues {
				mapCSV[headerParts[j]] = k
			}
			csvToMaps = append(csvToMaps, mapCSV)
		}
	}
	return csvToMaps
}

func setScp(message string) string {
	s := strings.ReplaceAll(message, "\\", "\\\\")
	s = strings.ReplaceAll(message, "=", "\\=")
	return s

}

func FilterInclude(message map[string]string, include map[string][]string) bool {
	for k, _ := range include {
		if v, ok := message[k]; ok {
			result := ElementInList(include[k], v)
			if !result {
				return result
			}
		} else {
			return false
		}
	}
	return true
}

func FilterExclude(message map[string]string, exclude map[string][]string) bool {
	for k, _ := range exclude {
		if v, ok := message[k]; ok {
			result := ElementInList(exclude[k], v)
			if result {
				return false
			}
		}
	}
	return true
}

func ElementInList(l []string, element string) bool {
	for _, v := range l {
		if v == element {
			return true
		}
	}
	return false
}

func ProcessLogs(logs []map[string]string, include map[string][]string, exclude map[string][]string, category string) {
	for _, v := range logs {
		cef := ""
		displayInfo := ""
		if len(include) != 0 && !FilterInclude(v, include) {
			continue
		}
		if len(exclude) != 0 && !FilterExclude(v, exclude) {
			continue
		}
		if category == Web {
			var csgLogStruct CsgLogWeb
			err := mapstructure.Decode(v, &csgLogStruct)
			if err != nil {
				logrus.Error(err)
			}
			cef, err = CreateCommonEventFormatWeb(csgLogStruct)
			if err != nil {
				logrus.Error(err)
				continue
			}
			displayInfo = fmt.Sprintf("sent web log to sentinel: policy Name:%s, SourceIp=%s, User:%s",
				csgLogStruct.PolicyName, csgLogStruct.SourceIP, csgLogStruct.User)
		} else {
			var csgLogStruct CsgLogEmail
			err := mapstructure.Decode(v, &csgLogStruct)
			if err != nil {
				logrus.Error(err)
			}
			cef, err = CreateCommonEventFormatEmail(csgLogStruct)
			if err != nil {
				logrus.Error(err)
				continue
			}
			displayInfo = fmt.Sprintf("sent email log to sentinel: policy Name:%s, Recipient Address=%s, Action:%s",
				csgLogStruct.PolicyName, csgLogStruct.RecipientAddress, csgLogStruct.Action)
		}
		if err := SendLog(cef); err != nil {
			logrus.Error(err)
		} else {
			if viper.GetBool("DISPLAY_SENT_LOGS_INFO") {
				logrus.Info(displayInfo)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func SendLog(cef string) error {
	if cef != "CEF:0|Forcepoint CSG||1.0|||0|" && cef != "" {
		cmdLogger := fmt.Sprintf("logger -n localhost -P 514 -T '%s'", cef)
		_, err := ExecuteCmd(cmdLogger)
		if err != nil {
			return err
		}
	}
	return nil
}

func ExecuteCmd(cmd string) (string, error) {
	var stdout, stderr bytes.Buffer
	exe := exec.Command("sh", "-c", cmd)
	exe.Stderr = &stderr
	exe.Stdout = &stdout
	err := exe.Run()
	errorResult := string(stderr.Bytes())
	if len(errorResult) != 0 && !strings.Contains(errorResult, "deprecated") {
		return "", errors.New(errorResult)
	}
	if err != nil && !strings.Contains(errorResult, "deprecated") {
		return "", errors.New(fmt.Sprintf("failed to connect to localhost port 514: %s", cmd))
	}
	output := string(stdout.Bytes())
	if len(output) != 0 {
		return strings.TrimSpace(output), nil
	}
	return "", nil
}

func GetLast(csv string) string {
	v := strings.Split(csv, ",")
	return v[len(v)-1]
}

func ReverseList(logs []Log) []Log {
	var reversed []Log
	for i := len(logs) - 1; i >= 0; i-- {
		reversed = append(reversed, logs[i])
	}
	return reversed
}
