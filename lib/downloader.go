package lib

import (
	"encoding/xml"
	"fmt"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	LayoutFormat = "2006-01-02 15:04:05"
	Web          = "web"
	Email        = "email"
)

type LogsDownloader struct {
	LastDownloadTimeWeb   time.Time
	LastDownloadTimeEmail time.Time
	UserName              string
	Password              string
	LogsUrl               string
	*http.Client
}

type Logs struct {
	XMLName xml.Name `xml:"logs"`
	AllLogs []Log    `xml:"log"`
}
type Log struct {
	XMLName xml.Name `xml:"log"`
	Value   float32  `xml:",chardata"`
	Time    string   `xml:"time,attr"`
	Version string   `xml:"version,attr"`
	Size    string   `xml:"size,attr"`
	Url     string   `xml:"url,attr"`
}

func NewLogsDownloader() (*LogsDownloader, error) {
	web := viper.GetString("TIMER_TRACKER_DIRECTORY") + "/web"
	email := viper.GetString("TIMER_TRACKER_DIRECTORY") + "/email"
	exits := FileExists(web)
	if !exits {
		err := ioutil.WriteFile(web,
			[]byte(viper.GetString("WEB_LOGS_START_DATETIME")), 0644)
		if err != nil {
			return nil, errors.Wrap(err, "failed in writing the datetime to TIMER_TRACKER_DIRECTORY for web")
		}
		err = ioutil.WriteFile(email,
			[]byte(viper.GetString("EMAIL_LOGS_START_DATETIME")), 0644)
		if err != nil {
			return nil, errors.Wrap(err, "failed in writing the datetime to TIMER_TRACKER_DIRECTORY for email")
		}
		timeTrackWeb, err := time.Parse(LayoutFormat, viper.GetString("WEB_LOGS_START_DATETIME"))
		timeTrackEmail, err := time.Parse(LayoutFormat, viper.GetString("EMAIL_LOGS_START_DATETIME"))

		return &LogsDownloader{LastDownloadTimeWeb: timeTrackWeb,
			LastDownloadTimeEmail: timeTrackEmail,
			Password:              viper.GetString("CSG_PASSWORD"),
			UserName:              viper.GetString("CSG_USERNAME"),
			LogsUrl:               viper.GetString("CSG_LOGS_URL")}, nil
	}
	datetimeWeb, err := ioutil.ReadFile(web)
	if err != nil {
		return nil, errors.Wrap(err, "Failed in reading the datetime value from 'WEB_LOGS_START_DATETIME'")
	}
	datetimeEmail, err := ioutil.ReadFile(email)
	if err != nil {
		return nil, errors.Wrap(err, "Failed in reading the datetime value from 'EMAIL_LOGS_START_DATETIME'")
	}
	latestDateTimeWeb := string(datetimeWeb)
	latestDateTimeEmail := string(datetimeEmail)
	timeTrackWeb, err := time.Parse(LayoutFormat, latestDateTimeWeb)
	timeTrackEmail, err := time.Parse(LayoutFormat, latestDateTimeEmail)

	return &LogsDownloader{LastDownloadTimeWeb: timeTrackWeb,
		LastDownloadTimeEmail: timeTrackEmail,
		Password:              viper.GetString("CSG_PASSWORD"),
		UserName:              viper.GetString("CSG_USERNAME"),
		LogsUrl:               viper.GetString("CSG_LOGS_URL")}, nil
}

func (d *LogsDownloader) TackLogs(category string) (*Logs, error) {
	logs, err := d.ListLogs(category)
	if err != nil {
		return nil, err
	}
	if len(logs.AllLogs) > 2 {
		reversedLogs := ReverseList(logs.AllLogs)
		logs.AllLogs = reversedLogs
	}
	return logs, nil
}

func (d *LogsDownloader) Do(req *http.Request) (*http.Response, error) {
	req.SetBasicAuth(d.UserName, d.Password)
	return http.DefaultClient.Do(req)
}

func (d *LogsDownloader) ListLogs(category string) (*Logs, error) {
	url := fmt.Sprintf("%s/%s", d.LogsUrl, category)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.Do(req)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New(fmt.Sprintf("got an empty response from %s ", url))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(fmt.Sprintf("Got http statusCode: %d", http.StatusOK))
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	var allLogs Logs
	err = xml.Unmarshal(body, &allLogs)
	return &allLogs, nil

}

func (d *LogsDownloader) FilterTime(logs []Log, category string) ([]string, error) {
	var logsToProcess []string
	maxTime := d.LastDownloadTimeEmail
	if category == Web {
		maxTime = d.LastDownloadTimeWeb
	}
	for _, v := range logs {
		dateTimeParts := strings.Split(v.Time, " ")
		timeParts := strings.Split(dateTimeParts[1], ":")
		if len(timeParts) == 2 {
			v.Time = v.Time + ":00"
		}
		timeTrack, _ := time.Parse(LayoutFormat, v.Time)
		if category == Web {
			if timeTrack.After(d.LastDownloadTimeWeb) {
				if timeTrack.After(maxTime) {
					maxTime = timeTrack
					viper.Set("WEB_LOGS_START_DATETIME", v.Time)
				}
				logsToProcess = append(logsToProcess, v.Url)
			}
		} else {
			if timeTrack.After(d.LastDownloadTimeEmail) {
				if timeTrack.After(maxTime) {
					maxTime = timeTrack
					viper.Set("EMAIL_LOGS_START_DATETIME", v.Time)
				}
				logsToProcess = append(logsToProcess, v.Url)
			}
		}
	}
	if category == Web {
		d.LastDownloadTimeWeb = maxTime
		webTimeFile := viper.GetString("TIMER_TRACKER_DIRECTORY") + "/web"
		err := ioutil.WriteFile(webTimeFile,
			[]byte(viper.GetString("WEB_LOGS_START_DATETIME")), 0644)
		if err != nil {
			return nil, err
		}
	} else {
		d.LastDownloadTimeEmail = maxTime
		emailTimeFile := viper.GetString("TIMER_TRACKER_DIRECTORY") + "/email"
		err := ioutil.WriteFile(emailTimeFile,
			[]byte(viper.GetString("EMAIL_LOGS_START_DATETIME")), 0644)
		if err != nil {
			return nil, err
		}
	}
	return logsToProcess, nil
}

func (d *LogsDownloader) DownloadLog(url string) ([]string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.Do(req)
	if err != nil {
		return nil, err
	}

	if resp == nil {
		return nil, errors.New(fmt.Sprintf("got an empty response from %s ", url))
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	r, err := GunzipData(body)
	if err != nil {
		return nil, errors.Wrap(err, "failed in Gunzip")
	}
	data := string(r)
	lines := strings.Split(strings.TrimSpace(data), "\n")
	return lines, nil
}
