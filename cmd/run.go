package cmd

import (
	"github.cicd.cloud.fpdev.io/BD/fp-csg-snetinel/lib"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"time"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "run the integration",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		for {
			// web logs
			if viper.GetBool("SEND_WEB_LOGS") {
				include, exclude := lib.WebLogsFilter()
				process(include, exclude, lib.Web)
			}
			// email logs
			if viper.GetBool("SEND_EMAIL_LOGS") {
				includeEmail, excludeEmail := lib.EmailLogsFilter()
				process(includeEmail, excludeEmail, lib.Email)
			}
			time.Sleep(time.Duration(viper.GetInt("INTERVAL_TIME_IN_MINUTES")) * time.Minute)

		}
	},
}

func process(include map[string][]string, exclude map[string][]string, category string) {
	logs, err := LogDownloader.TackLogs(category)
	if err != nil {
		logrus.Error(err)
	}
	logsToProcess, err := LogDownloader.FilterTime(logs.AllLogs, category)
	if err != nil {
		logrus.Error(err)
	}
	for _, v := range logsToProcess {
		lines, err := LogDownloader.DownloadLog(v)
		if err != nil {
			logrus.Error(err)
		}

		csvToMaps := lib.CsvToMap(lines)
		lib.ProcessLogs(csvToMaps, include, exclude, category)
	}
}

func init() {
	rootCmd.AddCommand(runCmd)
}
