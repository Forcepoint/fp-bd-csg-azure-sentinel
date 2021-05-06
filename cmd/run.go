package cmd

import (
	"github.cicd.cloud.fpdev.io/BD/fp-csg-snetinel/lib"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"io/ioutil"
	"os"
	"time"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "run the integration",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if viper.GetBool("csg_creds_flag") {
			cipherText, err := lib.ReadCredentialFromStdin()
			if err != nil {
				logrus.Error(err)
				logrus.Exit(1)
			}
			if err := ioutil.WriteFile(viper.GetString("CSG_ENCRYPTED_FILE"), cipherText, 0666); err != nil {
				logrus.Error(err)
				logrus.Exit(1)
			}
			os.Exit(0)
		}
		if !lib.FileExists(viper.GetString("CSG_ENCRYPTED_FILE")) {
			cipherText, err := lib.ReadCredentialFromStdin()
			if err != nil {
				logrus.Error(err)
				logrus.Exit(1)
			}
			if err := ioutil.WriteFile(viper.GetString("CSG_ENCRYPTED_FILE"), cipherText, 0666); err != nil {
				logrus.Error(err)
				logrus.Exit(1)
			}

		} else {
			// read credentials from encrypted file
			csgCredential, err := lib.ReadCredentialFromDisk(viper.GetString("CSG_ENCRYPTED_FILE"))
			if err != nil {
				logrus.Error(err)
				logrus.Exit(1)
			}
			viper.Set("CSG_PASSWORD", csgCredential.Password)
			viper.Set("CSG_USERNAME", csgCredential.Username)
		}
		// create logDownloader
		logDownloader, err := lib.NewLogsDownloader()
		if err != nil {
			logrus.Errorf("failed in creating a LogsDownloader instance '%s'", err.Error())
			logrus.Exit(1)
		}
		for {
			// web logs
			if viper.GetBool("SEND_WEB_LOGS") {
				include, exclude := lib.WebLogsFilter()
				process(logDownloader, include, exclude, lib.Web)
			}
			// email logs
			if viper.GetBool("SEND_EMAIL_LOGS") {
				includeEmail, excludeEmail := lib.EmailLogsFilter()
				process(logDownloader, includeEmail, excludeEmail, lib.Email)
			}
			time.Sleep(time.Duration(viper.GetInt("INTERVAL_TIME_IN_MINUTES")) * time.Minute)

		}
	},
}

func process(logDownloader *lib.LogsDownloader, include map[string][]string, exclude map[string][]string, category string) {
	logs, err := logDownloader.TackLogs(category)
	if err != nil {
		logrus.Error(err)
	}
	logsToProcess, err := logDownloader.FilterTime(logs.AllLogs, category)
	if err != nil {
		logrus.Error(err)
	}
	for _, v := range logsToProcess {
		lines, err := logDownloader.DownloadLog(v)
		if err != nil {
			logrus.Error(err)
		}

		csvToMaps := lib.CsvToMap(lines)
		lib.ProcessLogs(csvToMaps, include, exclude, category)
	}
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().BoolP("creds", "c", true, "Read CSG Creds and save them on disk as encrypted file")
	if err := viper.BindPFlag("csg_creds_flag",
		runCmd.Flags().Lookup("creds")); err != nil {
		logrus.Fatal(err.Error())
	}
}
