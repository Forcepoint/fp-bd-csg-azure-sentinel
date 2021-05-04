package cmd

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"io"
	"os"
)

var (
	cfgFile string
)
var rootCmd = &cobra.Command{
	Use:   "fp-csg-sentinel",
	Short: "send Forcepoint Cloud Security Gateway logs to azure Sentinel",
	Long:  ``,
}

func Execute(hashKey string) {
	viper.Set("hash_key", hashKey)
	if err := rootCmd.Execute(); err != nil {
		logrus.Error(err)
		logrus.Exit(1)
	}
}

func init() {
	viper.SetDefault("hash_key", "")
	viper.SetDefault("CSG_ENCRYPTED_FILE", "/var/forpcepoint-csg/csg")
	viper.SetDefault("TIMER_TRACKER_DIRECTORY", "/var/forpcepoint-csg")
	viper.SetDefault("INTERNAL_LOGS_FILE", "/var/forpcepoint-csg/csg-sentinel.log")
	viper.SetDefault("WEB_LOGS_START_DATETIME", "2020-08-18 18:40:00")
	viper.SetDefault("EMAIL_LOGS_START_DATETIME", "2020-08-18 18:40:00")
	viper.SetDefault("CSG_PASSWORD", "")
	viper.SetDefault("CSG_USERNAME", "")
	viper.SetDefault("CSG_LOGS_URL", "https://hlfs-web-d.mailcontrol.com/siem/logs")
	viper.SetDefault("CSG_VERSION", "1.0")
	viper.SetDefault("CSG_WEB_LOGS_INCLUDE", "")
	viper.SetDefault("CSG_WEB_LOGS_EXCLUDE", "")
	viper.SetDefault("CSG_EMAIL_LOGS_INCLUDE", "")
	viper.SetDefault("CSG_EMAIL_LOGS_EXCLUDE", "")
	viper.SetDefault("INTERVAL_TIME_IN_MINUTES", 10)
	viper.SetDefault("DISPLAY_SENT_LOGS_INFO", true)
	viper.SetDefault("SEND_WEB_LOGS", true)
	viper.SetDefault("SEND_EMAIL_LOGS", true)
	viper.SetDefault("csg_creds_flag", false)

	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file ")

}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	}
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
	errorLogFile, err := os.OpenFile(viper.GetString("INTERNAL_LOGS_FILE"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		logrus.Fatalf("Cannot create or open the Error logs file: %s", viper.GetString("INTERNAL_LOGS_FILE"))
	}
	mw := io.MultiWriter(os.Stdout, errorLogFile)
	logrus.SetOutput(mw)
	logrus.SetFormatter(&logrus.TextFormatter{})

}
