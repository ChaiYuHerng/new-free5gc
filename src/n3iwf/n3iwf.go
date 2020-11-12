package main

import (
	"free5gc/src/app"
	"free5gc/src/n3iwf/logger"
	"free5gc/src/n3iwf/service"
	"free5gc/src/n3iwf/version"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var N3IWF = &service.N3IWF{}

var appLog *logrus.Entry

func init() {
	appLog = logger.AppLog
}

func main() {
	app := cli.NewApp()
	app.Name = "n3iwf"
	appLog.Infoln(app.Name)
	appLog.Infoln("N3IWF version: ", version.GetVersion())
	app.Usage = "-free5gccfg common configuration file -n3iwfcfg n3iwf configuration file"
	app.Action = action
	app.Flags = N3IWF.GetCliCmd()
	if err := app.Run(os.Args); err != nil {
		logger.AppLog.Errorf("N3IWF Run Error: %v", err)
	}
}

func action(c *cli.Context) {
	app.AppInitializeWillInitialize(c.String("free5gccfg"))
	N3IWF.Initialize(c)
	N3IWF.Start()
}
