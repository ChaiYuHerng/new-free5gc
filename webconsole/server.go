package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"bitbucket.org/free5gc-team/version"
	"bitbucket.org/free5gc-team/webconsole/backend/logger"
	"bitbucket.org/free5gc-team/webconsole/backend/webui_service"
)

var WEBUI = &webui_service.WEBUI{}

var appLog *logrus.Entry

func init() {
	appLog = logger.AppLog
}

func main() {
	app := cli.NewApp()
	app.Name = "webui"
	appLog.Infoln(app.Name)
	appLog.Infoln("webconsole version: ", version.GetVersion())
	app.Usage = "-free5gccfg common configuration file -webuicfg webui configuration file"
	app.Action = action
	app.Flags = WEBUI.GetCliCmd()
	if err := app.Run(os.Args); err != nil {
		logger.AppLog.Warnf("Error args: %v", err)
	}
}

func action(c *cli.Context) {
	WEBUI.Initialize(c)
	WEBUI.Start()
}
