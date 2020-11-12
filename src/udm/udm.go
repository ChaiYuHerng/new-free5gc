package main

import (
	"fmt"
	"free5gc/src/app"
	"free5gc/src/udm/logger"
	"free5gc/src/udm/service"
	"free5gc/src/udm/version"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"os"
)

var UDM = &service.UDM{}

var appLog *logrus.Entry

func init() {
	appLog = logger.AppLog
}

func main() {
	app := cli.NewApp()
	app.Name = "udm"
	fmt.Print(app.Name, "\n")
	appLog.Infoln("UDM version: ", version.GetVersion())
	app.Usage = "-free5gccfg common configuration file -udmcfg udm configuration file"
	app.Action = action
	app.Flags = UDM.GetCliCmd()
	if err := app.Run(os.Args); err != nil {
		fmt.Printf("UDM Run error: %v", err)
	}

	// appLog.Infoln(app.Name)

}

func action(c *cli.Context) {
	app.AppInitializeWillInitialize(c.String("free5gccfg"))
	UDM.Initialize(c)
	UDM.Start()
}
