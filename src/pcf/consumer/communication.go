package consumer

import (
	"context"
	"fmt"
	"free5gc/lib/openapi"
	"free5gc/lib/openapi/models"
	pcf_context "free5gc/src/pcf/context"
	"free5gc/src/pcf/logger"
	"free5gc/src/pcf/util"
	"strings"
)

func AmfStatusChangeSubscribe(amfInfo pcf_context.AMFStatusSubscriptionData) (
	problemDetails *models.ProblemDetails, err error) {
	logger.Consumerlog.Debugf("PCF Subscribe to AMF status[%+v]", amfInfo.AmfUri)
	pcfSelf := pcf_context.PCF_Self()
	client := util.GetNamfClient(amfInfo.AmfUri)

	subscriptionData := models.SubscriptionData{
		AmfStatusUri: fmt.Sprintf("%s/npcf-callback/v1/amfstatus", pcfSelf.GetIPv4Uri()),
		GuamiList:    amfInfo.GuamiList,
	}

	res, httpResp, localErr :=
		client.SubscriptionsCollectionDocumentApi.AMFStatusChangeSubscribe(context.Background(), subscriptionData)
	if localErr == nil {
		locationHeader := httpResp.Header.Get("Location")
		logger.Consumerlog.Debugf("location header: %+v", locationHeader)

		subscriptionId := locationHeader[strings.LastIndex(locationHeader, "/")+1:]
		amfStatusSubsData := pcf_context.AMFStatusSubscriptionData{
			AmfUri:       amfInfo.AmfUri,
			AmfStatusUri: res.AmfStatusUri,
			GuamiList:    res.GuamiList,
		}
		pcfSelf.AMFStatusSubsData[subscriptionId] = amfStatusSubsData
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err = localErr
			return
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("%s: server no response", amfInfo.AmfUri)
	}
	return problemDetails, err
}
