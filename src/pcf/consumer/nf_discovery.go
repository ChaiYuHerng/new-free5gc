package consumer

import (
	"context"
	"fmt"
	"free5gc/lib/openapi/Nnrf_NFDiscovery"
	"free5gc/lib/openapi/models"
	pcf_context "free5gc/src/pcf/context"
	"free5gc/src/pcf/logger"
	"free5gc/src/pcf/util"
	"net/http"

	"github.com/antihax/optional"
)

func SendSearchNFInstances(
	nrfUri string, targetNfType, requestNfType models.NfType, param Nnrf_NFDiscovery.SearchNFInstancesParamOpts) (
	result models.SearchResult, err error) {

	// Set client and set url
	configuration := Nnrf_NFDiscovery.NewConfiguration()
	configuration.SetBasePath(nrfUri)
	client := Nnrf_NFDiscovery.NewAPIClient(configuration)

	var res *http.Response
	result, res, err = client.NFInstancesStoreApi.SearchNFInstances(context.TODO(), targetNfType, requestNfType, &param)
	if res != nil && res.StatusCode == http.StatusTemporaryRedirect {
		err = fmt.Errorf("Temporary Redirect For Non NRF Consumer")
	}
	return
}

func SendNFIntancesUDR(nrfUri, id string) string {
	targetNfType := models.NfType_UDR
	requestNfType := models.NfType_PCF
	localVarOptionals := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{
		// 	DataSet: optional.NewInterface(models.DataSetId_SUBSCRIPTION),
	}
	// switch types {
	// case NFDiscoveryToUDRParamSupi:
	// 	localVarOptionals.Supi = optional.NewString(id)
	// case NFDiscoveryToUDRParamExtGroupId:
	// 	localVarOptionals.ExternalGroupIdentity = optional.NewString(id)
	// case NFDiscoveryToUDRParamGpsi:
	// 	localVarOptionals.Gpsi = optional.NewString(id)
	// }

	result, err := SendSearchNFInstances(nrfUri, targetNfType, requestNfType, localVarOptionals)
	if err != nil {
		logger.Consumerlog.Error(err.Error())
		return ""
	}
	for _, profile := range result.NfInstances {
		if uri := util.SearchNFServiceUri(profile, models.ServiceName_NUDR_DR, models.NfServiceStatus_REGISTERED); uri != "" {
			return uri
		}
	}
	return ""
}

func SendNFIntancesAMF(nrfUri string, guami models.Guami, serviceName models.ServiceName) string {
	targetNfType := models.NfType_AMF
	requestNfType := models.NfType_PCF

	localVarOptionals := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{
		Guami: optional.NewInterface(util.MarshToJsonString(guami)),
	}
	// switch types {
	// case NFDiscoveryToUDRParamSupi:
	// 	localVarOptionals.Supi = optional.NewString(id)
	// case NFDiscoveryToUDRParamExtGroupId:
	// 	localVarOptionals.ExternalGroupIdentity = optional.NewString(id)
	// case NFDiscoveryToUDRParamGpsi:
	// 	localVarOptionals.Gpsi = optional.NewString(id)
	// }

	result, err := SendSearchNFInstances(nrfUri, targetNfType, requestNfType, localVarOptionals)
	if err != nil {
		logger.Consumerlog.Error(err.Error())
		return ""
	}
	for _, profile := range result.NfInstances {
		return util.SearchNFServiceUri(profile, serviceName, models.NfServiceStatus_REGISTERED)
	}
	return ""
}

func SearchAvailableAMFs(nrfUri string, serviceName models.ServiceName) (
	amfInfos []pcf_context.AMFStatusSubscriptionData) {
	localVarOptionals := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{}

	result, err := SendSearchNFInstances(nrfUri, models.NfType_AMF, models.NfType_PCF, localVarOptionals)
	if err != nil {
		logger.Consumerlog.Error(err.Error())
		return
	}

	for _, profile := range result.NfInstances {
		uri := util.SearchNFServiceUri(profile, serviceName, models.NfServiceStatus_REGISTERED)
		if uri != "" {
			item := pcf_context.AMFStatusSubscriptionData{
				AmfUri:    uri,
				GuamiList: *profile.AmfInfo.GuamiList,
			}
			amfInfos = append(amfInfos, item)
		}
	}
	return
}
