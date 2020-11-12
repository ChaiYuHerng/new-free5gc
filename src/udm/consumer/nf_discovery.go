package consumer

import (
	"context"
	"fmt"

	// "github.com/antihax/optional"
	"free5gc/lib/openapi/Nnrf_NFDiscovery"
	"free5gc/lib/openapi/models"
	udm_context "free5gc/src/udm/context"
	"free5gc/src/udm/logger"
	"free5gc/src/udm/util"
	"net/http"
)

const (
	NFDiscoveryToUDRParamSupi int = iota
	NFDiscoveryToUDRParamExtGroupId
	NFDiscoveryToUDRParamGpsi
)

func SendNFIntances(nrfUri string, targetNfType, requestNfType models.NfType,
	param Nnrf_NFDiscovery.SearchNFInstancesParamOpts) (result models.SearchResult, err error) {

	// config := factory.UdmConfig
	// nrfclient := config.Configuration.Nrfclient
	// addr := fmt.Sprintf("%s://%s:%d", nrfclient.Scheme, nrfclient.Ipv4Addr, nrfclient.Port)

	configuration := Nnrf_NFDiscovery.NewConfiguration()
	configuration.SetBasePath(nrfUri) //addr
	clientNRF := Nnrf_NFDiscovery.NewAPIClient(configuration)

	result, res, err1 := clientNRF.NFInstancesStoreApi.SearchNFInstances(context.TODO(), targetNfType,
		requestNfType, &param)
	if err1 != nil {
		err = err1
		return
	}
	if res != nil && res.StatusCode == http.StatusTemporaryRedirect {
		err = fmt.Errorf("Temporary Redirect For Non NRF Consumer")
	}
	return
}

func SendNFIntancesUDR(id string, types int) string {

	self := udm_context.UDM_Self()
	targetNfType := models.NfType_UDR
	requestNfType := models.NfType_UDM
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
	fmt.Println(self.NrfUri)
	result, err := SendNFIntances(self.NrfUri, targetNfType, requestNfType, localVarOptionals)
	if err != nil {
		logger.Handlelog.Error(err.Error())
		return ""
	}
	for _, profile := range result.NfInstances {
		return util.SearchNFServiceUri(profile, models.ServiceName_NUDR_DR, models.NfServiceStatus_REGISTERED)
	}
	return ""
}
