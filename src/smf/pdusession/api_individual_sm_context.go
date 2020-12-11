/*
 * Nsmf_PDUSession
 *
 * SMF PDU Session Service
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package pdusession

import (
	"free5gc/lib/http_wrapper"
	"free5gc/lib/openapi"
	"free5gc/lib/openapi/models"
	"free5gc/src/smf/logger"
	"free5gc/src/smf/producer"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"strings"
)

// HTTPReleaseSmContext - Release SM Context
func HTTPReleaseSmContext(c *gin.Context) {
	logger.PduSessLog.Info("Recieve Release SM Context Request")
	var request models.ReleaseSmContextRequest
	request.JsonData = new(models.SmContextReleaseData)

	s := strings.Split(c.GetHeader("Content-Type"), ";")
	var err error
	switch s[0] {
	case "application/json":
		err = c.ShouldBindJSON(request.JsonData)
	case "multipart/related":
		err = c.ShouldBindWith(&request, openapi.MultipartRelatedBinding{})
	}
	if err != nil {
		log.Print(err)
		return
	}

	req := http_wrapper.NewRequest(c.Request, request)
	req.Params["smContextRef"] = c.Params.ByName("smContextRef")

	smContextRef := req.Params["smContextRef"]
	producer.HandlePDUSessionSMContextRelease(
		smContextRef, req.Body.(models.ReleaseSmContextRequest))

	c.Status(http.StatusNoContent)

}

// RetrieveSmContext - Retrieve SM Context
func RetrieveSmContext(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{})
}

// HTTPUpdateSmContext - Update SM Context
func HTTPUpdateSmContext(c *gin.Context) {
	logger.PduSessLog.Info("Recieve Update SM Context Request")
	var request models.UpdateSmContextRequest
	request.JsonData = new(models.SmContextUpdateData)

	s := strings.Split(c.GetHeader("Content-Type"), ";")
	var err error
	switch s[0] {
	case "application/json":
		err = c.ShouldBindJSON(request.JsonData)
	case "multipart/related":
		err = c.ShouldBindWith(&request, openapi.MultipartRelatedBinding{})
	}
	if err != nil {
		log.Print(err)
		return
	}

	req := http_wrapper.NewRequest(c.Request, request)
	req.Params["smContextRef"] = c.Params.ByName("smContextRef")

	
	fmt.Printf("in the api_individual_sm_context, c.Request is %v\n\n",c.Request)
	smContextRef := req.Params["smContextRef"]
	fmt.Printf("in the api_individual_sm_context, smContextRef is %v\n\n",smContextRef)
	HTTPResponse := producer.HandlePDUSessionSMContextUpdate(
		smContextRef, req.Body.(models.UpdateSmContextRequest))

	fmt.Printf("in the api_individual_sm_context, HTTPResponse is %v\n\n",HTTPResponse)
	if HTTPResponse.Status < 300 {
		c.Render(HTTPResponse.Status, openapi.MultipartRelatedRender{Data: HTTPResponse.Body})
	} else {
		c.JSON(HTTPResponse.Status, HTTPResponse.Body)
	}
}
