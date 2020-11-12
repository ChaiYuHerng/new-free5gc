package WebUI

import "free5gc/lib/openapi/models"

type SubsData struct {
	PlmnID                            string                                   `json:"plmnID"`
	UeId                              string                                   `json:"ueId"`
	AuthenticationSubscription        models.AuthenticationSubscription        `json:"AuthenticationSubscription"`
	AccessAndMobilitySubscriptionData models.AccessAndMobilitySubscriptionData `json:"AccessAndMobilitySubscriptionData"`
	SessionManagementSubscriptionData models.SessionManagementSubscriptionData `json:"SessionManagementSubscriptionData"`
	SmfSelectionSubscriptionData      models.SmfSelectionSubscriptionData      `json:"SmfSelectionSubscriptionData"`
	AmPolicyData                      models.AmPolicyData                      `json:"AmPolicyData"`
	SmPolicyData                      models.SmPolicyData                      `json:"SmPolicyData"`
}
