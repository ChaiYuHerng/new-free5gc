package TestAmf

import (
	"free5gc/lib/openapi/models"
	"github.com/google/uuid"
)

func BuildSmfNfProfile() (uuId string, profile models.NfProfile) {
	fmt.Printf("\n\n\nnow in the BuildSmfNfProfile function\n\n\n")
	uuId = uuid.New().String()
	profile = models.NfProfile{
		NfInstanceId: uuId,
		NfType:       models.NfType_SMF,
		NfStatus:     models.NfStatus_REGISTERED,
		SNssais: &[]models.Snssai{
			{
				Sst: 1,
				Sd:  "010203",
			},
		},
		PlmnList: &[]models.PlmnId{
			{
				Mcc: "208",
				Mnc: "93",
			},
		},
		NfServices: &[]models.NfService{
			{

				ServiceInstanceId: "1",
				ServiceName:       models.ServiceName_NSMF_PDUSESSION,
				Scheme:            models.UriScheme_HTTPS,
				NfServiceStatus:   models.NfServiceStatus_REGISTERED,
				Versions: &[]models.NfServiceVersion{
					{
						ApiVersionInUri: "v1",
						ApiFullVersion:  "1.0.0",
					},
				},
				ApiPrefix: "https://192.168.2.103:29502",
				IpEndPoints: &[]models.IpEndPoint{
					{
						Ipv4Address: "192.168.2.103",
						Port:        29502,
					},
				},
			},
		},
		SmfInfo: &models.SmfInfo{
			SNssaiSmfInfoList: &[]models.SnssaiSmfInfoItem{
				{
					SNssai: &models.Snssai{
						Sst: 1,
						Sd:  "010203",
					},
					DnnSmfInfoList: &[]models.DnnSmfInfoItem{
						{
							Dnn: "internet",
						},
					},
				},
			},
		},
	}
	return

}
