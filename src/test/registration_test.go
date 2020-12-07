package test_test

import (
	//"context"
	"encoding/hex"
	//"free5gc/lib/CommonConsumerTestData/PCF/TestPolicyAuthorization"
	"free5gc/lib/CommonConsumerTestData/UDM/TestGenAuthData"
	"free5gc/lib/CommonConsumerTestData/UDR/TestRegistrationProcedure"
	//"free5gc/lib/http2_util"
	"free5gc/lib/nas"
	"free5gc/lib/nas/nasMessage"
	"free5gc/lib/nas/nasTestpacket"
	"free5gc/lib/nas/nasType"
	"free5gc/lib/nas/security"
	"free5gc/lib/ngap"
	//"free5gc/lib/openapi/Npcf_PolicyAuthorization"
	"free5gc/lib/openapi/models"
	//"net/http"

	//"github.com/gin-gonic/gin"
	//"github.com/mohae/deepcopy"

	// ausf_context "free5gc/src/ausf/context"
	"free5gc/src/test"
	"net"
	"testing"
	"time"
        "os"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
        "log"
	"fmt"
	//"os/exec"
        "bytes"
	"encoding/binary"
	"sync"
	"github.com/stretchr/testify/assert"
	"github.com/google/gopacket"
        "github.com/google/gopacket/layers"
)

// Traffic Generator Configure
var wg sync.WaitGroup
var udpInterval time.Duration = 100 * time.Nanosecond
var udpPacketCount int =        15000
var totalUdpPacket int = 120000000000

const my_type int = 1
const ranIpAddr string = "192.168.2.157" //157, 150, 25
const amfIpAddr string = "192.168.2.102" // no need to change
const upfIpAddr1 string = "192.168.2.111" // 110, 111
const upfIpAddr2 string = "192.168.2.111" // 110, 111
const dNServer1  string = "192.168.2.54" // 54, 219, 23
var dNServerI = [4]byte{192, 168, 2, 54} // 54, 219, 23

type UE struct {
    Supi              string
    Teid              uint32
    RanUeNgapId       int64
    AmfUeNgapId       int64
    MobileIdentity5GS nasType.MobileIdentity5GS
    PduSessionId2     int64
    PduSessionId1     uint8
    DN                string
    Ip                string
    ranIpAddr         string
}

var my_ue = UE{
    Supi:        "imsi-2089300007487",
    Teid:        1,
    RanUeNgapId: 1,
    AmfUeNgapId: 1,
    MobileIdentity5GS: nasType.MobileIdentity5GS{
        Len:    12, //, suci
        Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
    },
    PduSessionId1: 10,
    PduSessionId2: 10,
    DN:            "internet",
    Ip:            "60.60.0.1",
    ranIpAddr:     ranIpAddr,
}

var my_ue2 = UE{
    Supi:        "imsi-2089300007488",
    Teid:        2,
    RanUeNgapId: 2,
    AmfUeNgapId: 2,
    MobileIdentity5GS: nasType.MobileIdentity5GS{
        Len:    12, //, suci
        Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x88},
    },
    PduSessionId1: 11,
    PduSessionId2: 11,
    DN:            "internet2",
    Ip:            "60.60.0.1",
    ranIpAddr:     ranIpAddr,
}




func BuildGTPHeader(teid uint32, seq uint16) ([]byte, error) {
    var ml uint16 = 52
    gtpheader := &layers.GTPv1U{
        Version:             1,
        ProtocolType:        1,
        Reserved:            0,
        ExtensionHeaderFlag: false,
        SequenceNumberFlag:  true,
        NPDUFlag:            false,
        MessageType:         255,
        MessageLength:       ml,
        TEID:                teid,
        SequenceNumber:      seq,
    }
    buf := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{}
    err := gtpheader.SerializeTo(buf, opts)

    if err != nil {
        return nil, err
    }
    return buf.Bytes(), nil
}

func CheckSum(data []byte) uint16 {
    var (
        sum    uint32
        length int = len(data)
        index  int
    )
    //以每16位为单位进行求和，直到所有的字节全部求完或者只剩下一个8位字节（如果剩余一个8位字节说明字节数为奇数个）
    for length > 1 {
        sum += uint32(data[index])<<8 + uint32(data[index+1])
        index += 2
        length -= 2
    }
    //如果字节数为奇数个，要加上最后剩下的那个8位字节
    if length > 0 {
        sum += uint32(data[index])
    }
    //加上高16位进位的部分
    sum += (sum >> 16)
    //别忘了返回的时候先求反
    return uint16(^sum)
}

func ipv4HeaderChecksum(hdr *ipv4.Header) uint32 {
	var Checksum uint32
	Checksum += uint32((hdr.Version<<4|(20>>2&0x0f))<<8 | hdr.TOS)
	Checksum += uint32(hdr.TotalLen)
	Checksum += uint32(hdr.ID)
	Checksum += uint32((hdr.FragOff & 0x1fff) | (int(hdr.Flags) << 13))
	Checksum += uint32((hdr.TTL << 8) | (hdr.Protocol))

	src := hdr.Src.To4()
	Checksum += uint32(src[0])<<8 | uint32(src[1])
	Checksum += uint32(src[2])<<8 | uint32(src[3])
	dst := hdr.Dst.To4()
	Checksum += uint32(dst[0])<<8 | uint32(dst[1])
	Checksum += uint32(dst[2])<<8 | uint32(dst[3])
	return ^(Checksum&0xffff0000>>16 + Checksum&0xffff)
}

func getAuthSubscription() (authSubs models.AuthenticationSubscription) {
	authSubs.PermanentKey = &models.PermanentKey{
		PermanentKeyValue: TestGenAuthData.MilenageTestSet19.K,
	}
	authSubs.Opc = &models.Opc{
		OpcValue: TestGenAuthData.MilenageTestSet19.OPC,
	}
	authSubs.Milenage = &models.Milenage{
		Op: &models.Op{
			OpValue: TestGenAuthData.MilenageTestSet19.OP,
		},
	}
	authSubs.AuthenticationManagementField = "8000"

	authSubs.SequenceNumber = TestGenAuthData.MilenageTestSet19.SQN
	authSubs.AuthenticationMethod = models.AuthMethod__5_G_AKA
	return
}

func getAccessAndMobilitySubscriptionData() (amData models.AccessAndMobilitySubscriptionData) {
	return TestRegistrationProcedure.TestAmDataTable[TestRegistrationProcedure.FREE5GC_CASE]
}

func getSmfSelectionSubscriptionData() (smfSelData models.SmfSelectionSubscriptionData) {
	return TestRegistrationProcedure.TestSmfSelDataTable[TestRegistrationProcedure.FREE5GC_CASE]
}

func getSessionManagementSubscriptionData() (smfSelData models.SessionManagementSubscriptionData) {
	return TestRegistrationProcedure.TestSmSelDataTable[TestRegistrationProcedure.FREE5GC_CASE]
}

func getAmPolicyData() (amPolicyData models.AmPolicyData) {
	return TestRegistrationProcedure.TestAmPolicyDataTable[TestRegistrationProcedure.FREE5GC_CASE]
}

func getSmPolicyData() (smPolicyData models.SmPolicyData) {
	return TestRegistrationProcedure.TestSmPolicyDataTable[TestRegistrationProcedure.FREE5GC_CASE]
}

// Need to configure
var rg_ues = my_ue

// Registration
func TestRegistration(t *testing.T) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// RAN connect to AMF
	fmt.Printf("start\n\n")
	conn, err := test.ConntectToAmf(amfIpAddr, ranIpAddr, 38412, 9487)
	assert.Nil(t, err)
        fmt.Printf("RAN connect to AMF\n")
	// RAN connect to UPF
	//upfConn, err := connectToUpf(ranIpAddr, upfIpAddr, 2152, 2152)
	//assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
        fmt.Printf("send NGSetupRequest Msg\n")
	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
        fmt.Printf("receive NGSetupResponse Msg\n")
	// New UE
	// ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA2, security.AlgIntegrity128NIA2)
	ue := test.NewRanUeContext(rg_ues.Supi, rg_ues.RanUeNgapId, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2)
	ue.AmfUeNgapId = rg_ues.AmfUeNgapId
	ue.AuthenticationSubs = getAuthSubscription()
	// insert UE data to MongoDB

	servingPlmnId := "20893"
	test.InsertAuthSubscriptionToMongoDB(ue.Supi, ue.AuthenticationSubs)
    getData := test.GetAuthSubscriptionFromMongoDB(ue.Supi)
	assert.NotNil(t, getData)
	{
        fmt.Printf("now is amData\n")
        amData := getAccessAndMobilitySubscriptionData()
        fmt.Printf("amData is %v\n\n",amData)
		test.InsertAccessAndMobilitySubscriptionDataToMongoDB(ue.Supi, amData, servingPlmnId)
        getData := test.GetAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
        fmt.Printf("getData is %v\n\n",getData)
		assert.NotNil(t, getData)
	}
	{
        fmt.Printf("now is smfSelfData\n")
        smfSelData := getSmfSelectionSubscriptionData()
        fmt.Printf("smfSelData is %v\n\n",smfSelData)
		test.InsertSmfSelectionSubscriptionDataToMongoDB(ue.Supi, smfSelData, servingPlmnId)
        getData := test.GetSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
        fmt.Printf("getData is %v\n\n",getData)
		assert.NotNil(t, getData)
	}
	{
        fmt.Printf("now is smSelData\n")
        smSelData := getSessionManagementSubscriptionData()
        fmt.Printf("smSelData is %v\n\n",smSelData)
		test.InsertSessionManagementSubscriptionDataToMongoDB(ue.Supi, servingPlmnId, smSelData)
        getData := test.GetSessionManagementDataFromMongoDB(ue.Supi, servingPlmnId)
        fmt.Printf("getData is %v\n\n",getData)
		assert.NotNil(t, getData)
	}
	{
        fmt.Printf("now is amPolicyData\n")
        amPolicyData := getAmPolicyData()
        fmt.Printf("amPolicyData is %v\n\n",amPolicyData)
		test.InsertAmPolicyDataToMongoDB(ue.Supi, amPolicyData)
        getData := test.GetAmPolicyDataFromMongoDB(ue.Supi)
        fmt.Printf("getData is %v\n\n",getData)
		assert.NotNil(t, getData)
	}
	{
        fmt.Printf("now is smPolicyData\n")
        smPolicyData := getSmPolicyData()
        fmt.Printf("smPolicyData is %v\n\n",smPolicyData)
		test.InsertSmPolicyDataToMongoDB(ue.Supi, smPolicyData)
        getData := test.GetSmPolicyDataFromMongoDB(ue.Supi)
        fmt.Printf("getData is %v\n\n",getData)
		assert.NotNil(t, getData)
    }
    fmt.Printf("t is %v\n\n",t)
        fmt.Printf("insert UE data to MongoDB\n")
	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := rg_ues.MobileIdentity5GS
		//Len:    12, // suci
		//Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	//}

	ueSecurityCapability := setUESecurityCapability(ue)
	registrationRequest := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
        fmt.Printf("send InitialUeMessage\n")
	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
        fmt.Printf("receive NAS Authentication Request Msg\n")
	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue,ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
	assert.NotNil(t, nasPdu)
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")
        fmt.Printf("Calculate for RES*\n")
	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
        fmt.Printf("send NAS Authentication Response\n")
	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
        fmt.Printf("receive NAS Security Mode Command Msg\n")
	// send NAS Security Mode Complete Msg
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequest)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
        fmt.Printf("send NAS Security Mode Complete Msg\n")
	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
        fmt.Printf("receive ngap Initial Context Setup Request Msg\n")
	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
        fmt.Printf("send ngap Initial Context Setup Response Msg\n")
	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	//fmt.Printf("check1\n")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	//fmt.Printf("check2\n")
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
        fmt.Printf("send NAS Registration Complete Msg\n")
	time.Sleep(100 * time.Millisecond)
	// send GetPduSessionEstablishmentRequest Msg

	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "010203",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(rg_ues.PduSessionId1, nasMessage.ULNASTransportRequestTypeInitialRequest, rg_ues.DN, &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	//fmt.Printf("check1\n")
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	//fmt.Printf("check2\n")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	//fmt.Printf("check3\n")
	assert.Nil(t, err)
        fmt.Printf("send GetPduSessionEstablishmentRequest Msg\n")
	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
        fmt.Printf("receive 12. NGAP-PDU Session Resource Setup Request\n")
	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId, ranIpAddr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
        fmt.Printf("send 14. NGAP-PDU Session Resource Setup Response\n")
	// wait 1s
	time.Sleep(1 * time.Second)

	// Send the dummy packet
	// ping IP(tunnel IP) from 60.60.0.2(127.0.0.1) to 60.60.0.20(127.0.0.8)
	/*gtpHdr, err := hex.DecodeString("32ff00340000000100000000")
	assert.Nil(t, err)
	icmpData, err := hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	assert.Nil(t, err)

	ipv4hdr := ipv4.Header{
		Version:  4,
		Len:      20,
		Protocol: 1,
		Flags:    0,
		TotalLen: 48,
		TTL:      64,
		Src:      net.ParseIP(ranIpAddr).To4(),
		Dst:      net.ParseIP(upfIpAddr).To4(),
		ID:       1,
	}
	checksum := ipv4HeaderChecksum(&ipv4hdr)
	ipv4hdr.Checksum = int(checksum)

	v4HdrBuf, err := ipv4hdr.Marshal()
	assert.Nil(t, err)
	tt := append(gtpHdr, v4HdrBuf...)
	assert.Nil(t, err)

	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: 12394, Seq: 1,
			Data: icmpData,
		},
	}
	b, err := m.Marshal(nil)
	assert.Nil(t, err)
	b[2] = 0xaf
	b[3] = 0x88
	_, err = upfConn.Write(append(tt, b...))
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)*/
        
	// delete test data
	test.DelAuthSubscriptionToMongoDB(ue.Supi)
	test.DelAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
	test.DelSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)

	// close Connection
	conn.Close()
}

func setUESecurityCapability(ue *test.RanUeContext) (UESecurityCapability *nasType.UESecurityCapability) {
	UESecurityCapability = &nasType.UESecurityCapability{
		Iei:    nasMessage.RegistrationRequestUESecurityCapabilityType,
		Len:    8,
		Buffer: []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
	switch ue.CipheringAlg {
	case security.AlgCiphering128NEA0:
		UESecurityCapability.SetEA0_5G(1)
	case security.AlgCiphering128NEA1:
		UESecurityCapability.SetEA1_128_5G(1)
	case security.AlgCiphering128NEA2:
		UESecurityCapability.SetEA2_128_5G(1)
	case security.AlgCiphering128NEA3:
		UESecurityCapability.SetEA3_128_5G(1)
	}

	switch ue.IntegrityAlg {
	case security.AlgIntegrity128NIA0:
		UESecurityCapability.SetIA0_5G(1)
	case security.AlgIntegrity128NIA1:
		UESecurityCapability.SetIA1_128_5G(1)
	case security.AlgIntegrity128NIA2:
		UESecurityCapability.SetIA2_128_5G(1)
	case security.AlgIntegrity128NIA3:
		UESecurityCapability.SetIA3_128_5G(1)
	}

	return
}

func TestTransfer(t *testing.T) {
    fmt.Println("Start Transmission...")
    // RAN connect to UPF
    upfConn1, err := test.ConnectToUpf(ranIpAddr, upfIpAddr1, 2152, 2152)
    //upfConn1, err := connectToUpf("192.168.2.146", "192.168.122.204", 2152, 2152)
	assert.Nil(t, err)
	/*upfConn2, err := test.ConnectToUpf(ranIpAddr, upfIpAddr2, 2152, 2152)
	assert.Nil(t, err)
	upfConn3, err := test.ConnectToUpf(ranIpAddr, upfIpAddr3, 2152, 2152)
	assert.Nil(t, err)*/

    // wait 1s
    time.Sleep(1 * time.Second)

    logger := log.New(os.Stdout, "", 0)
    //recv := make(chan time.Time, 1)
    //defer close(recv)

    //for _, ueData := range ues {
        //go gtpPacketListener(upfConn, logger)
    wg.Add(1)
    go gtpPacketListener(upfConn1, logger)
    wg.Add(1)
    go icmpTrafficGenerator(1, "60.60.0.1", upfConn1, logger)
    wg.Add(1)
	go udpTrafficGenerator(1, "60.60.0.1", upfConn1, logger)
	wg.Add(1)
    /*go gtpPacketListener(upfConn2, logger)
    wg.Add(1)
    go icmpTrafficGenerator2(1, "60.60.0.1", upfConn2, logger)
    wg.Add(1)
	go udpTrafficGenerator2(1, "60.60.0.1", upfConn2, logger)
	wg.Add(1)
    go gtpPacketListener(upfConn3, logger)
    wg.Add(1)
    go icmpTrafficGenerator3(1, "60.60.0.1", upfConn3, logger)
    wg.Add(1)
    go udpTrafficGenerator3(1, "60.60.0.1", upfConn3, logger)*/
    //}

    wg.Wait()
    logger.Println("Transmission Finished")

}

func errLog(err error, logger *log.Logger) {
    if err != nil {
        logger.Println(err)
    }
}

func recvICMP(conn *net.UDPConn, recv chan<- time.Time, logger *log.Logger) {
    defer wg.Done()
    data := make([]byte, 1024)
    for {
        _, _, err := conn.ReadFrom(data)
        errLog(err, logger)
        t := time.Now()
        recv <- t
    }
}

func gtpPacketListener(conn *net.UDPConn, logger *log.Logger) {
    defer wg.Done()
    recv := make([]byte, 1024)
    var total_time float64 = 0
    count := 0
    for {
        len, _, err := conn.ReadFrom(recv)
        errLog(err, logger)
        if len != 0 {
            recvTime := time.Now().UnixNano()

            // icmpData
            icmpData := recv[36:44]
            sendTime := BytesToInt64(icmpData)

            respTime := float64(recvTime-sendTime) / 1000000
            count++
            //total_time += respTime
            if respTime > 0 && count > 15 {
                total_time += respTime
                logger.Printf("%d  time=%.2f ms, avg=%.2f", count, respTime, total_time/float64(count-15))
            }

        }
    }
}

func icmpTrafficGenerator(teid uint32, ip string, conn *net.UDPConn, logger *log.Logger) {
    //var t_rep int64
    //t_rep = 0
    // Create ICMP payload

    // gtp packet read buffer
    //data := make([]byte, 1024)

    //icmp_start_t := time.Now()
    for i := 0; i < 4000; i++ {
        // Create GTP header
        gtpHdr, err := BuildGTPHeader(teid, uint16(i))
	//gtpHdr, err := hex.DecodeString("32ff00340000000100000000")
        errLog(err, logger)

        // Create ICMP data payload
        icmpData := Int64ToBytes(time.Now().UnixNano())
        //icmpData, err := hex.DecodeString("1234567890") //8c870d0000000000101112131415161718191a1b
        //errLog(err, logger)
        packetLen := 28 + len(icmpData)

        // Create IPv4 header
        ipv4hdr := ipv4.Header{
            Version:  4,
            Len:      20,
            Protocol: 1,
            Flags:    0,
            TotalLen: packetLen,
            TTL:      64,
            Src:      net.ParseIP(ip).To4(),
            Dst:      net.ParseIP(dNServer1).To4(),
            ID:       1,
            Checksum: 0,
        }
        v4HdrBuf, err := ipv4hdr.Marshal()
        ipv4hdr.Checksum = int(CheckSum(v4HdrBuf))

        v4HdrBuf, err = ipv4hdr.Marshal()

        // Create ICMP payload
        m := icmp.Message{
            Type: ipv4.ICMPTypeEcho, Code: 0,
            Body: &icmp.Echo{
                ID: 0, Seq: i,
                Data: icmpData,
            },
        }

        tt := append(gtpHdr, v4HdrBuf...)
        b, err := m.Marshal(nil)

        conn.Write(append(tt, b...))

        time.Sleep(500 * time.Millisecond)
    }
    log.Println("icmp finished")

    wg.Done()
}

func Int64ToBytes(i int64) []byte {
    var buf = make([]byte, 8)
    binary.BigEndian.PutUint64(buf, uint64(i))
    return buf
}

func BytesToInt64(buf []byte) int64 {
    return int64(binary.BigEndian.Uint64(buf))
}

func IntToBytes(n int) []byte {
    data := int16(n)
    bytebuf := bytes.NewBuffer([]byte{})
    binary.Write(bytebuf, binary.BigEndian, data)
    return bytebuf.Bytes()
}

func udpTrafficGenerator(teid uint32, ip string, conn *net.UDPConn, logger *log.Logger) {

    buff := make([]byte, 1028)
    ip_addr_src, _, _ := net.ParseCIDR(ip + "/24")
    src := ip_addr_src
    dst := net.IPv4(dNServerI[0], dNServerI[1], dNServerI[2], dNServerI[3])

    ipv4hdr := ipv4.Header{
        Version:  ipv4.Version,
        Len:      ipv4.HeaderLen,
        Protocol: 17,
        Flags:    ipv4.DontFragment,
        TotalLen: ipv4.HeaderLen + len(buff),
        TOS:      0x00,
        FragOff:  0,
        TTL:      64,
        Src:      net.ParseIP(ip).To4(),
        Dst:      net.ParseIP(dNServer1).To4(),
        Checksum: 0,
    }
    v4HdrBuf, err := ipv4hdr.Marshal()
    errLog(err, logger)
    ipv4hdr.Checksum = int(CheckSum(v4HdrBuf))

    //填充udp首部
    //udp伪首部
    udph := make([]byte, 20)
    //源ip地址
    udph[0], udph[1], udph[2], udph[3] = src[12], src[13], src[14], src[15]
    //目的ip地址
    udph[4], udph[5], udph[6], udph[7] = dst[12], dst[13], dst[14], dst[15]
    //协议类型
    udph[8], udph[9] = 0x00, 0x11
    //udp头长度
    udph[10], udph[11] = IntToBytes(len(buff))[0], IntToBytes(len(buff))[1]
    //下面开始就真正的udp头部
    //源端口号
    udph[12], udph[13] = 0x27, 0x10
    //目的端口号
    udph[14], udph[15] = 0x17, 0x70
    //udp头长度
    udph[16], udph[17] = IntToBytes(len(buff))[0], IntToBytes(len(buff))[1]
    //校验和
    udph[18], udph[19] = 0x00, 0x00
    //计算校验值
    check := CheckSum(append(udph, buff...))
    udph[18], udph[19] = byte(check>>8&255), byte(check&255)

    // wait 1s
    time.Sleep(1 * time.Second)
    i := 0
    traffic := (udpPacketCount*1024)/(1024*1024)*8 // Mbp
    for i < totalUdpPacket {
        j := 0
        startTime := time.Now()
        for j < udpPacketCount {
            // Create GTP header
            //gtpHdr, err := BuildGTPHeader(teid, uint16(i))
            //errLog(err, logger)
            gtpHdr, err := hex.DecodeString("32ff00340000000100000000")
	    errLog(err, logger)
            v4HdrBuf, err = ipv4hdr.Marshal()
            udp := append(udph[12:20], buff[:]...)
            UDP := append(v4HdrBuf, udp...)

            //gtpHdr, err := BuildGTPHeader(1)
            tt := append(gtpHdr, UDP...)

            _, err = conn.Write(tt)
           errLog(err, logger)

           time.Sleep(udpInterval)
           i++
           j++
        }
        endTime := time.Now()
        duration := endTime.Sub(startTime)
        durationSec := float64(duration) / 1000000000
        fmt.Printf("%f Mbps\n", float64(traffic)/durationSec)
    }
    fmt.Println("UDP END")
}

