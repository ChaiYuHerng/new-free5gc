package context

import (
	"free5gc/lib/pfcp/pfcpType"
	"free5gc/src/smf/factory"
	"free5gc/src/smf/logger"
	"net"
	"fmt"
	"reflect"
)

// UserPlaneInformation store userplane topology
type UserPlaneInformation struct {
	UPNodes              map[string]*UPNode
	UPFs                 map[string]*UPNode
	AccessNetwork        map[string]*UPNode
	UPFIPToName          map[string]string
	UPFsID               map[string]string    // name to id
	UPFsIPtoID           map[string]string    // ip->id table, for speed optimization
	DefaultUserPlanePath map[string][]*UPNode // DNN to Default Path
}

type UPNodeType string

const (
	UPNODE_UPF UPNodeType = "UPF"
	UPNODE_UPF1 UPNodeType = "UPF1"
	UPNODE_UPF2 UPNodeType = "UPF2"
	UPNODE_UPF3 UPNodeType = "UPF3"
	UPNODE_UPF4 UPNodeType = "UPF4"
	UPNODE_UPF5 UPNodeType = "UPF5"
	UPNODE_UPF6 UPNodeType = "UPF6"
	UPNODE_AN  UPNodeType = "AN"
	UPNODE_AN1  UPNodeType = "AN1"
	UPNODE_AN2  UPNodeType = "AN2"
	UPNODE_AN3  UPNodeType = "AN3"
)

// UPNode represent the user plane node topology
type UPNode struct {
	Type   UPNodeType
	NodeID pfcpType.NodeID
	ANIP   net.IP
	Dnn    string
	Links  []*UPNode
	UPF    *UPF
}

// UPPath represent User Plane Sequence of this path
type UPPath []*UPNode

func AllocateUPFID() {
	UPFsID := smfContext.UserPlaneInformation.UPFsID
	UPFsIPtoID := smfContext.UserPlaneInformation.UPFsIPtoID

	for upfName, upfNode := range smfContext.UserPlaneInformation.UPFs {
		upfid := upfNode.UPF.UUID()
		upfip := upfNode.NodeID.ResolveNodeIdToIp().String()

		UPFsID[upfName] = upfid
		UPFsIPtoID[upfip] = upfid
	}
}

// NewUserPlaneInformation process the configuration then returns a new instance of UserPlaneInformation
func NewUserPlaneInformation(upTopology *factory.UserPlaneInformation) *UserPlaneInformation {
	fmt.Printf("now in the NewUserPlaneInformation\n\n")
	nodePool := make(map[string]*UPNode)
	upfPool := make(map[string]*UPNode)
	anPool := make(map[string]*UPNode)
	upfIPMap := make(map[string]string)

	//fmt.Printf("1.upfPool is %v\n",upfPool)
	//fmt.Printf("1.nodePool is %v\n",nodePool)

	for name, node := range upTopology.UPNodes {
		upNode := new(UPNode)
		upNode.Type = UPNodeType(node.Type)
		fmt.Printf("upNode is %v\n",upNode)
		fmt.Printf("upNode.Type is %v\n",upNode.Type)
		switch upNode.Type {
		case UPNODE_AN:
			fmt.Printf("now is the case UPNODE_AN\n\n")
			upNode.ANIP = net.ParseIP(node.ANIP)
			anPool[name] = upNode
		case UPNODE_AN1:
			fmt.Printf("now is the case UPNODE_AN1\n\n")
			upNode.ANIP = net.ParseIP(node.ANIP)
			anPool[name] = upNode
		case UPNODE_AN2:
			fmt.Printf("now is the case UPNODE_AN2\n\n")
			upNode.ANIP = net.ParseIP(node.ANIP)
			anPool[name] = upNode
		case UPNODE_AN3:
			fmt.Printf("now is the case UPNODE_AN3\n\n")
			upNode.ANIP = net.ParseIP(node.ANIP)
			anPool[name] = upNode
		case UPNODE_UPF:
			//ParseIp() always return 16 bytes
			//so we can't use the length of return ip to seperate IPv4 and IPv6
			//This is just a work around
			var ip net.IP
			if net.ParseIP(node.NodeID).To4() == nil {
				ip = net.ParseIP(node.NodeID)
			} else {
				ip = net.ParseIP(node.NodeID).To4()
			}

			switch len(ip) {
			case net.IPv4len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeIpv4Address,
					NodeIdValue: ip,
				}
			case net.IPv6len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeIpv6Address,
					NodeIdValue: ip,
				}
			default:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeFqdn,
					NodeIdValue: []byte(node.NodeID),
				}
			}

			upfPool[name] = upNode
		case UPNODE_UPF1:
			//ParseIp() always return 16 bytes
			//so we can't use the length of return ip to seperate IPv4 and IPv6
			//This is just a work around
			var ip net.IP
			if net.ParseIP(node.NodeID).To4() == nil {
				ip = net.ParseIP(node.NodeID)
			} else {
				ip = net.ParseIP(node.NodeID).To4()
			}
			fmt.Printf("ip is %v\n",ip)

			switch len(ip) {
			case net.IPv4len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeIpv4Address,
					NodeIdValue: ip,
				}
			case net.IPv6len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeIpv6Address,
					NodeIdValue: ip,
				}
			default:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeFqdn,
					NodeIdValue: []byte(node.NodeID),
				}
			}

			upfPool[name] = upNode
		case UPNODE_UPF2:
			//ParseIp() always return 16 bytes
			//so we can't use the length of return ip to seperate IPv4 and IPv6
			//This is just a work around
			var ip net.IP
			if net.ParseIP(node.NodeID).To4() == nil {
				ip = net.ParseIP(node.NodeID)
			} else {
				ip = net.ParseIP(node.NodeID).To4()
			}
			fmt.Printf("ip is %v\n",ip)

			switch len(ip) {
			case net.IPv4len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeIpv4Address,
					NodeIdValue: ip,
				}
			case net.IPv6len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeIpv6Address,
					NodeIdValue: ip,
				}
			default:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeFqdn,
					NodeIdValue: []byte(node.NodeID),
				}
			}

			upfPool[name] = upNode
		case UPNODE_UPF3:
			//ParseIp() always return 16 bytes
			//so we can't use the length of return ip to seperate IPv4 and IPv6
			//This is just a work around
			var ip net.IP
			if net.ParseIP(node.NodeID).To4() == nil {
				ip = net.ParseIP(node.NodeID)
			} else {
				ip = net.ParseIP(node.NodeID).To4()
			}
			fmt.Printf("ip is %v\n",ip)

			switch len(ip) {
			case net.IPv4len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeIpv4Address,
					NodeIdValue: ip,
				}
			case net.IPv6len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeIpv6Address,
					NodeIdValue: ip,
				}
			default:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeFqdn,
					NodeIdValue: []byte(node.NodeID),
				}
			}

			upfPool[name] = upNode
		case UPNODE_UPF4:
			//ParseIp() always return 16 bytes
			//so we can't use the length of return ip to seperate IPv4 and IPv6
			//This is just a work around
			var ip net.IP
			if net.ParseIP(node.NodeID).To4() == nil {
				ip = net.ParseIP(node.NodeID)
			} else {
				ip = net.ParseIP(node.NodeID).To4()
			}

			switch len(ip) {
			case net.IPv4len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeIpv4Address,
					NodeIdValue: ip,
				}
			case net.IPv6len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeIpv6Address,
					NodeIdValue: ip,
				}
			default:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeFqdn,
					NodeIdValue: []byte(node.NodeID),
				}
			}

			upfPool[name] = upNode
		case UPNODE_UPF5:
			//ParseIp() always return 16 bytes
			//so we can't use the length of return ip to seperate IPv4 and IPv6
			//This is just a work around
			var ip net.IP
			if net.ParseIP(node.NodeID).To4() == nil {
				ip = net.ParseIP(node.NodeID)
			} else {
				ip = net.ParseIP(node.NodeID).To4()
			}

			switch len(ip) {
			case net.IPv4len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeIpv4Address,
					NodeIdValue: ip,
				}
			case net.IPv6len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeIpv6Address,
					NodeIdValue: ip,
				}
			default:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeFqdn,
					NodeIdValue: []byte(node.NodeID),
				}
			}

			upfPool[name] = upNode
		case UPNODE_UPF6:
			//ParseIp() always return 16 bytes
			//so we can't use the length of return ip to seperate IPv4 and IPv6
			//This is just a work around
			var ip net.IP
			if net.ParseIP(node.NodeID).To4() == nil {
				ip = net.ParseIP(node.NodeID)
			} else {
				ip = net.ParseIP(node.NodeID).To4()
			}

			switch len(ip) {
			case net.IPv4len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeIpv4Address,
					NodeIdValue: ip,
				}
			case net.IPv6len:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeIpv6Address,
					NodeIdValue: ip,
				}
			default:
				upNode.NodeID = pfcpType.NodeID{
					NodeIdType:  pfcpType.NodeIdTypeFqdn,
					NodeIdValue: []byte(node.NodeID),
				}
			}

			upfPool[name] = upNode
		default:
			logger.InitLog.Warningf("invalid UPNodeType: %s\n", upNode.Type)
		}

		nodePool[name] = upNode

		ipStr := upNode.NodeID.ResolveNodeIdToIp().String()
		upfIPMap[ipStr] = name
	}

	for _, link := range upTopology.Links {
		nodeA := nodePool[link.A]
		nodeB := nodePool[link.B]
		if nodeA == nil || nodeB == nil {
			logger.InitLog.Warningf("UPLink [%s] <=> [%s] not establish\n", link.A, link.B)
			continue
		}
		nodeA.Links = append(nodeA.Links, nodeB)
		nodeB.Links = append(nodeB.Links, nodeA)
	}

	//Initialize each UPF
	for _, upfNode := range upfPool {
		upfNode.UPF = NewUPF(&upfNode.NodeID)
	}

	userplaneInformation := &UserPlaneInformation{
		UPNodes:              nodePool,
		UPFs:                 upfPool,
		AccessNetwork:        anPool,
		UPFIPToName:          upfIPMap,
		UPFsID:               make(map[string]string),
		UPFsIPtoID:           make(map[string]string),
		DefaultUserPlanePath: make(map[string][]*UPNode),
	}

	//fmt.Printf("2.upfPool is %v\n",upfPool)
	//fmt.Printf("2.nodePool is %v\n",nodePool)

	return userplaneInformation
}

func (upi *UserPlaneInformation) GetUPFNameByIp(ip string) string {

	return upi.UPFIPToName[ip]
}

func (upi *UserPlaneInformation) GetUPFNodeIDByName(name string) pfcpType.NodeID {

	return upi.UPFs[name].NodeID
}

func (upi *UserPlaneInformation) GetUPFNodeByIP(ip string) *UPNode {
	upfName := upi.GetUPFNameByIp(ip)
	return upi.UPFs[upfName]
}

func (upi *UserPlaneInformation) GetUPFIDByIP(ip string) string {

	return upi.UPFsIPtoID[ip]
}

func (upi *UserPlaneInformation) GetDefaultUserPlanePathByDNN(dnn string) (path UPPath) {
	path, pathExist := upi.DefaultUserPlanePath[dnn]

	fmt.Printf("now in the GetDefaultUserPlanePathByDNN,dnn is %v\n\n",dnn)
	fmt.Printf("path now is %v\n",path)
	//pathExist = false
	fmt.Printf("pathExist is %v\n",pathExist)

	if pathExist {
		return
	} else {
		pathExist = upi.GenerateDefaultPath(dnn)
		fmt.Printf("pathExist is %v\n",pathExist)
		if pathExist {
			return upi.DefaultUserPlanePath[dnn]
		}
	}
	return nil
}

func (upi *UserPlaneInformation) ExistDefaultPath(dnn string) bool {

	_, exist := upi.DefaultUserPlanePath[dnn]
	return exist
}

func GenerateDataPath(upPath UPPath, smContext *SMContext) *DataPath {
	if len(upPath) < 1 {
		logger.CtxLog.Errorf("Invalid data path")
		return nil
	}
	fmt.Printf("now in the GenerateDataPath function\n\n")
	fmt.Printf("len(upPath) is %v\n",len(upPath))
	var lowerBound = 0
	var upperBound = len(upPath) - 1
	var root *DataPathNode
	var curDataPathNode *DataPathNode
	var prevDataPathNode *DataPathNode
	var tmp_dest string

	for idx, upNode := range upPath {
		fmt.Printf("upNode is %v\n",upNode)
		if upNode.Type == UPNODE_UPF1 {
			tmp_dest = "192.168.2.111"
		} else if upNode.Type == UPNODE_UPF2 {
			tmp_dest = "192.168.2.112"
		} else if upNode.Type == UPNODE_UPF3 {
			tmp_dest = "192.168.2.113"
		}
		fmt.Printf("tmp_dest is %v\n",tmp_dest)
		curDataPathNode = NewDataPathNode()
		curDataPathNode.UPF = upNode.UPF
		fmt.Printf("curDataPathNode is %v\n",curDataPathNode)
		fmt.Printf("Current DP Node IP is %v\n",curDataPathNode.UPF.NodeID)

		if idx == lowerBound {
			fmt.Printf("idx == lowerBound\n")
			root = curDataPathNode
			root.AddPrev(nil)
		}
		if idx == upperBound {
			fmt.Printf("idx == upperBound\n")
			curDataPathNode.AddNext(nil)
		}
		if prevDataPathNode != nil {
			fmt.Printf("prevDataPathNode != nil\n")
			prevDataPathNode.AddNext(curDataPathNode)
			curDataPathNode.AddPrev(prevDataPathNode)
		}
		prevDataPathNode = curDataPathNode
	}

	dataPath := &DataPath{
		Activated: true,
		IsDefaultPath: true,
		Destination: Destination{
			DestinationIP:   tmp_dest,
			//DestinationIP:   "",
			DestinationPort: "",
			Url:             "",
		},
		HasBranchingPoint: false,
		FirstDPNode: root,
	}
	fmt.Printf("root after GenerateDataPath is %v\n",root)
	fmt.Printf("root.UPF after GenerateDataPath is %v\n",root.UPF)
	fmt.Printf("root.UpLinkTunnel.TEID after GenerateDataPath is %v\n",root.UpLinkTunnel.TEID)
	fmt.Printf("root.DownLinkTunnel.TEID after GenerateDataPath is %v\n",root.DownLinkTunnel.TEID)
	fmt.Printf("dataPath after GenerateDataPath is %v\n",dataPath)
	return dataPath
}

func (upi *UserPlaneInformation) GenerateDefaultPath(dnn string) bool {

	fmt.Printf("now in the GenerateDefaultPath\n\n")
	fmt.Printf("dnn is %v\n",dnn)
	var source1 *UPNode
	var destination1 *UPNode
	var source2 *UPNode
	var destination2 *UPNode
	var source3 *UPNode
	var destination3 *UPNode
	var source *UPNode
	var destination *UPNode

	check1 :=0
	for _, node := range upi.AccessNetwork {

		fmt.Printf("node.Type is %v\n",node.Type)
		fmt.Printf("UPNODE_AN is %v\n",UPNODE_AN)
		fmt.Printf("node is %v\n",node)
		/*if node.Type == UPNODE_AN {
			source = node
			break
		}*/
		if node.Type == UPNODE_AN {
			source = node
			check1 = 1
			break
		} else if node.Type == UPNODE_AN1 {
			source1 = node
		} else if node.Type == UPNODE_AN2 {
			source2 = node
		} else if node.Type == UPNODE_AN3 {
			source3 = node
		}
	}

	if check1 ==0 {
		fmt.Printf("source1 is %v\n\n",source1)
		fmt.Printf("source2 is %v\n\n",source2)
		fmt.Printf("source3 is %v\n\n",source3)
		if dnn == "internet" {
			source = source1
		} else if dnn == "internet2" {
			source = source2
		} else {
			source = source3
		}
	}
	fmt.Printf("source is %s\n",source)
	

	if source == nil {
		logger.CtxLog.Errorf("There is no AN Node in config file!")
		return false
	}


	check2 :=0
	for _, node := range upi.UPFs {
		fmt.Printf("node is %v\n",node)
		fmt.Printf("node.Type is %v\n",node.Type)

		/*if node.UPF.UPIPInfo.NetworkInstance != nil {
			node_dnn := string(node.UPF.UPIPInfo.NetworkInstance)
			if node_dnn == dnn {
				destination = node
				break
			}
		}*/

		if node.UPF.UPIPInfo.NetworkInstance != nil {
			node_dnn := string(node.UPF.UPIPInfo.NetworkInstance)
			fmt.Printf("node_dnn is %v\n",node_dnn)
			fmt.Printf("dnn is %v\n",dnn)
			if node.Type == UPNODE_UPF {
				destination = node
				check2 =1
				break
			} else if node.Type == UPNODE_UPF1 {
				destination1 = node
			} else if node.Type == UPNODE_UPF2 {
				destination2 = node
			} else if node.Type == UPNODE_UPF3 {
				destination3 = node
			}
		}
	}

	if check2 ==0 {
		fmt.Printf("destination1 is %v\n",destination1)
		fmt.Printf("destination2 is %v\n",destination2)
		fmt.Printf("destination3 is %v\n",destination3)
		
		if dnn == "internet" {
			destination = destination1
		} else if dnn == "internet2" {
			destination = destination2
		} else {
			destination = destination3
		}
	}
	fmt.Printf("destination is %s\n",destination)
	

	if destination == nil {
		logger.CtxLog.Errorf("Can't find UPF with DNN [%s]\n", dnn)
		return false
	}

	fmt.Printf("source is %v\n, destination is %v\n\n",source,destination)
	fmt.Printf("start run DFS\n")

	//Run DFS
	visited := make(map[*UPNode]bool)

	for _, upNode := range upi.UPNodes {
		visited[upNode] = false
	}

	path, pathExist := getPathBetween(source, destination, visited)



	//fmt.Printf("path[0].Type is %v\n\n",path[0].Type)
	//fmt.Printf("UPNODE_AN is %v\n\n",UPNODE_AN)
	/*if path[0].Type == UPNODE_AN {
		path = path[1:]
	}*/
	path = path[1:]
	upi.DefaultUserPlanePath[dnn] = path
	fmt.Printf("path is %s\n",path)
	return pathExist
}

func getPathBetween(cur *UPNode, dest *UPNode, visited map[*UPNode]bool) (path []*UPNode, pathExist bool) {

	visited[cur] = true

	if reflect.DeepEqual(*cur, *dest) {

		path = make([]*UPNode, 0)
		path = append(path, cur)
		pathExist = true
		return
	}

	for _, nodes := range cur.Links {

		if !visited[nodes] {
			path_tail, path_exist := getPathBetween(nodes, dest, visited)

			if path_exist {
				path = make([]*UPNode, 0)
				path = append(path, cur)

				path = append(path, path_tail...)
				pathExist = true

				return
			}
		}
	}

	return nil, false

}