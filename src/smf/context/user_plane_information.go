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

	fmt.Printf("now in the GetDefaultUserPlanePathByDNN\n\n")
	fmt.Printf("path now is %v\n",path)
	pathExist = false
	fmt.Printf("pathExist is %v\n",pathExist)

	if pathExist {
		return
	} else {
		pathExist = upi.GenerateDefaultPath(dnn)
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
	var lowerBound = 0
	var upperBound = len(upPath) - 1
	var root *DataPathNode
	var curDataPathNode *DataPathNode
	var prevDataPathNode *DataPathNode

	for idx, upNode := range upPath {
		curDataPathNode = NewDataPathNode()
		curDataPathNode.UPF = upNode.UPF

		if idx == lowerBound {
			root = curDataPathNode
			root.AddPrev(nil)
		}
		if idx == upperBound {
			curDataPathNode.AddNext(nil)
		}
		if prevDataPathNode != nil {
			prevDataPathNode.AddNext(curDataPathNode)
			curDataPathNode.AddPrev(prevDataPathNode)
		}
		prevDataPathNode = curDataPathNode
	}

	dataPath := &DataPath{
		Destination: Destination{
			DestinationIP:   "",
			DestinationPort: "",
			Url:             "",
		},
		FirstDPNode: root,
	}
	return dataPath
}

func (upi *UserPlaneInformation) GenerateDefaultPath(dnn string) bool {

	fmt.Printf("now in the GenerateDefaultPath\n\n")
	var source *UPNode
	var destination *UPNode

	check1 := 1
	for _, node := range upi.AccessNetwork {

		fmt.Printf("node.Type is %v\n",node.Type)
		fmt.Printf("UPNODE_AN is %v\n",UPNODE_AN)
		fmt.Printf("node is %v\n",node)
		if check1 == 1 {
			if node.Type == UPNODE_AN1 {
				source = node
				break
			}
		} else if check1 ==2 {
			if node.Type == UPNODE_AN2 {
				source = node
				break
			}
		} else {
			if node.Type == UPNODE_AN3 {
				source = node
				break
			}
		}
		check1 +=1
	}

	fmt.Printf("source is %v\n\n",source)

	if source == nil {
		logger.CtxLog.Errorf("There is no AN Node in config file!")
		return false
	}

	for _, node := range upi.UPFs {
		fmt.Printf("node is %v\n",node)

		check2 :=1
		if node.UPF.UPIPInfo.NetworkInstance != nil {
			node_dnn := string(node.UPF.UPIPInfo.NetworkInstance)
			fmt.Printf("node_dnn is %v\n",node_dnn)
			fmt.Printf("dnn is %v\n",dnn)
			if check2 == 1 {
				if node.Type == UPNODE_UPF1 {
					destination = node
					break
				}
			} else if check2 ==2 {
				if node.Type == UPNODE_UPF2 {
					destination = node
					break
				}
			} else {
				if node.Type == UPNODE_UPF3 {
					destination = node
					break
				}
			}
		}
	}

	fmt.Printf("destination is %v\n",destination)

	if destination == nil {
		logger.CtxLog.Errorf("Can't find UPF with DNN [%s]\n", dnn)
		return false
	}

	//Run DFS
	visited := make(map[*UPNode]bool)

	for _, upNode := range upi.UPNodes {
		visited[upNode] = false
	}

	path, pathExist := getPathBetween(source, destination, visited)

	fmt.Printf("path[0].Type is %v\n\n",path[0].Type)
	fmt.Printf("UPNODE_AN is %v\n\n",UPNODE_AN)
	if path[0].Type == UPNODE_AN {
		path = path[1:]
	}
	upi.DefaultUserPlanePath[dnn] = path
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
