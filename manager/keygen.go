package manager

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	tmjson "github.com/tendermint/tendermint/libs/json"
	tmtypes "github.com/tendermint/tendermint/rpc/jsonrpc/types"

	"github.com/ethereum/go-ethereum/log"

	tss "github.com/eniac-x-labs/tss/common"
	"github.com/eniac-x-labs/tss/manager/types"
	"github.com/eniac-x-labs/tss/ws/server"
)

/*
每隔固定时间（taskInterval + 30s），尝试一次 election 处理。

如果 stopGenKey = false：

查询是否有新的 inactive 成员。

如果有，检查本轮 election 是否已有未确认的 CPK。

如果没有或者过期，就生成新的 CPK 并存储。

支持随时通过 m.stopChan 停止。
*/

func (m *Manager) observeElection() {

	queryTicker := time.NewTicker(m.taskInterval + 30*time.Second)
	for {
		log.Info("trying to handle new election...", "stopGenKey", m.stopGenKey)
		if !m.stopGenKey {
			func() {
				// check if new round election is held(inactive tss members)
				tssInfo, err := m.tssQueryService.QueryInactiveInfo()
				if err != nil {
					log.Error("failed to query inactive info", "err", err)
					return
				}
				log.Info("query inactive members", "numbers", len(tssInfo.TssMembers))

				// tssMembers, threshold, electionId := getInactiveMembers()
				if len(tssInfo.TssMembers) > 0 {

					// the CPK has not been confirmed in the latest election
					// start to generate CPK
					cpkData, err := m.store.GetByElectionId(tssInfo.ElectionId) // 查询数据库（或存储层），看看这一轮 ElectionId 是否已经有对应的 CPK 数据
					if err != nil {
						log.Error("failed to get cpk from storage", "err", err)
						return
					}

					if len(cpkData.Cpk) != 0 && time.Now().Sub(cpkData.CreationTime).Hours() < m.cpkConfirmTimeout.Hours() { // cpk is generated, but has not been confirmed yet
						return
					}
					cpk, err := m.generateKey(tssInfo.TssMembers, tssInfo.Threshold, tssInfo.ElectionId)
					if err != nil {
						log.Error("failed to generate key", "err", err)
						return
					}

					if err = m.store.Insert(types.CpkData{
						Cpk:          cpk,
						ElectionId:   tssInfo.ElectionId,
						CreationTime: time.Now(),
					}); err != nil {
						log.Error("failed to get cpk from storage", "err", err)
					}
				}
			}()
		}

		select {
		case <-m.stopChan:
			return
		case <-queryTicker.C:
		}
	}
}

/*
generateKey：

向一组可用节点（availableNodes）发起 门限密钥生成（Keygen）请求。

收集这些节点返回的 Cluster Public Key (CPK)。

确认所有节点生成的 CPK 一致后，返回这个 CPK。

如果过程中有错误、超时、不一致，就报错。
*/

func (m *Manager) generateKey(tssMembers []string, threshold int, electionId uint64) (string, error) {

	// 获取实际可用的节点列表，如果可用节点数少于需要的成员数，直接报错（说明缺员，没法生成）
	availableNodes := m.availableNodes(tssMembers)
	if len(availableNodes) < len(tssMembers) {
		return "", errors.New("not enough available nodes to generate CPK")
	}
	requestId := randomRequestId()            // 生成一个唯一的 requestId（用来标识本次 Keygen 请求）
	respChan := make(chan server.ResponseMsg) // 节点的响应会被投递到这里
	stopChan := make(chan struct{})           // 用于关闭监听
	if err := m.wsServer.RegisterResChannel(requestId, respChan, stopChan); err != nil {
		log.Error("failed to register response channel", "err", err)
		return "", err
	} // 向 wsServer 注册响应通道：意思是说，凡是带 requestId 的返回结果都塞进 respChan

	sendError := make(chan struct{})                // sendError：如果消息发送失败，会触发
	clusterPublicKeys := make(map[string]string, 0) // clusterPublicKeys：存放每个节点返回的 CPK
	var anyError error                              // anyError：存放错误信息
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		cctx, cancel := context.WithTimeout(context.Background(), m.keygenTimeout)
		defer func() {
			log.Info("exit accept keygen response goroutine")
			cancel()
			close(stopChan)
			wg.Done()
		}()
		for {
			select {
			case <-sendError:
				anyError = errors.New("failed to send request to node")
				log.Error("failed to send request to node")
				return
			case <-cctx.Done():
				anyError = errors.New("wait nodes for keygen response timeout")
				log.Error("wait nodes for keygen response timeout")
				return
			case resp := <-respChan:
				log.Info("received keygen response", "response", resp.RpcResponse.String(), "node", resp.SourceNode)
				if resp.RpcResponse.Error != nil {
					anyError = errors.New(resp.RpcResponse.Error.Error())
					log.Error("returns error", "node", resp.SourceNode)
					return // 如果返回 error，记录并退出
				}
				var keygenResp tss.KeygenResponse
				if err := tmjson.Unmarshal(resp.RpcResponse.Result, &keygenResp); err != nil { // 否则反序列化结果，提取 ClusterPublicKey
					anyError = err
					log.Error("failed to Unmarshal KeygenResponse", "err", err)
					return
				}
				clusterPublicKeys[resp.SourceNode] = keygenResp.ClusterPublicKey
			default:
				if len(clusterPublicKeys) == len(availableNodes) { // 全部响应收齐：收集到的 key 数量等于可用节点数
					return
				}
			}
		}
	}()

	m.callKeygen(availableNodes, threshold, electionId, requestId, sendError) // 广播 Keygen 请求到所有节点
	wg.Wait()

	if anyError != nil {
		return "", anyError
	}

	// check if existing different CPKs
	var base string
	for _, cpk := range clusterPublicKeys {
		if len(base) == 0 {
			base = cpk
			continue
		}
		if cpk != base {
			return "", errors.New("found different CPKs generated from tss members")
		}
	}

	if len(clusterPublicKeys) != len(availableNodes) {
		return "", errors.New("timeout")
	}
	return base, nil
}

/*
callKeygen：

向每个节点广播一个 Keygen 请求（异步并发发送）。

这是 典型的 TSS / MPC 集体密钥生成流程：所有节点共同运行协议 → 返回同一个集体公钥
*/

func (m *Manager) callKeygen(availableNodes []string, threshold int, electionId uint64, requestId string, sendError chan struct{}) {
	for _, node := range availableNodes { // 遍历每个节点，构造一个 KeygenRequest：包括节点集合、阈值、选举 ID、时间戳
		nodeRequest := tss.KeygenRequest{
			Nodes:      availableNodes,
			Threshold:  threshold,
			ElectionId: electionId,
			Timestamp:  time.Now().UnixMilli(),
		}

		// 序列化后，异步发送到节点
		requestBz, _ := json.Marshal(nodeRequest)
		go func(node string, requestBz []byte) {
			requestMsg := server.RequestMsg{
				TargetNode: node,
				RpcRequest: tmtypes.NewRPCRequest(tmtypes.JSONRPCStringID(requestId), "keygen", requestBz),
			}
			if err := m.wsServer.SendMsg(requestMsg); err != nil {
				sendError <- struct{}{}
			}
		}(node, requestBz)
	}
}
