package router

import (
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"

	tss "github.com/eniac-x-labs/tss/common"
	"github.com/eniac-x-labs/tss/manager/types"
)

type Registry struct {
	signService  types.SignService
	adminService types.AdminService
}

func NewRegistry(signService types.SignService, adminService types.AdminService) *Registry {
	return &Registry{
		signService:  signService,
		adminService: adminService,
	}
}

func (registry *Registry) SignStateHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var request tss.TransactionSignRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, errors.New("invalid request body"))
			return
		}
		if request.MessageHash == "" {
			c.JSON(http.StatusBadRequest, errors.New("StartBlock and OffsetStartsAtIndex must not be nil or negative"))
			return
		}
		signature, err := registry.signService.TransactionSign(request)
		if err != nil {
			c.String(http.StatusInternalServerError, "failed to sign state")
			log.Error("failed to sign state", "error", err)
			return
		}
		if _, err = c.Writer.Write(signature); err != nil {
			log.Error("failed to write signature to response writer", "error", err)
		}
	}
}

func (registry *Registry) SignEIP7702Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var request tss.EIP7702SignRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, errors.New("invaild request body"))
			return
		}
		if request.ChainId == "" {
			c.JSON(http.StatusBadRequest, errors.New("parameter input wrong"))
			return
		}
		if request.Address == "" {
			c.JSON(http.StatusBadRequest, errors.New("parameter input wrong"))
			return
		}
		chainIDStr := request.ChainId
		addrHex := request.Address
		chainID, ok := new(big.Int).SetString(strip0x(chainIDStr), detectBase(chainIDStr))
		if !ok {
			c.JSON(http.StatusBadRequest, errors.New("process chainId failed"))
			return
		}
		addr := common.HexToAddress(addrHex)

		// RLP([chain_id, address, nonce])
		tuple := struct {
			ChainID *big.Int
			Address common.Address
			Nonce   uint64
		}{
			ChainID: chainID,
			Address: addr,
			Nonce:   request.Nonce,
		}

		rlpBytes, err := rlp.EncodeToBytes(tuple)
		if err != nil {
			c.JSON(http.StatusBadRequest, errors.New("rlp process chainId failed"))
			return
		}

		// MAGIC prefix 0x05
		payload := append([]byte{0x05}, rlpBytes...)

		hash := crypto.Keccak256(payload)
		messsageHash := "0x" + hex.EncodeToString(hash)

		var signRequest tss.TransactionSignRequest
		signRequest.MessageHash = messsageHash
		signRequest.ElectionId = request.ElectionId

		signature, err := registry.signService.TransactionSign(signRequest)
		if err != nil {
			c.String(http.StatusInternalServerError, "failed to sign state")
			log.Error("failed to sign state", "error", err)
			return
		}
		if _, err = c.Writer.Write(signature); err != nil {
			log.Error("failed to write signature to response writer", "error", err)
		}
	}
}

func (registry *Registry) ResetHeightHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		heightStr := c.PostForm("height")
		height, err := strconv.Atoi(heightStr)
		if err != nil {
			c.String(http.StatusInternalServerError, "wrong height format")
			log.Error("failed to reset height", "error", err)
			return
		}
		err = registry.adminService.ResetScanHeight(uint64(height))
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			log.Error("failed to reset height", "error", err)
			return
		}
	}
}

func (registry *Registry) GetHeightHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		height, err := registry.adminService.GetScannedHeight()
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			log.Error("failed to get height", "error", err)
			return
		}
		c.String(http.StatusOK, strconv.FormatUint(height, 10))
	}
}

func (registry *Registry) PrometheusHandler() gin.HandlerFunc {
	h := promhttp.InstrumentMetricHandler(
		prometheus.DefaultRegisterer, promhttp.HandlerFor(
			prometheus.DefaultGatherer,
			promhttp.HandlerOpts{MaxRequestsInFlight: 3},
		),
	)

	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

func strip0x(s string) string {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return s[2:]
	}
	return s
}

func detectBase(s string) int {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return 16
	}
	return 10
}
