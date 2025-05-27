// Copyright (C) 2025 l3montree UG (haftungsbeschraenkt)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package config

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"log/slog"

	toto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/zalando/go-keyring"
)

type baseConfig struct {
	Token     string `json:"token" mapstructure:"token"`
	AssetName string `json:"assetName" mapstructure:"assetName"`
	ApiUrl    string `json:"apiUrl" mapstructure:"apiUrl"`

	Path       string `json:"path" mapstructure:"path"`
	FailOnRisk string `json:"failOnRisk" mapstructure:"failOnRisk"`
	WebUI      string `json:"webUI" mapstructure:"webUI"`

	Username string `json:"username" mapstructure:"username"`
	Password string `json:"password" mapstructure:"password"`
	Registry string `json:"registry" mapstructure:"registry"`

	// used in SbomCMD
	ScannerID  string `json:"scannerId" mapstructure:"scannerId"`
	Ref        string `json:"ref" mapstructure:"ref"`
	DefaultRef string `json:"defaultRef" mapstructure:"defaultRef"`
}

type InTotoConfig struct {
	Step      string   `mapstructure:"step"`
	Materials []string `mapstructure:"materials"`
	Products  []string `mapstructure:"products"`
	Ignore    []string `mapstructure:"ignore"`

	SupplyChainID          string `mapstructure:"supplyChainId"`
	GenerateSlsaProvenance bool   `mapstructure:"generateSlsaProvenance"`

	LayoutKeyPath string `mapstructure:"layoutKey"`

	Key       toto.Key
	LayoutKey toto.Key
}

type AttestationConfig struct {
	PredicateType string `mapstructure:"predicateType"`
}

var RuntimeBaseConfig baseConfig
var RuntimeInTotoConfig InTotoConfig
var RuntimeAttestationConfig AttestationConfig

func ParseBaseConfig() {
	err := viper.Unmarshal(&RuntimeBaseConfig)
	if err != nil {
		panic(err)
	}

	if RuntimeBaseConfig.ApiUrl != "" {
		RuntimeBaseConfig.ApiUrl = sanitizeApiUrl(RuntimeBaseConfig.ApiUrl)
	}

	if RuntimeBaseConfig.Path != "" {
		if err := isValidPath(RuntimeBaseConfig.Path); err != nil {
			panic(err)
		}
	}
	gitVersionInfo, err := utils.GetAssetVersionInfoFromGit(RuntimeBaseConfig.Path)

	if RuntimeBaseConfig.Ref == "" {
		// check if we have a git version info
		if err == nil {
			RuntimeBaseConfig.Ref = gitVersionInfo.BranchOrTag
		} else {
			// if we don't have a git version info, we use the current time as ref
			slog.Info("could not get git version info, using current 'main' as ref", "err", err)
			RuntimeBaseConfig.Ref = "main"
		}
	}

	if RuntimeBaseConfig.DefaultRef == "" {

		// check if we have a git version info
		if err == nil {
			RuntimeBaseConfig.DefaultRef = gitVersionInfo.DefaultBranch
		} else {
			// if we don't have a git version info, we use the current time as default ref
			slog.Info("could not get git version info, using current '--ref' as default ref", "err", err)
			RuntimeBaseConfig.DefaultRef = RuntimeBaseConfig.Ref
		}
	}
}

func StoreTokenInKeyring(assetName, token string) error {
	service := "devguard/" + assetName
	user := "devguard"

	// set password
	return keyring.Set(service, user, token)
}

func getTokenFromKeyring(assetName string) (string, error) {
	service := "devguard/" + assetName
	user := "devguard"

	token, err := keyring.Get(service, user)
	if err != nil {
		return "", err
	}

	return token, nil
}

func tokenToInTotoKey(token string) (toto.Key, error) {
	privKey, _, err := pat.HexTokenToECDSA(token)
	if err != nil {
		return toto.Key{}, err
	}
	privKeyBytes, err := x509.MarshalECPrivateKey(&privKey)
	if err != nil {
		return toto.Key{}, err
	}

	// encode to pem
	b := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	// create new reader
	reader := bytes.NewReader(b)

	var key toto.Key
	err = key.LoadKeyReader(reader, "ecdsa-sha2-nistp521", []string{"sha256"})
	if err != nil {
		return toto.Key{}, errors.Wrap(err, "failed to load key")
	}

	return key, nil
}
func ParseAttestationConfig() {
	err := viper.Unmarshal(&RuntimeAttestationConfig)
	if err != nil {
		panic(err)
	}

}

func ParseInTotoConfig() {
	err := viper.Unmarshal(&RuntimeInTotoConfig)
	if err != nil {
		panic(err)
	}

	if RuntimeBaseConfig.Token == "" {
		RuntimeBaseConfig.Token, err = getTokenFromKeyring(RuntimeBaseConfig.AssetName)
		if err != nil {
			panic(err)
		}
	}

	RuntimeInTotoConfig.Key, err = tokenToInTotoKey(RuntimeBaseConfig.Token)
	if err != nil {
		panic(err)
	}

	if RuntimeInTotoConfig.LayoutKeyPath != "" {
		var layoutKey toto.Key
		err = layoutKey.LoadKey(RuntimeInTotoConfig.LayoutKeyPath, "ecdsa-sha2-nistp256", []string{"sha256"})
		if err != nil {
			panic(err)
		}
	}
}
