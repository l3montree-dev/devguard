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
	"net/http"

	toto "github.com/in-toto/in-toto-golang/in_toto"

	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/zalando/go-keyring"
)

type baseConfig struct {
	CI        bool   `json:"ci" mapstructure:"ci"`
	Token     string `json:"token" mapstructure:"token"`
	AssetName string `json:"assetName" mapstructure:"assetName"`
	APIURL    string `json:"apiUrl" mapstructure:"apiUrl"`

	Image      string `json:"image" mapstructure:"image"`
	Path       string `json:"path" mapstructure:"path"`
	FailOnRisk string `json:"failOnRisk" mapstructure:"failOnRisk"`
	FailOnCVSS string `json:"failOnCVSS" mapstructure:"failOnCVSS"`
	WebUI      string `json:"webUI" mapstructure:"webUI"`

	Username string `json:"username" mapstructure:"username"`
	Password string `json:"password" mapstructure:"password"`
	Registry string `json:"registry" mapstructure:"registry"`

	ScannerID     string `json:"scannerId" mapstructure:"scannerID"`
	Ref           string `json:"ref" mapstructure:"ref"`
	DefaultBranch string `json:"defaultRef" mapstructure:"defaultRef"`
	IsTag         bool   `json:"isTag" mapstructure:"isTag"`
	ArtifactName  string `json:"artifactName" mapstructure:"artifactName"`
	Origin        string `json:"origin" mapstructure:"origin"`
	OutputPath    string `json:"outputPath" mapstructure:"outputPath"`

	Timeout                    int  `json:"timeout" mapstructure:"timeout"`
	IgnoreExternalReferences   bool `json:"ignoreExternalReferences" mapstructure:"ignoreExternalReferences"`
	IgnoreUpstreamAttestations bool `json:"ignoreUpstreamAttestations" mapstructure:"ignoreUpstreamAttestations"`

	Offline bool `json:"offline" mapstructure:"offline"`

	ImagePath                     string `json:"imagePath" mapstructure:"imagePath"`
	ImagePathSuffix               string `json:"imageSuffix" mapstructure:"imageSuffix"`
	UpstreamVersion               string `json:"upstreamVersion" mapstructure:"upstreamVersion"`
	Architecture                  string `json:"architecture" mapstructure:"architecture"`
	ImageVariant                  string `json:"imageVariant" mapstructure:"imageVariant"`
	KeepOriginalSbomRootComponent bool   `json:"keepOriginalSbomRootNodes" mapstructure:"keepOriginalSbomRootNodes"`
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

	Disabled bool
}

type AttestationConfig struct {
	PredicateType string `mapstructure:"predicateType"`
}

var RuntimeBaseConfig baseConfig
var RuntimeInTotoConfig InTotoConfig
var RuntimeAttestationConfig AttestationConfig

func ParseBaseConfig(runningCMD string) {
	err := viper.Unmarshal(&RuntimeBaseConfig)
	if err != nil {
		panic(err)
	}

	if RuntimeBaseConfig.APIURL != "" {
		RuntimeBaseConfig.APIURL = sanitizeAPIURL(RuntimeBaseConfig.APIURL)
	}

	if RuntimeBaseConfig.Path != "" {
		if err := isValidPath(RuntimeBaseConfig.Path); err != nil {
			panic(err)
		}
	}

	if RuntimeBaseConfig.Ref == "" || RuntimeBaseConfig.DefaultBranch == "" {
		gitVersionInfo, err := utils.GetAssetVersionInfo(RuntimeBaseConfig.Path)
		if err != nil {
			slog.Debug("could not get git version info")
		}
		if RuntimeBaseConfig.Ref == "" {
			// check if we have a git version info
			if err == nil {
				RuntimeBaseConfig.Ref = gitVersionInfo.BranchOrTag
			} else {
				// if we don't have a git version info, we use the current time as ref
				slog.Debug("could not get git version info, using current 'main' as ref")
				RuntimeBaseConfig.Ref = "main"
			}
		}

		if RuntimeBaseConfig.DefaultBranch == "" {
			// check if we have a git version info
			if gitVersionInfo.DefaultBranch != nil {
				RuntimeBaseConfig.DefaultBranch = *gitVersionInfo.DefaultBranch
			} else {
				// if we don't have a git version info, we use the current time as default ref
				slog.Debug("could not get git default ref. Not updating anything default branch information")
			}
		}
	}

	if RuntimeBaseConfig.ArtifactName == "" {
		RuntimeBaseConfig.ArtifactName = normalize.ArtifactPurl(runningCMD, RuntimeBaseConfig.AssetName)
	}

	if RuntimeBaseConfig.Timeout <= 0 {
		RuntimeBaseConfig.Timeout = 300
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
	privKey, _, err := services.HexTokenToECDSA(token)
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
	if RuntimeBaseConfig.Token == "" && utils.RunsInCI() {
		// we cannot use in toto
		RuntimeInTotoConfig.Disabled = true
		slog.Debug("no token provided, disabling in-toto functionality")
		return
	}

	if RuntimeBaseConfig.Token == "" && RuntimeBaseConfig.CI {
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

func SetXAssetHeaders(req *http.Request) {
	req.Header.Set("X-Asset-Name", RuntimeBaseConfig.AssetName)
	req.Header.Set("X-Asset-Ref", RuntimeBaseConfig.Ref)

	if RuntimeBaseConfig.IsTag {
		req.Header.Set("X-Tag", "1")
	} else {
		req.Header.Set("X-Tag", "0")
	}

	if RuntimeBaseConfig.DefaultBranch != "" {
		req.Header.Set("X-Asset-Default-Branch", RuntimeBaseConfig.DefaultBranch)
	}
}
