// Copyright (C) 2026 l3montree GmbH
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
package dtos

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/go-playground/validator/v10"
)

var V = func() *validator.Validate {
	v := validator.New()
	// future_max_1y: value must be a Unix timestamp between now and now+1 year
	v.RegisterValidation("future_max_1y", func(fl validator.FieldLevel) bool { //nolint:errcheck
		ts := fl.Field().Int()
		now := time.Now().Unix()
		return ts > now && ts <= now+31536000
	})

	v.RegisterValidation("pgp_keyring", func(fl validator.FieldLevel) bool { //nolint:errcheck
		keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(fl.Field().String()))
		return err == nil && len(keyring) > 0
	})

	v.RegisterValidation("rsa_public_key", func(fl validator.FieldLevel) bool { //nolint:errcheck
		_, err := ParseRSAPublicKey(fl.Field().String())
		return err == nil
	})
	return v
}()

func ParseRSAPublicKey(pemKey string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an RSA key")
	}
	return rsaKey, nil
}
