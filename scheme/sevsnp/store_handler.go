// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package sevsnp

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"

	"github.com/jraman567/tokens"
	"github.com/veraison/corim/comid"
	"github.com/veraison/services/handler"
	"github.com/veraison/services/proto"
)

type StoreHandler struct{}

func (s StoreHandler) GetName() string {
	return fmt.Sprintf("%s-store-handler", SchemeName)
}

func (s StoreHandler) GetAttestationScheme() string {
	return SchemeName
}

func (s StoreHandler) GetSupportedMediaTypes() []string {
	return nil
}

func getRefValKey(rv comid.ValueTriple, tenantID string) (string, error) {
	m, err := measurementByUintKey(rv, measurementMKey)
	if err != nil {
		return "", err
	}

	if m == nil {
		return "", fmt.Errorf("measurement not found")
	}

	d := m.Val.Digests

	u := url.URL{
		Scheme: SchemeName,
		Host:   tenantID,
		Path:   hex.EncodeToString((*d)[0].HashValue),
	}

	return u.String(), nil
}

// SynthKeysFromRefValue
//
// Constructs SEV-SNP reference value of the form
// "SEVSNP://<tenantID>/<measurement>". The measurement
// is unique to an attester instance and, as such, is
// the best candidate to use as the key.
func (s StoreHandler) SynthKeysFromRefValue(
	tenantID string,
	refValue *handler.Endorsement,
) ([]string, error) {
	var rv comid.ValueTriple

	err := json.Unmarshal(refValue.Attributes, &rv)
	if err != nil {
		return nil, err
	}

	refValKey, err := getRefValKey(rv, tenantID)
	if err != nil {
		return nil, err
	}

	return []string{refValKey}, nil
}

// SynthKeysFromTrustAnchor
//
// AMD's Root Key (ARK) is the only Trust Anchor for SEV-SNP.
//
// The attester supplies all the keys in the certificate chain
// for verification. During verification, we must ensure that
// the ARK in the evidence matches the provisioned Trust Anchor.
//
// The TA key is "SEVSNP://<keyname>". For example, "SEV-SNP://ARK-Milan"
func (s StoreHandler) SynthKeysFromTrustAnchor(_ string, ta *handler.Endorsement) ([]string, error) {
	var avk comid.KeyTriple

	err := json.Unmarshal(ta.Attributes, &avk)
	if err != nil {
		return nil, err
	}

	ark := avk.VerifKeys[0]

	keyBlock, _ := pem.Decode([]byte(ark.String()))
	if keyBlock == nil || keyBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode ARK")
	}

	cert, err := x509.ParseCertificate(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	u := url.URL{
		Scheme: SchemeName,
		Path:   cert.Issuer.CommonName,
	}

	return []string{u.String()}, nil
}

// GetTrustAnchorIDs
//
// "auxblob" in the TSM report contains a certificate
// table. Extract ARK from it and construct the TA key.
func (s StoreHandler) GetTrustAnchorIDs(token *proto.AttestationToken) ([]string, error) {
	var tsm tokens.TSMReport

	err := tsm.FromCBOR(token.Data)
	if err != nil {
		return nil, err
	}

	ark, err := getARK(tsm.AuxBlob)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(ark)
	if keyBlock == nil || keyBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode ARK")
	}

	cert, err := x509.ParseCertificate(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	u := url.URL{
		Scheme: SchemeName,
		Path:   cert.Issuer.CommonName,
	}

	return []string{u.String()}, nil
}

// GetRefValueIDs
//
// Reference value key for SEV-SNP is of the form
// "SEVSNP://<tenantID>/<measurement>", as explained
// in SynthKeysFromRefValue.
//
// Look up "measurement" using its MKey (641) and construct the refval key.
func (s StoreHandler) GetRefValueIDs(
	tenantID string,
	_ []string,
	claims map[string]interface{},
) ([]string, error) {
	claimsJson, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	extractedComid, err := comidFromJson(claimsJson)
	if err != nil {
		return nil, err
	}

	if len(extractedComid.Triples.ReferenceValues.Values) > 1 {
		return nil, fmt.Errorf("unable to process multiple claims in evidence")
	}

	m, err := measurementByUintKey(extractedComid.Triples.ReferenceValues.Values[0], measurementMKey)
	if err != nil {
		return nil, err
	}

	digest := hex.EncodeToString((*m.Val.Digests)[0].HashValue)

	u := url.URL{
		Scheme: SchemeName,
		Host:   tenantID,
		Path:   digest,
	}

	return []string{u.String()}, nil
}
