// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package sevsnp

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	sevsnpParser "github.com/jraman567/go-gen-ref/cmd/sevsnp"
	"github.com/jraman567/tokens"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/services/handler"
	"github.com/veraison/services/log"
	"github.com/veraison/services/proto"
)

type EvidenceHandler struct {
}

func (o EvidenceHandler) GetName() string {
	return "sevsnp-evidence-handler"
}

func (o EvidenceHandler) GetAttestationScheme() string {
	return SchemeName
}

func (o EvidenceHandler) GetSupportedMediaTypes() []string {
	return EvidenceMediaTypes
}

// ExtractClaims
//
// Converts evidence in tsm-report format to our
// "internal representation", which is in CoRIM format.
func (o EvidenceHandler) ExtractClaims(
	token *proto.AttestationToken,
	_ []string,
) (map[string]interface{}, error) {
	var claimsSet map[string]interface{}
	var tsm tokens.TSMReport

	err := tsm.FromCBOR(token.Data)
	if err != nil {
		return nil, err
	}

	reportProto, err := abi.ReportToProto(tsm.OutBlob)
	if err != nil {
		return nil, err
	}

	refValComid, err := sevsnpParser.ReportToComid(reportProto, 0)
	if err != nil {
		return nil, err
	}

	err = refValComid.Valid()
	if err != nil {
		return nil, err
	}

	refValCorim := corim.UnsignedCorim{}
	refValCorim.SetProfile("http://amd.com/2024/snp-corim-profile")
	refValCorim.AddComid(*refValComid)

	refValJson, err := refValCorim.ToJSON()
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(refValJson, &claimsSet)
	if err != nil {
		return nil, err
	}

	return claimsSet, nil
}
func snpAttestationOptions() *verify.Options {
	return &verify.Options{
		Getter:              trust.DefaultHTTPSGetter(),
		Now:                 time.Now(),
		DisableCertFetching: true,
	}
}

func readCert(cert []byte) ([]byte, error) {
	block, _ := pem.Decode(cert)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to read certificate")
	}
	return block.Bytes, nil
}

func compareTAs(provisionedArk []byte, evidenceArk []byte) (bool, error) {
	pArk, err := readCert(provisionedArk)
	if err != nil {
		return false, err
	}

	pCert, err := x509.ParseCertificate(pArk)
	if err != nil {
		return false, err
	}

	eArk, err := readCert(evidenceArk)
	if err != nil {
		return false, err
	}

	eCert, err := x509.ParseCertificate(eArk)
	if err != nil {
		return false, err
	}

	return pCert.Equal(eCert), nil
}

// ValidateEvidenceIntegrity
//
// The "auxblob" in the evidence contains a certificate chain.
// The Trust Anchor in this chain is AMD Root Key (ARK).
//
// Verify that the ARK in the evidence matches the provisioned
// ARK, confirm the integrity of the certificate chain, and
// validate the signature of the evidence.
func (o EvidenceHandler) ValidateEvidenceIntegrity(
	token *proto.AttestationToken,
	trustAnchors []string,
	endorsementsStrings []string,
) error {
	var (
		taEndorsement handler.Endorsement
		avk           comid.KeyTriple
		tsm           tokens.TSMReport
	)

	// Get the ARK TA
	for i, t := range trustAnchors {
		var endorsement handler.Endorsement

		if err := json.Unmarshal([]byte(t), &endorsement); err != nil {
			return fmt.Errorf("could not decode endorsement at index %d: %w", i, err)
		}

		if endorsement.Type == handler.EndorsementType_VERIFICATION_KEY {
			taEndorsement = endorsement
			break
		}
	}

	if taEndorsement.Type != handler.EndorsementType_VERIFICATION_KEY {
		return fmt.Errorf("trust anchors unavailable")
	}

	err := json.Unmarshal(taEndorsement.Attributes, &avk)
	if err != nil {
		return err
	}

	provisionedArk := avk.VerifKeys[0]

	// Parse certificate chain in evidence (auxblob)
	err = tsm.FromCBOR(token.Data)
	if err != nil {
		return err
	}

	protoReport, err := abi.ReportToProto(tsm.OutBlob)
	if err != nil {
		return err
	}

	ark, err := getARK(tsm.AuxBlob)
	if err != nil {
		return err
	}

	arkBlock, err := readCert(ark)
	if err != nil {
		return err
	}

	ask, err := getASK(tsm.AuxBlob)
	if err != nil {
		return err
	}

	askBlock, err := readCert(ask)
	if err != nil {
		return err
	}

	vcek, err := getVCEK(tsm.AuxBlob)
	if err != nil {
		return err
	}

	vcekBlock, err := readCert(vcek)
	if err != nil {
		return err
	}

	// Test if TA matches with the one supplied in evidence
	match, err := compareTAs([]byte(provisionedArk.String()), ark)
	if err != nil {
		return err
	}
	if !match {
		return fmt.Errorf("ARK in evidence does not match provisioned ARK")
	}

	// Validate the integrity of evidence by ensuring the
	// certificate chain is intact, and the signature is valid
	var attestation sevsnp.Attestation
	attestation.Report = protoReport
	attestation.CertificateChain = &sevsnp.CertificateChain{VcekCert: vcekBlock, AskCert: askBlock, ArkCert: arkBlock}
	err = verify.SnpAttestation(&attestation, snpAttestationOptions())

	if err != nil {
		log.Errorf("failed to validate certificate chain: %+v\n", err)
	}

	return err
}
