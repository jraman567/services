// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package sevsnp

import (
	"github.com/veraison/services/handler"
	"github.com/veraison/services/scheme/common"
)

type EndorsementHandler struct{}

func (o EndorsementHandler) Init(params handler.EndorsementHandlerParams) error {
	return nil // no-op
}

func (o EndorsementHandler) Close() error {
	return nil // no-op
}

func (o EndorsementHandler) GetName() string {
	return SchemeName
}

func (o EndorsementHandler) GetAttestationScheme() string {
	return SchemeName
}

func (o EndorsementHandler) GetSupportedMediaTypes() []string {
	return EndorsementMediaTypes
}

/* ToDo: Add support for signed CoRIMs */
func (o EndorsementHandler) Decode(data []byte) (*handler.EndorsementHandlerResponse, error) {
	return common.UnsignedCorimDecoder(data, &Extractor{})
}
