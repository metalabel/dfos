package protocol

import (
	"crypto/ed25519"
	"time"
)

// ContentState represents the verified state of a content chain.
type ContentState struct {
	ContentID         string  `json:"contentId"`
	GenesisCID        string  `json:"genesisCID"`
	HeadCID           string  `json:"headCID"`
	IsDeleted         bool    `json:"isDeleted"`
	CurrentDocumentCID *string `json:"currentDocumentCID"`
	Length            int     `json:"length"`
	CreatorDID        string  `json:"creatorDID"`
}

// SignContentCreate signs a content chain genesis (create) operation.
func SignContentCreate(did, documentCID, kid string, note string, privateKey ed25519.PrivateKey) (jwsToken string, contentID string, operationCID string, err error) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	payload := map[string]any{
		"version":        1,
		"type":           "create",
		"did":            did,
		"documentCID":    documentCID,
		"baseDocumentCID": nil,
		"createdAt":      now.Format("2006-01-02T15:04:05.000Z"),
		"note":           nil,
	}
	if note != "" {
		payload["note"] = note
	}

	_, cidBytes, cidStr, err := DagCborCID(payload)
	if err != nil {
		return "", "", "", err
	}

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:content-op",
		Kid: kid,
		CID: cidStr,
	}

	jwsToken, err = CreateJWS(header, payload, privateKey)
	if err != nil {
		return "", "", "", err
	}

	contentID = DeriveContentID(cidBytes)
	return jwsToken, contentID, cidStr, nil
}

// SignContentUpdate signs a content chain update operation.
func SignContentUpdate(did, previousCID, documentCID, kid string, note string, privateKey ed25519.PrivateKey) (jwsToken string, operationCID string, err error) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	payload := map[string]any{
		"version":              1,
		"type":                 "update",
		"did":                  did,
		"previousOperationCID": previousCID,
		"documentCID":          documentCID,
		"baseDocumentCID":      nil,
		"createdAt":            now.Format("2006-01-02T15:04:05.000Z"),
		"note":                 nil,
	}
	if note != "" {
		payload["note"] = note
	}

	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		return "", "", err
	}

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:content-op",
		Kid: kid,
		CID: cidStr,
	}

	jwsToken, err = CreateJWS(header, payload, privateKey)
	if err != nil {
		return "", "", err
	}

	return jwsToken, cidStr, nil
}

// DocumentCID computes the dag-cbor CID of a JSON document.
func DocumentCID(doc any) (string, []byte, error) {
	cborBytes, err := DagCborEncode(doc)
	if err != nil {
		return "", nil, err
	}
	cidBytes := MakeCIDBytes(cborBytes)
	return CIDToBase32(cidBytes), cborBytes, nil
}
