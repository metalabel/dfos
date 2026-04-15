package dfos

import "crypto/ed25519"

// ContentState represents the verified state of a content chain.
type ContentState struct {
	ContentID          string  `json:"contentId"`
	GenesisCID         string  `json:"genesisCID"`
	HeadCID            string  `json:"headCID"`
	IsDeleted          bool    `json:"isDeleted"`
	CurrentDocumentCID *string `json:"currentDocumentCID"`
	Length             int     `json:"length"`
	CreatorDID         string  `json:"creatorDID"`
}

// SignContentCreate signs a content chain genesis (create) operation.
func SignContentCreate(did, documentCID, kid string, note string, privateKey ed25519.PrivateKey) (jwsToken string, contentID string, operationCID string, err error) {
	now := protocolTimestamp()

	payload := map[string]any{
		"version":         1,
		"type":            "create",
		"did":             did,
		"documentCID":     documentCID,
		"baseDocumentCID": nil,
		"createdAt":       now.Format("2006-01-02T15:04:05.000Z"),
		"note":            nil,
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

// ContentUpdateOptions holds optional parameters for content update operations.
type ContentUpdateOptions struct {
	Note            string
	BaseDocumentCID string
	Authorization   string
}

// SignContentUpdate signs a content chain update operation.
func SignContentUpdate(did, previousCID, documentCID, kid string, note string, privateKey ed25519.PrivateKey) (jwsToken string, operationCID string, err error) {
	return SignContentUpdateWithOptions(did, previousCID, documentCID, kid, privateKey, ContentUpdateOptions{Note: note})
}

// SignContentUpdateWithOptions signs a content chain update operation with full options.
func SignContentUpdateWithOptions(did, previousCID, documentCID, kid string, privateKey ed25519.PrivateKey, opts ContentUpdateOptions) (jwsToken string, operationCID string, err error) {
	now := protocolTimestamp()

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
	if opts.Note != "" {
		payload["note"] = opts.Note
	}
	if opts.BaseDocumentCID != "" {
		payload["baseDocumentCID"] = opts.BaseDocumentCID
	}
	if opts.Authorization != "" {
		payload["authorization"] = opts.Authorization
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

// SignContentDelete signs a content chain delete operation (permanent destruction).
func SignContentDelete(did, previousCID, kid string, note string, authorization string, privateKey ed25519.PrivateKey) (jwsToken string, operationCID string, err error) {
	now := protocolTimestamp()

	payload := map[string]any{
		"version":              1,
		"type":                 "delete",
		"did":                  did,
		"previousOperationCID": previousCID,
		"createdAt":            now.Format("2006-01-02T15:04:05.000Z"),
		"note":                 nil,
	}
	if note != "" {
		payload["note"] = note
	}
	if authorization != "" {
		payload["authorization"] = authorization
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
// Normalizes JSON number types (float64 → int64 for whole numbers) to match
// the relay's DagCborCID verification path.
func DocumentCID(doc any) (string, []byte, error) {
	doc = NormalizeJSONNumbers(doc)
	cborBytes, err := DagCborEncode(doc)
	if err != nil {
		return "", nil, err
	}
	cidBytes := MakeCIDBytes(cborBytes)
	return CIDToBase32(cidBytes), cborBytes, nil
}
