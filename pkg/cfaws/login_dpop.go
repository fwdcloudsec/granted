package cfaws

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/signin"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/google/uuid"
)

// AWS Sign-In DPoP always uses the P-256 curve, so signatures are 2 x 32 bytes.
const dpopCurveLen = 256 / 8

// makeDPoP builds the DPoP proof JWT (RFC 9449) that AWS Sign-In requires on
// CreateOAuth2Token refresh calls. It mirrors the proof the AWS CLI and SDKs send:
// an ES256 JWS over the HTTP method and URL, signed with the session's EC key.
func makeDPoP(keyPEM, method, htu string, now time.Time) (string, error) {
	key, err := parseDPoPKey(keyPEM)
	if err != nil {
		return "", err
	}

	header, err := jsonBase64URL(map[string]any{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(padCoordinate(key.X.Bytes())),
			"y":   base64.RawURLEncoding.EncodeToString(padCoordinate(key.Y.Bytes())),
		},
	})
	if err != nil {
		return "", err
	}

	payload, err := jsonBase64URL(map[string]any{
		"jti": uuid.NewString(),
		"htm": method,
		"htu": htu,
		"iat": now.Unix(),
	})
	if err != nil {
		return "", err
	}

	signingInput := header + "." + payload
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing dpop proof: %w", err)
	}

	// JWS ES256 signatures are the raw r || s values, each left-padded to the curve size.
	sig := make([]byte, dpopCurveLen*2)
	r.FillBytes(sig[:dpopCurveLen])
	s.FillBytes(sig[dpopCurveLen:])

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func parseDPoPKey(keyPEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("login session dpopKey is not PEM encoded")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing login session dpopKey: %w", err)
	}
	return key, nil
}

// padCoordinate left-pads an EC coordinate to the curve size, as JWK requires.
func padCoordinate(b []byte) []byte {
	if len(b) >= dpopCurveLen {
		return b
	}
	out := make([]byte, dpopCurveLen)
	copy(out[dpopCurveLen-len(b):], b)
	return out
}

func jsonBase64URL(v any) (string, error) {
	j, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(j), nil
}

// withDPoP returns a signin client option that adds a DPoP header, signed with keyPEM,
// to the outgoing request. The URL is only known at finalize time, so this is a
// middleware rather than a static header.
func withDPoP(keyPEM string) func(*signin.Options) {
	return signin.WithAPIOptions(func(stack *middleware.Stack) error {
		return stack.Finalize.Add(&dpopMiddleware{keyPEM: keyPEM}, middleware.After)
	})
}

type dpopMiddleware struct {
	keyPEM string
}

func (*dpopMiddleware) ID() string { return "grantedSignDPoP" }

func (m *dpopMiddleware) HandleFinalize(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
	req, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return middleware.FinalizeOutput{}, middleware.Metadata{}, fmt.Errorf("unexpected transport type %T", in.Request)
	}
	proof, err := makeDPoP(m.keyPEM, req.Method, req.URL.String(), time.Now())
	if err != nil {
		return middleware.FinalizeOutput{}, middleware.Metadata{}, err
	}
	req.Header.Set("DPoP", proof)
	return next.HandleFinalize(ctx, in)
}
