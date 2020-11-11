package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	xhttp "github.com/minio/minio/cmd/http"
	"github.com/minio/minio/pkg/auth"
)

type serviceType string

const (
	serviceS3  serviceType = "s3"
	serviceSTS serviceType = "sts"
)

// AWS Signature Version '4' constants.
const (
	signV4Algorithm = "AWS4-HMAC-SHA256"
	iso8601Format   = "20060102T150405Z"
	yyyymmdd        = "20060102"
)

// isValidRegion - verify if incoming region value is valid with configured Region.
func isValidRegion(reqRegion string, confRegion string) bool {
	if confRegion == "" {
		return true
	}
	if confRegion == "US" {
		confRegion = ""
	}
	// Some older s3 clients set region as "US" instead of
	// globalMinioDefaultRegion, handle it.
	if reqRegion == "US" {
		reqRegion = ""
	}
	return reqRegion == confRegion
}

// parse credentialHeader string into its structured form.
func parseCredentialHeader(credElement string, region string) (accessKey string, err error) {
	creds := strings.SplitN(strings.TrimSpace(credElement), "=", 2)
	if len(creds) != 2 {
		return "", errors.New("error missing fields")
	}
	if creds[0] != "Credential" {
		return "", errors.New("missing Credential tag")
	}
	credElements := strings.Split(strings.TrimSpace(creds[1]), "/")
	if len(credElements) < 5 {
		return "", errors.New("malformed Credential tag")
	}
	accessKey = strings.Join(credElements[:len(credElements)-4], "/") // The access key may contain one or more `/`
	if !auth.IsAccessKeyValid(accessKey) {
		return "", errors.New("invalid access key id")
	}

	credElements = credElements[len(credElements)-4:]
	if _, err = time.Parse(yyyymmdd, credElements[0]); err != nil {
		return accessKey, fmt.Errorf("invalid credential date %s", err)
	}

	// Region is set to be empty, we use whatever was sent by the
	// request and proceed further. This is a work-around to address
	// an important problem for ListBuckets() getting signed with
	// different regions.
	if region == "" {
		region = credElements[1]
	}

	// Should validate region, only if region is set.
	if !isValidRegion(credElements[1], region) {
		return accessKey, errors.New("invalid region")

	}
	switch serviceType(credElements[2]) {
	case serviceSTS:
	case serviceS3:
	default:
		return accessKey, fmt.Errorf("invalid service type %s", credElements[2])
	}
	if credElements[3] != "aws4_request" {
		return accessKey, errors.New("invalid AWS signature version")
	}
	return accessKey, nil
}

func getReqAccessKey(r *http.Request, region string) (string, error) {
	accessKey, err := parseCredentialHeader("Credential="+r.URL.Query().Get(xhttp.AmzCredential), region)
	if err != nil {
		// Strip off the Algorithm prefix.
		v4Auth := strings.TrimPrefix(r.Header.Get("Authorization"), signV4Algorithm)
		authFields := strings.Split(strings.TrimSpace(v4Auth), ",")
		if len(authFields) != 3 {
			return accessKey, errors.New("missing expected fields")
		}
		accessKey, err = parseCredentialHeader(authFields[0], region)
	}
	return accessKey, err
}
