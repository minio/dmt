package main

import (
	"strings"

	"github.com/minio/minio/pkg/env"
)

func getDMTNamespace() string {
	return strings.TrimSpace(env.Get(dmtNamespace, "default"))
}

func getDMTConfigMapName() string {
	return strings.TrimSpace(env.Get(dmtConfigMapName, "dmt-configuration"))
}