package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/fwdcloudsec/granted/pkg/cfaws"
)

type opts struct {
	region      *string
	secretKey   *string
	accessKeyId *string
}

func main() {
	o := opts{}
	fs := flag.FlagSet{}
	o.accessKeyId = fs.String("aws-access-key-id", "", "")
	o.secretKey = fs.String("aws-secret-key", "", "")
	o.region = fs.String("aws-region", "", "")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	creds := cfaws.GetEnvCredentials(context.Background())
	if !creds.HasKeys() {
		fmt.Println("No credentials set in env")
		os.Exit(1)
	}

	if creds.AccessKeyID != *o.accessKeyId {
		fmt.Println("access key id not equal")
		os.Exit(1)
	}
	if creds.SecretAccessKey != *o.secretKey {
		fmt.Println("secret access key not equal")
		os.Exit(1)
	}
	if os.Getenv("AWS_REGION") != *o.region {
		fmt.Println("region not set correctly")
		os.Exit(1)
	}
}
