package cfaws

import (
	"fmt"

	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/testable"
	"github.com/joho/godotenv"
)

// WriteCredentialsToDotenv will check if a .env file exists and prompt to create one if it does not.
// After the file exists, it will be opened, credentaisl added and then written to disc
func WriteCredentialsToDotenv(region string, creds aws.Credentials) error {
	withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
	if _, err := os.Stat("./.env"); os.IsNotExist(err) {
		ans := false
		err = testable.AskOne(&survey.Confirm{Message: "No .env file found in the current directory, would you like to create one?"}, &ans, withStdio)
		if err != nil {
			return err
		}
		if ans {
			f, err := os.Create("./.env")
			if err != nil {
				return err
			}
			err = f.Close()
			if err != nil {
				return err
			}
			clio.Success("Successfully created a new .env file in the current directory")
		} else {
			return fmt.Errorf(".env file does not exist and creation was aborted")
		}
	}

	myEnv, err := godotenv.Read()
	if err != nil {
		return err
	}

	myEnv["AWS_ACCESS_KEY_ID"] = creds.AccessKeyID
	myEnv["AWS_SECRET_ACCESS_KEY"] = creds.SecretAccessKey
	myEnv["AWS_SESSION_TOKEN"] = creds.SessionToken
	myEnv["AWS_REGION"] = region

	return godotenv.Write(myEnv, "./.env")
}
