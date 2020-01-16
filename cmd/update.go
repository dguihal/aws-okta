package cmd

import (
	"encoding/json"
	"errors"

	"github.com/99designs/keyring"
	analytics "github.com/segmentio/analytics-go"
	"github.com/segmentio/aws-okta/lib"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "update your okta credentials",
	RunE:  update,
}

func init() {
	RootCmd.AddCommand(updateCmd)
	updateCmd.Flags().StringVarP(&oktaAccountName, "account", "", "", "Okta account name")
}

func update(cmd *cobra.Command, args []string) error {

	var allowedBackends []keyring.BackendType
	if backend != "" {
		allowedBackends = append(allowedBackends, keyring.BackendType(backend))
	}
	kr, err := lib.OpenKeyring(allowedBackends)

	if oktaAccountName == "" {
		oktaAccountName = "okta-creds"
	} else {
		oktaAccountName = "okta-creds-" + oktaAccountName
	}
	log.Debugf("Keyring key: %s", oktaAccountName)

	if err != nil {
		log.Fatal(err)
	}

	var oktaCreds lib.OktaCreds
	item, err := kr.Get(oktaAccountName)
	if err != nil {
		log.Fatal(err)
	} else {
		if err = json.Unmarshal(item.Data, &oktaCreds); err != nil {
			return errors.New("Failed to get okta credentials from your keyring. Please make sure you have added okta credentials with `aws-okta add`")
		}
	}

	if analyticsEnabled && analyticsClient != nil {
		analyticsClient.Enqueue(analytics.Track{
			UserId: username,
			Event:  "Ran Command",
			Properties: analytics.NewProperties().
				Set("backend", backend).
				Set("aws-okta-version", version).
				Set("command", "update"),
		})
	}

	// Ask for password from prompt
	password, err := lib.Prompt("New Okta password", true)
	if err != nil {
		return err
	}

	oktaCreds.Password = password

	// Profiles aren't parsed during `add`, but still want
	// to centralize the MFA config logic
	var dummyProfiles lib.Profiles
	updateMfaConfig(cmd, dummyProfiles, "", &mfaConfig)

	if err := oktaCreds.Validate(mfaConfig); err != nil {
		log.Debugf("Failed to validate credentials: %s", err)
		return ErrFailedToValidateCredentials
	}

	encoded, err := json.Marshal(oktaCreds)
	if err != nil {
		return err
	}

	krItem := keyring.Item{
		Key:   oktaAccountName,
		Data:  encoded,
		Label: "okta credentials",
		KeychainNotTrustApplication: false,
	}

	if err := kr.Set(krItem); err != nil {
		log.Debugf("Failed to add user to keyring: %s", err)
		return ErrFailedToSetCredentials
	}

	log.Infof("Added credentials for user %s", username)
	return nil
}
