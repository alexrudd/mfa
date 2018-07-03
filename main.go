package main

import "github.com/99designs/keyring"
import "github.com/alexrudd/mfa/otp"
import "os"
import "fmt"
import "golang.org/x/crypto/ssh/terminal"

const keyringService = "mfa"
const keyringDir = "~/.mfa"

func main() {
	args := os.Args[1:]

	if len(args) < 1 {
		usageExit()
	}

	switch args[0] {
	case "add":
		if len(args) < 3 {
			fmt.Fprintf(os.Stderr, "add requires two arguments: mfa add <service> <secret>\n")
			os.Exit(1)
		}
		addService(args[1], args[2])
	case "get":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "get requires one arguments: mfa get <service>\n")
			os.Exit(1)
		}
		secret, err := getServiceSecret(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to retrieve secret for service %s: %s\n", args[1], err.Error())
			os.Exit(1)
		}
		fmt.Println(secret)
	case "otp":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "otp requires one arguments: mfa otp <service>\n")
			os.Exit(1)
		}
		secret, err := getServiceSecret(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to retrieve secret for service %s: %s\n", args[1], err.Error())
			os.Exit(1)
		}
		fmt.Println(otp.GetTotp(secret))
	default:
		usageExit()
	}
}

func usageExit() {
	fmt.Fprintf(os.Stderr, "Usage:\n\tmfa add <service> <secret>\n\tmfa get <service>\n\tmfa otp <service>\n")
	os.Exit(1)
}

func openKeyring() (keyring.Keyring, error) {
	return keyring.Open(keyring.Config{
		ServiceName:             keyringService,
		KeychainName:            keyringService,
		FileDir:                 keyringDir,
		FilePasswordFunc:        fileKeyringPassphrasePrompt,
		LibSecretCollectionName: keyringService,
		KWalletAppID:            keyringService,
		KWalletFolder:           keyringService,
	})
}

func addService(service, secret string) error {
	ring, err := openKeyring()
	if err != nil {
		return err
	}
	return ring.Set(keyring.Item{
		Key:  service,
		Data: []byte(secret),
	})
}

func getServiceSecret(service string) (string, error) {
	ring, err := openKeyring()
	if err != nil {
		return "", err
	}
	item, err := ring.Get(service)
	if err != nil {
		return "", err
	}
	return string(item.Data), nil
}

func fileKeyringPassphrasePrompt(prompt string) (string, error) {
	if password := os.Getenv("MFA_FILE_PASSPHRASE"); password != "" {
		return password, nil
	}

	fmt.Printf("%s: ", prompt)
	b, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(b), nil
}
