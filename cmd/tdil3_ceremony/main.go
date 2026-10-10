// Quantaureum Node source, version 1.0.0.
//
// tdil3_ceremony — offline (air-gapped) Dilithium3 v1 committee key ceremony.
//
// Mainnet refuses any runtime DKG, so the genesis v1 committee key is produced
// here, on an air-gapped machine, and installed per validator afterwards:
//
//	generate:  derive the chain-bound session, deal all committee shares,
//	           write one encrypted share blob per participant + the group key
//	           + a manifest (digests, roster mapping).
//	install:   run ON a validator; decrypt one share blob with the ceremony
//	           password and store it under the node's own store password.
//
// Passwords come from files — never argv — so nothing lands in ps or history.
// The ceremony password protects share blobs in transit (e.g. the USB stick);
// the store password is the validator's own unlock password.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	nodepkg "github.com/quantaureum/qau/node"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

type rosterEntryJSON struct {
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
}

type manifestJSON struct {
	ChainID              uint64 `json:"chain_id"`
	ActivationEpoch      uint64 `json:"activation_epoch"`
	KeyGeneration        uint64 `json:"key_generation"`
	SessionNonce         string `json:"session_nonce"`
	SessionDigest        string `json:"session_digest"`
	CommitteeDigest      string `json:"committee_digest"`
	IdentityRosterDigest string `json:"identity_roster_digest"`
	GroupPublicKey       string `json:"group_public_key"`
	Rho                  string `json:"rho"`
	Participants         []struct {
		ParticipantID uint32 `json:"participant_id"`
		Position      uint8  `json:"position"`
		Address       string `json:"address"`
		ShareFile     string `json:"share_file"`
	} `json:"participants"`
}

func readPasswordFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	password := []byte(strings.TrimSpace(string(raw)))
	if len(password) < 16 {
		return nil, fmt.Errorf("password in %s too short (%d bytes, min 16)", path, len(password))
	}
	return password, nil
}

func generate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	chain := fs.Uint64("chain", 0, "chain ID (mainnet = 1668)")
	genesisHex := fs.String("genesis", "", "genesis block hash, hex (0x optional)")
	activationEpoch := fs.Uint64("activation-epoch", 0, "epoch the shares activate at")
	rosterPath := fs.String("roster", "", "roster JSON: [{address, public_key}] in canonical order")
	passwordPath := fs.String("password-file", "", "file with the ceremony (transport) password")
	outDir := fs.String("out", "", "output directory for share blobs + manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *chain == 0 || *genesisHex == "" || *activationEpoch == 0 || *rosterPath == "" || *passwordPath == "" || *outDir == "" {
		return fmt.Errorf("required: -chain -genesis -activation-epoch -roster -password-file -out")
	}
	genesisBytes, err := hex.DecodeString(strings.TrimPrefix(*genesisHex, "0x"))
	if err != nil || len(genesisBytes) != 32 {
		return fmt.Errorf("genesis must be 32 bytes hex (got %d bytes)", len(genesisBytes))
	}
	var genesis types.Hash
	copy(genesis[:], genesisBytes)

	var rosterJSON []rosterEntryJSON
	rawRoster, err := os.ReadFile(*rosterPath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(rawRoster, &rosterJSON); err != nil {
		return fmt.Errorf("roster JSON: %w", err)
	}
	entries := make([]nodepkg.OfflineCeremonyRosterEntry, len(rosterJSON))
	for i, entry := range rosterJSON {
		entry.Address = strings.TrimSpace(entry.Address)
		addrBytes, err := hex.DecodeString(strings.TrimPrefix(entry.Address, "0x"))
		if err != nil || len(addrBytes) != 20 {
			return fmt.Errorf("roster entry %d: address must be 20 bytes hex", i)
		}
		copy(entries[i].Address[:], addrBytes)
		keyBytes, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(entry.PublicKey), "0x"))
		if err != nil || len(keyBytes) == 0 {
			return fmt.Errorf("roster entry %d: invalid public key", i)
		}
		entries[i].PublicKey = keyBytes
	}

	password, err := readPasswordFile(*passwordPath)
	if err != nil {
		return err
	}
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()

	session, err := nodepkg.OfflineCeremonySession(*chain, genesis, *activationEpoch, entries)
	if err != nil {
		return err
	}
	shares, key, rho, err := dilithium3v1.DealShares(session, rand.Reader)
	if err != nil {
		return err
	}
	defer func() {
		for _, share := range shares {
			if share != nil {
				share.Zeroize()
			}
		}
	}()

	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		return err
	}
	sessionDigest, err := session.Digest()
	if err != nil {
		return err
	}
	committeeDigest, err := session.Committee.CanonicalDigest()
	if err != nil {
		return err
	}
	manifest := manifestJSON{
		ChainID:              session.ChainID,
		ActivationEpoch:      session.ActivationEpoch,
		KeyGeneration:        session.KeyGeneration,
		SessionNonce:         hex.EncodeToString(session.Nonce[:]),
		SessionDigest:        hex.EncodeToString(sessionDigest[:]),
		CommitteeDigest:      hex.EncodeToString(committeeDigest[:]),
		IdentityRosterDigest: hex.EncodeToString(session.IdentityRosterDigest[:]),
		GroupPublicKey:       hex.EncodeToString(key.PublicKey),
		Rho:                  hex.EncodeToString(rho[:]),
	}
	for position, share := range shares {
		plaintext, err := share.MarshalBinary()
		if err != nil {
			return fmt.Errorf("share %d marshal: %w", position, err)
		}
		blob, err := tss.EncryptSingleShareBlob(plaintext, password)
		for i := range plaintext {
			plaintext[i] = 0
		}
		if err != nil {
			return fmt.Errorf("share %d encrypt: %w", position, err)
		}
		name := fmt.Sprintf("share_%d.enc", share.ParticipantID)
		if err := os.WriteFile(filepath.Join(*outDir, name), blob, 0o600); err != nil {
			return err
		}
		manifest.Participants = append(manifest.Participants, struct {
			ParticipantID uint32 `json:"participant_id"`
			Position      uint8  `json:"position"`
			Address       string `json:"address"`
			ShareFile     string `json:"share_file"`
		}{share.ParticipantID, share.ParticipantPosition, rosterJSON[position].Address, name})
	}
	if err := os.WriteFile(filepath.Join(*outDir, "group_public_key.bin"), key.PublicKey, 0o600); err != nil {
		return err
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*outDir, "manifest.json"), manifestRaw, 0o600); err != nil {
		return err
	}
	fmt.Printf("ceremony complete: %d shares, group key %s…, activation epoch %d\n",
		len(shares), hex.EncodeToString(key.PublicKey[:8]), session.ActivationEpoch)
	return nil
}

func install(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	dataDir := fs.String("datadir", "", "validator node data directory")
	sharePath := fs.String("share", "", "encrypted share blob from the ceremony")
	transportPasswordPath := fs.String("transport-password-file", "", "file with the ceremony (transport) password")
	storePasswordPath := fs.String("store-password-file", "", "file with this validator's store password")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" || *sharePath == "" || *transportPasswordPath == "" || *storePasswordPath == "" {
		return fmt.Errorf("required: -datadir -share -transport-password-file -store-password-file")
	}
	blob, err := os.ReadFile(*sharePath)
	if err != nil {
		return err
	}
	transportPassword, err := readPasswordFile(*transportPasswordPath)
	if err != nil {
		return err
	}
	defer func() {
		for i := range transportPassword {
			transportPassword[i] = 0
		}
	}()
	storePassword, err := readPasswordFile(*storePasswordPath)
	if err != nil {
		return err
	}
	defer func() {
		for i := range storePassword {
			storePassword[i] = 0
		}
	}()
	pid, err := nodepkg.InstallOfflineCeremonyShare(*dataDir, blob, transportPassword, storePassword)
	if err != nil {
		return err
	}
	fmt.Printf("installed threshold share candidate for participant %d\n", pid)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tdil3_ceremony generate|install ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "generate":
		err = generate(os.Args[2:])
	case "install":
		err = install(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: tdil3_ceremony generate|install ...")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
