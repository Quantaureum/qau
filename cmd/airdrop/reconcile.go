// Quantaureum Node source, version 1.0.0.
// airdrop: startup reconciliation of stuck payout rows.
//
// A crashed distributor run can leave a registration in the reserved or
// broadcast state (a "stuck" row): the reservation was claimed but the
// receipt was never written back. Before paying anything new, the distributor
// settles these rows against the chain:
//
//	a row whose recorded reveal transaction confirmed with status 0x1 is
//	written back as paid; a row whose reveal provably reverted is released for
//	a later attempt; a row with no recorded transaction (a crash before the
//	intent write) is released so a fresh attempt can claim it. A row whose
//	transaction is still genuinely in flight is left alone.
//
// Only rows not confirmed within the reconcile grace window are touched, so a
// healthy run is never yanked out from under itself.

package main

import (
	"fmt"
	"strings"
	"time"
)

func reconcileStuck(s *signer, cfg config) {
	var stuck struct {
		Success      bool `json:"success"`
		Reservations []struct {
			ID        int     `json:"id"`
			TxHash    *string `json:"txHash"`
			State     string  `json:"state"`
			UpdatedAt *string `json:"updatedAt"`
		} `json:"reservations"`
	}
	if err := siteRequest(cfg.siteURL, "/api/airdrop/admin/stuck?limit=500",
		cfg.adminKey, "GET", nil, &stuck); err != nil {
		fmt.Printf("reconcile: fetch stuck list: %v (skipping)\n", err)
		return
	}
	if !stuck.Success {
		fmt.Println("reconcile: website returned a failure status (skipping)")
		return
	}

	now := time.Now()
	for _, r := range stuck.Reservations {
		// Skip rows touched very recently: a live run may still be settling
		// them and yanking them out early risks a second attempt.
		if r.UpdatedAt != nil {
			if t, err := time.Parse(time.RFC3339, *r.UpdatedAt); err == nil {
				if now.Sub(t) < cfg.reconcileGrace {
					fmt.Printf("reconcile: #%d in %s state within grace — leaving alone\n", r.ID, r.State)
					continue
				}
			}
		}

		if r.TxHash == nil || *r.TxHash == "" {
			// Reserved but no transaction was recorded: the reveal never even
			// reached the intent step. Nothing moved for this row, so release
			// it for a later attempt.
			fmt.Printf("reconcile: #%d reserved with no recorded tx — releasing\n", r.ID)
			failItem(cfg, r.ID, "reconcile: stale reservation, no broadcast intent recorded")
			continue
		}

		// The intent step recorded the reveal hash. Ask the chain for its fate.
		txHash := *r.TxHash
		if !strings.HasPrefix(txHash, "0x") {
			txHash = "0x" + txHash
		}
		confirmed, succeeded := s.receiptStatus(txHash)
		switch {
		case confirmed && succeeded:
			fmt.Printf("reconcile: #%d confirm tx %s — marking paid\n", r.ID, txHash)
			_ = siteRequest(cfg.siteURL, "/api/airdrop/admin/record",
				cfg.adminKey, "POST", map[string]any{"id": r.ID, "phase": "paid", "txHash": txHash}, nil)
		case confirmed && !succeeded:
			fmt.Printf("reconcile: #%d reveal %s reverted on chain — releasing\n", r.ID, txHash)
			failItem(cfg, r.ID, "reconcile: reveal tx reverted on chain ("+txHash+")")
		default:
			// No receipt yet: the reveal may still be in flight. Leave it; the
			// next run's reconciliation will pick it up once the receipt lands.
			fmt.Printf("reconcile: #%d tx %s has no receipt yet — leaving in flight\n", r.ID, txHash)
		}
	}
}
