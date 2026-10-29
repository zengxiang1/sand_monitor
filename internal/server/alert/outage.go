package alert

import (
	"database/sql"
	"encoding/json"
)

type receiverOutage struct {
	Since    int64                   `json:"since"`
	Detected int64                   `json:"detected"`
	Members  map[string]outageMember `json:"members"`
	Notified bool                    `json:"notified"`
}

type outageMember struct {
	LastSeen  int64 `json:"last_seen"`
	Recovered int64 `json:"recovered"`
	Outage    bool  `json:"outage"`
}

func loadOutage(tx *sql.Tx) (*receiverOutage, error) {
	var raw string
	err := tx.QueryRow(`SELECT value FROM kv WHERE key='receiver.outage'`).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var outage receiverOutage
	if err = json.Unmarshal([]byte(raw), &outage); err != nil {
		return nil, err
	}
	return &outage, nil
}

func saveOutage(tx *sql.Tx, outage *receiverOutage) error {
	body, err := json.Marshal(outage)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO kv(key,value) VALUES('receiver.outage',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, string(body))
	return err
}
