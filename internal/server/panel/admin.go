package panel

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/store"
)

func Admin(s *store.Store, action, user string, passwordStdin bool, input io.Reader, output io.Writer) error {
	if action == "list" {
		rows, err := s.DB.Query(`SELECT user,created_at,last_login FROM admins ORDER BY user`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			var created, last int64
			if err = rows.Scan(&name, &created, &last); err != nil {
				return err
			}
			fmt.Fprintf(output, "%s\t%s\t%s\n", name, time.Unix(created, 0).UTC().Format(time.RFC3339), formatTime(last))
		}
		return rows.Err()
	}
	if !proto.ValidNode(user) {
		return fmt.Errorf("invalid username")
	}
	switch action {
	case "add", "passwd", "reset-totp", "remove":
	default:
		return fmt.Errorf("admin requires add|passwd|reset-totp|list|remove")
	}
	var password, hash, secret string
	if action == "add" || action == "passwd" {
		password = randomToken(18)
		if passwordStdin {
			scanner := bufio.NewScanner(io.LimitReader(input, 4097))
			if !scanner.Scan() {
				return fmt.Errorf("password required")
			}
			password = strings.TrimSuffix(scanner.Text(), "\r")
			if len(password) > 4096 {
				return fmt.Errorf("password too long")
			}
		}
		var err error
		hash, err = HashPassword(password)
		if err != nil {
			return err
		}
	}
	if action == "add" || action == "reset-totp" {
		secret = NewTOTPSecret()
	}
	err := s.Transaction(func(tx *sql.Tx) error {
		var result sql.Result
		var err error
		switch action {
		case "add":
			result, err = tx.Exec(`INSERT INTO admins(user,pw_hash,totp_secret,created_at) VALUES(?,?,?,?)`, user, hash, secret, time.Now().Unix())
		case "passwd":
			result, err = tx.Exec(`UPDATE admins SET pw_hash=? WHERE user=?`, hash, user)
		case "reset-totp":
			result, err = tx.Exec(`UPDATE admins SET totp_secret=?,totp_last_step=-1 WHERE user=?`, secret, user)
		case "remove":
			result, err = tx.Exec(`DELETE FROM admins WHERE user=?`, user)
		}
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count == 0 {
			return fmt.Errorf("unknown admin")
		}
		if action != "add" {
			_, err = tx.Exec(`DELETE FROM sessions WHERE user=?`, user)
		}
		return err
	})
	if err != nil {
		return err
	}
	if password != "" && !passwordStdin {
		fmt.Fprintln(output, "Password:", password)
	}
	if secret != "" {
		fmt.Fprintln(output, "TOTP secret:", secret)
		fmt.Fprintf(output, "otpauth://totp/wanglou:%s?secret=%s&issuer=wanglou&algorithm=SHA1&digits=6&period=30\n", url.PathEscape(user), secret)
	}
	return nil
}
