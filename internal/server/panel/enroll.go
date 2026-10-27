package panel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/requestip"
	"wanglou/internal/server/store"
)

type enrollment struct {
	Name, Note, Pubkey, Hash, Code string
	Expires                        int64
}

func enrollmentCipher(key string) cipher.AEAD {
	derived := sha256.Sum256([]byte("wanglou-enroll-v1\n" + key))
	block, _ := aes.NewCipher(derived[:])
	gcm, _ := cipher.NewGCMWithRandomNonce(block)
	return gcm
}
func sealEnrollment(value enrollment, csrf, key string) string {
	data, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(enrollmentCipher(key).Seal(nil, nil, data, []byte(csrf)))
}
func readEnrollment(value, csrf, key string, now time.Time) (enrollment, error) {
	var state enrollment
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return state, fmt.Errorf("接入信息无效，请重新开始")
	}
	data, err := enrollmentCipher(key).Open(nil, nil, payload, []byte(csrf))
	if err != nil {
		return state, fmt.Errorf("接入信息无效，请重新开始")
	}
	if err = json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	if state.Expires <= now.Unix() {
		return state, fmt.Errorf("注册码或预览已过期，请重新开始")
	}
	return state, nil
}
func (h *Handler) enroll(w http.ResponseWriter, r *http.Request, sess session, action string) {
	data := h.base(sess)
	data.PublicURL = h.Config.PublicIngestURL
	if data.PublicURL == "" {
		data.PublicURL = "<接收端地址>"
	}
	now := h.Now()
	state := enrollment{}
	if enabled := r.URL.Query().Get("enabled"); enabled != "" {
		if node, err := h.Store.Node(enabled); err == nil {
			data.Success = node.Name
			data.NodeLink = "/nodes/" + node.Name
		}
	}
	token := r.URL.Query().Get("state")
	if r.Method == "POST" {
		token = r.PostForm.Get("state")
	}
	if token != "" {
		var err error
		state, err = readEnrollment(token, sess.CSRF, h.signingKey, now)

		if err != nil {
			if r.Method != "GET" {
				http.Error(w, err.Error(), 400)
				return
			}
			data.Error = "接入信息已失效，请重新生成注册码或粘贴公钥。"
			state = enrollment{Name: state.Name, Note: state.Note}
		}
	}
	if action == "codes" || action == "preview" {
		state = enrollment{Name: r.PostForm.Get("name"), Note: r.PostForm.Get("note"), Expires: now.Add(10 * time.Minute).Unix()}
		if !proto.ValidNode(state.Name) || !safeNote(state.Note) {
			http.Error(w, "节点名或备注无效", 400)
			return
		}
		_, err := h.Store.Node(state.Name)
		if err == nil {
			http.Error(w, "节点名已被占用", 409)
			return
		}
		if err != sql.ErrNoRows {
			h.serverError(w, err)
			return
		}
		if action == "preview" {
			key, err := proto.ParsePublicKey(r.PostForm.Get("pubkey"))
			if err != nil || strings.Fields(r.PostForm.Get("pubkey"))[2] != state.Name {
				http.Error(w, "公钥行中的名称必须与节点名一致", 400)
				return
			}
			state.Pubkey = proto.PublicKeyLine(key, state.Name)
		} else {
			const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
			random := randomBytes(8)
			var code strings.Builder
			for i, b := range random {
				if i == 4 {
					code.WriteByte('-')
				}
				code.WriteByte(alphabet[int(b)&31])
			}
			state.Code = code.String()
			state.Hash = store.TokenHash(state.Code)
			err = h.Store.Transaction(func(tx *sql.Tx) error {
				if _, err := tx.Exec(`INSERT INTO enroll_codes(code_hash,name,note,created_at,expires_at) VALUES(?,?,?,?,?)`, state.Hash, state.Name, state.Note, now.Unix(), state.Expires); err != nil {
					return err
				}
				_, err := tx.Exec(`INSERT INTO audit_log(ts,user,ip,action,detail) VALUES(?,?,?,?,?)`, now.Unix(), sess.User, requestip.ClientIP(r, h.Config.TrustedProxies), "enroll_code", state.Name)
				return err
			})
			if err != nil {
				h.serverError(w, err)
				return
			}
			http.Redirect(w, r, "/enroll?state="+url.QueryEscape(sealEnrollment(state, sess.CSRF, h.signingKey)), 303)
			return
		}
		http.Redirect(w, r, "/enroll?state="+url.QueryEscape(sealEnrollment(state, sess.CSRF, h.signingKey)), 303)
		return
	}
	if action == "confirm" {
		if token == "" || state.Pubkey == "" || r.PostForm.Get("matched") != "yes" || r.PostForm.Get("pubkey") != state.Pubkey {
			http.Error(w, "请核对指纹，公钥必须与预览一致", 400)
			return
		}
		err := h.Store.ConfirmEnrollment(state.Name, state.Note, state.Pubkey, state.Hash, now, sess.User, requestip.ClientIP(r, h.Config.TrustedProxies))
		if err != nil {
			http.Error(w, "无法启用：节点名已占用、注册码已过期或公钥不一致", 400)
			return
		}
		http.Redirect(w, r, "/enroll?enabled="+url.QueryEscape(state.Name), 303)
		return
	}
	if state.Hash != "" {
		var line string
		err := h.Store.DB.QueryRow(`SELECT pubkey FROM enroll_codes WHERE code_hash=? AND expires_at>?`, state.Hash, now.Unix()).Scan(&line)
		if err == sql.ErrNoRows {
			data.Error = "注册码已过期或已确认，请重新生成注册码或粘贴公钥。"
			state = enrollment{Name: state.Name, Note: state.Note}
		} else if err != nil {
			h.serverError(w, err)
			return
		} else {
			state.Pubkey = line
		}
	}
	data.Name = state.Name
	data.Note = state.Note
	data.Code = state.Code
	data.Pubkey = state.Pubkey
	data.Expires = state.Expires
	remaining := max(int64(0), state.Expires-now.Unix())
	data.Remaining = fmt.Sprintf("%d:%02d", remaining/60, remaining%60)
	if data.Name == "" {
		data.Name = r.URL.Query().Get("name")
		data.Note = r.URL.Query().Get("note")
		if !proto.ValidNode(data.Name) {
			data.Name = "node-01"
		}
		if !safeNote(data.Note) {
			data.Note = ""
		}
	}
	data.Command = fmt.Sprintf("sudo wanglou-agent init --name %s --server '%s'", data.Name, strings.ReplaceAll(data.PublicURL, "'", "'\\''"))
	if strings.HasPrefix(data.PublicURL, "http:") {
		data.Command += " --insecure-http"
	}
	if state.Expires > now.Unix() {
		data.State = sealEnrollment(state, sess.CSRF, h.signingKey)
	}
	if state.Pubkey != "" {
		key, err := proto.ParsePublicKey(state.Pubkey)
		if err != nil {
			h.serverError(w, err)
			return
		}
		fingerprint := strings.TrimPrefix(proto.Fingerprint(key), "SHA256:")
		for len(fingerprint) > 0 {
			end := min(4, len(fingerprint))
			data.Fingerprint = append(data.Fingerprint, fingerprint[:end])
			fingerprint = fingerprint[end:]
		}
	}
	h.render(w, r, "enroll", data, 200)
}
