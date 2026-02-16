package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/ponder2000/guardian/internal/crypto"
	"github.com/ponder2000/guardian/internal/store"
)

// KeysData is the template data for the keys list page.
type KeysData struct {
	PageData
	Keys []store.KeyPair
}

// KeyDetailData is the template data for key detail view.
type KeyDetailData struct {
	PageData
	Key *store.KeyPair
}

// KeyFormData is the template data for the key form.
type KeyFormData struct {
	PageData
}

// Keys handles key pair management.
type Keys struct {
	store     *store.Store
	templates TemplateRenderer
	logger    *log.Logger
}

// NewKeys creates a new Keys handler.
func NewKeys(s *store.Store, t TemplateRenderer, l *log.Logger) *Keys {
	return &Keys{store: s, templates: t, logger: l}
}

// List renders the key pairs list.
func (k *Keys) List(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	keys, err := k.store.ListKeyPairs()
	if err != nil {
		k.logger.Printf("list keys: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := KeysData{
		PageData: PageData{
			Title:     "Key Pairs",
			Active:    "keys",
			User:      user,
			CSRFToken: GetCSRFToken(r),
			Flash:     r.URL.Query().Get("flash"),
		},
		Keys: keys,
	}
	k.templates.RenderPage(w, "keys_list", "base", data)
}

// GenerateForm renders the key generation form.
func (k *Keys) GenerateForm(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	data := KeyFormData{
		PageData: PageData{
			Title:     "Generate Key Pair",
			Active:    "keys",
			User:      user,
			CSRFToken: GetCSRFToken(r),
		},
	}
	k.templates.RenderPage(w, "key_form", "base", data)
}

// Generate creates a new Ed25519 key pair.
func (k *Keys) Generate(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	name := strings.TrimSpace(r.FormValue("name"))

	if name == "" {
		data := KeyFormData{
			PageData: PageData{
				Title:     "Generate Key Pair",
				Active:    "keys",
				User:      user,
				CSRFToken: GetCSRFToken(r),
				Error:     "Name is required",
			},
		}
		w.WriteHeader(http.StatusBadRequest)
		k.templates.RenderPage(w, "key_form", "base", data)
		return
	}

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		k.logger.Printf("generate key pair: %v", err)
		http.Error(w, "Failed to generate key pair", http.StatusInternalServerError)
		return
	}

	pubHex := hex.EncodeToString(kp.PublicKey)
	privHex := hex.EncodeToString(kp.PrivateKey)
	fpHash := sha256.Sum256(kp.PublicKey)
	fingerprint := hex.EncodeToString(fpHash[:])

	stored, err := k.store.CreateKeyPair(name, pubHex, privHex, fingerprint)
	if err != nil {
		data := KeyFormData{
			PageData: PageData{
				Title:     "Generate Key Pair",
				Active:    "keys",
				User:      user,
				CSRFToken: GetCSRFToken(r),
				Error:     fmt.Sprintf("Failed to store key pair: %v", err),
			},
		}
		w.WriteHeader(http.StatusBadRequest)
		k.templates.RenderPage(w, "key_form", "base", data)
		return
	}

	k.store.LogAction(user.ID, user.Username, "key.generate", "key", stored.ID,
		fmt.Sprintf(`{"name":%q,"fingerprint":%q}`, name, fingerprint), ClientIP(r))

	http.Redirect(w, r, "/keys?flash=Key+pair+generated+successfully", http.StatusSeeOther)
}

// Import handles importing existing key files.
func (k *Keys) Import(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	name := strings.TrimSpace(r.FormValue("name"))
	pubHex := strings.TrimSpace(r.FormValue("public_key"))
	privHex := strings.TrimSpace(r.FormValue("private_key"))

	if name == "" || pubHex == "" || privHex == "" {
		data := KeyFormData{
			PageData: PageData{
				Title:     "Generate Key Pair",
				Active:    "keys",
				User:      user,
				CSRFToken: GetCSRFToken(r),
				Error:     "All fields are required",
			},
		}
		w.WriteHeader(http.StatusBadRequest)
		k.templates.RenderPage(w, "key_form", "base", data)
		return
	}

	// Validate hex encoding.
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil || len(pubBytes) != 32 {
		http.Error(w, "Invalid public key (expected 32-byte hex-encoded Ed25519 key)", http.StatusBadRequest)
		return
	}

	privBytes, err := hex.DecodeString(privHex)
	if err != nil || len(privBytes) != 64 {
		http.Error(w, "Invalid private key (expected 64-byte hex-encoded Ed25519 key)", http.StatusBadRequest)
		return
	}

	fpHash := sha256.Sum256(pubBytes)
	fingerprint := hex.EncodeToString(fpHash[:])

	stored, err := k.store.CreateKeyPair(name, pubHex, privHex, fingerprint)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to store key pair: %v", err), http.StatusBadRequest)
		return
	}

	k.store.LogAction(user.ID, user.Username, "key.import", "key", stored.ID,
		fmt.Sprintf(`{"name":%q,"fingerprint":%q}`, name, fingerprint), ClientIP(r))

	http.Redirect(w, r, "/keys?flash=Key+pair+imported+successfully", http.StatusSeeOther)
}

// Detail shows key pair details.
func (k *Keys) Detail(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	id, _ := strconv.Atoi(r.PathValue("id"))

	key, err := k.store.GetKeyPair(id)
	if err != nil {
		http.Error(w, "Key pair not found", http.StatusNotFound)
		return
	}

	data := KeyDetailData{
		PageData: PageData{
			Title:     "Key: " + key.Name,
			Active:    "keys",
			User:      user,
			CSRFToken: GetCSRFToken(r),
		},
		Key: key,
	}
	k.templates.RenderPage(w, "key_detail", "base", data)
}

// SetDefault makes a key pair the default.
func (k *Keys) SetDefault(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	id, _ := strconv.Atoi(r.PathValue("id"))

	if err := k.store.SetDefaultKeyPair(id); err != nil {
		http.Error(w, "Failed to set default", http.StatusInternalServerError)
		return
	}

	k.store.LogAction(user.ID, user.Username, "key.set_default", "key", id, "", ClientIP(r))
	http.Redirect(w, r, "/keys?flash=Default+key+updated", http.StatusSeeOther)
}

// Delete removes a key pair.
func (k *Keys) Delete(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	id, _ := strconv.Atoi(r.PathValue("id"))

	if err := k.store.DeleteKeyPair(id); err != nil {
		http.Error(w, "Failed to delete key pair", http.StatusInternalServerError)
		return
	}

	k.store.LogAction(user.ID, user.Username, "key.delete", "key", id, "", ClientIP(r))
	http.Redirect(w, r, "/keys?flash=Key+pair+deleted", http.StatusSeeOther)
}

// DownloadPublic serves the public key as a downloadable file.
func (k *Keys) DownloadPublic(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	key, err := k.store.GetKeyPair(id)
	if err != nil {
		http.Error(w, "Key pair not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.pub", key.Name))
	w.Write([]byte(key.PublicKeyHex))
}
