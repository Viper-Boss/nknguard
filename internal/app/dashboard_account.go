package app

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

const dashboardAccountName = "dashboard.account"

var ErrDashboardConfigured = errors.New("管理账号已经设置，请登录后修改")

type dashboardAccount struct {
	Username string `json:"username"`
	Hash     string `json:"password_hash"`
}

func ValidateDashboardUsername(username string) error {
	if n := utf8.RuneCountInString(username); n < 3 || n > 32 {
		return errors.New("用户名需要 3–32 个字符")
	}
	for _, r := range username {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' && r != '.' {
			return errors.New("用户名可使用汉字、字母、数字及 . _ -，不能包含空格")
		}
	}
	return nil
}

func (n *Node) readDashboardAccount() (dashboardAccount, error) {
	raw, err := n.Keystore.ReadSecret(dashboardAccountName)
	if err != nil {
		return dashboardAccount{}, err
	}
	var account dashboardAccount
	if json.Unmarshal(raw, &account) != nil || ValidateDashboardUsername(account.Username) != nil {
		return account, errors.New("invalid dashboard account")
	}
	if _, err := bcrypt.Cost([]byte(account.Hash)); err != nil {
		return account, err
	}
	return account, nil
}

func (n *Node) DashboardUsername() string {
	account, err := n.readDashboardAccount()
	if errors.Is(err, fs.ErrNotExist) {
		return "admin"
	}
	if err != nil {
		return ""
	}
	return account.Username
}

// The account is one atomically replaced file, so username and password never
// become a mismatched pair. The file lock also serializes CLI and web changes.
func (n *Node) SetDashboardAccount(username, password string) error {
	lock, err := acquireInstanceLock(filepath.Join(n.Config.Paths.StateDir, "dashboard-account.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	return n.writeDashboardAccount(username, password)
}

// Recheck the current password under the same lock as the credential write.
// A concurrent reset must not let a request authenticated with the old password
// overwrite the new account.
func (n *Node) ChangeDashboardAccount(current, username, password string) error {
	lock, err := acquireInstanceLock(filepath.Join(n.Config.Paths.StateDir, "dashboard-account.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	if !n.VerifyDashboardPassword(current) {
		return errors.New("账号已变更，请使用当前密码重新登录")
	}
	return n.writeDashboardAccount(username, password)
}

func (n *Node) SetupDashboardAccount(username, password string) error {
	lock, err := acquireInstanceLock(filepath.Join(n.Config.Paths.StateDir, "dashboard-account.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	if n.DashboardPasswordReady() {
		return ErrDashboardConfigured
	}
	if err := ValidateDashboardPassword(password); err != nil {
		return err
	}
	return n.writeDashboardAccount(username, password)
}

func (n *Node) writeDashboardAccount(username, password string) error {
	if err := ValidateDashboardUsername(username); err != nil {
		return err
	}
	var hash []byte
	if password != "" {
		if err := ValidateDashboardPassword(password); err != nil {
			return err
		}
		var err error
		hash, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
	} else {
		account, err := n.readDashboardAccount()
		if err == nil {
			hash = []byte(account.Hash)
		} else if errors.Is(err, fs.ErrNotExist) {
			hash, err = n.Keystore.ReadSecret(dashboardPasswordName)
			if errors.Is(err, fs.ErrNotExist) {
				legacy, readErr := n.Keystore.ReadSecret(dashboardKeyName)
				if readErr != nil {
					return readErr
				}
				hash, err = bcrypt.GenerateFromPassword(legacy, bcrypt.DefaultCost)
			}
			if err != nil {
				return err
			}
		} else {
			return err
		}
		if _, err := bcrypt.Cost(hash); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(dashboardAccount{Username: username, Hash: string(hash)})
	if err != nil {
		return err
	}
	if err := n.Keystore.WriteSecret(dashboardAccountName, raw); err != nil {
		return err
	}
	for _, name := range []string{dashboardPasswordName, dashboardKeyName} {
		if err := os.Remove(filepath.Join(n.Keystore.Dir(), name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if note := n.Config.Paths.LegacySetupNote; note != "" {
		if err := os.Remove(note); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}
