package storage

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// Users is Gorm struct for users info.
type (
	Users struct {
		CreatedAt time.Time
		UpdatedAt time.Time
		Login     string `gorm:"unique" `
		Pwd       string `gorm:"type:varchar(255)" `
		Key       string `gorm:"type:varchar(32)" `
		ID        uint   `gorm:"primarykey" `
	}
	// Cards is Gorm struct for user's cards information.
	// Value field contains private card's data.
	Cards struct {
		CreatedAt time.Time `json:"created"`
		UpdatedAt time.Time `json:"updated"`
		Label     string    `gorm:"unique;type:varchar(255)" json:"lablel"`
		Value     string    `gorm:"type:text" json:"value"`
		ID        uint      `gorm:"primarykey" json:"-"`
		UID       uint      `gorm:"numeric" json:"-"`
	}
	// Files is Gorm struct for user's files.
	Files struct {
		CreatedAt time.Time `json:"created"`
		Name      string    `gorm:"type:varchar(255)" json:"name"`
		FileName  string    `gorm:"type:varchar(32)" json:"-"`
		InitSize  int64     `gorm:"numeric" json:"size"`
		UID       int       `gorm:"numeric" json:"-"`
		ID        uint      `gorm:"primarykey" json:"id"`
		Crypted   bool      `gorm:"bool" json:"crypted"`
		Loaded    bool      `gorm:"bool" json:"loaded"`
	}
)

// structCheck checks database structure.
func structCheck(con *gorm.DB) error {
	err := con.AutoMigrate(&Users{}, &Cards{}, &Files{})
	if err != nil {
		return fmt.Errorf("database structure error: %w", err)
	}
	return nil
}
