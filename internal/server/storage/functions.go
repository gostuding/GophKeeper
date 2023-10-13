package storage

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

type Users struct {
	CreatedAt time.Time
	UpdatedAt time.Time
	Login     string `gorm:"unique" `
	Pwd       string `gorm:"type:varchar(255)" `
	Key       string `gorm:"type:varchar(32)" `
	ID        uint   `gorm:"primarykey" `
}

type Cards struct {
	CreatedAt time.Time `json:"created"`
	UpdatedAt time.Time `json:"updated"`
	Label     string    `gorm:"unique;type:varchar(255)" json:"lablel"`
	Value     string    `gorm:"type:text" json:"value"`
	ID        uint      `gorm:"primarykey" json:"-"`
	UID       uint      `gorm:"numeric" json:"-"`
}

// structCheck checks database structure.
func structCheck(con *gorm.DB) error {
	err := con.AutoMigrate(&Users{}, &Cards{})
	if err != nil {
		return fmt.Errorf("database structure error: %w", err)
	}
	return nil
}
