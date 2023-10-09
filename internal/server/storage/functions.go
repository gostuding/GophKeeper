package storage

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

type Users struct {
	CreatedAt time.Time `json:"-"`
	UpdatedAt time.Time `json:"-"`
	Login     string    `gorm:"unique" json:"-"`
	Pwd       string    `gorm:"type:varchar(255)" json:"-"`
	ID        uint      `gorm:"primarykey" json:"-"`
}

type Cards struct {
	CreatedAt time.Time `json:"uploaded_at"`
	UpdatedAt time.Time `json:"-"`
	Number    string    `gorm:"unique" json:"number"`
	Status    string    `gorm:"type:varchar(10)" json:"status"`
	Accrual   float32   `gorm:"type:numeric" json:"accrual,omitempty"`
	ID        uint      `gorm:"primarykey" json:"-"`
	User      Users     `json:"-"`
}

func structCheck(con *gorm.DB) error {
	err := con.AutoMigrate(&Users{}, &Cards{})
	if err != nil {
		return fmt.Errorf("database structure error: %w", err)
	}
	return nil
}
