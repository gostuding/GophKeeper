package storage

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"

	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	emptyJSON  = "[]"
	uidInQuery = "uid = ?"
	idOrder    = "id desc"
)

type (
	// Storage is struct for Gorm connection to database.
	Storage struct {
		con *gorm.DB
	}
	// SendCardsInfo struct sends card's information to clients.
	sendCardsInfo struct {
		Update time.Time `json:"updated"`
		Label  string    `json:"label,omitempty"`
		Info   string    `json:"info,omitempty"`
		ID     uint      `json:"id,omitempty"`
	}
)

// NewStorage creates and checks database connection.
func NewStorage(dsn string, maxCon int) (*Storage, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("pqx database connection error: %w", err)
	}
	db.SetMaxOpenConns(maxCon)
	con, err := gorm.Open(postgres.New(postgres.Config{Conn: db}), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("gorm open connection error: %w", err)
	}
	storage := Storage{
		con: con,
	}
	return &storage, structCheck(con)
}

// randomString generats random string.
func randomString(length int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// Registration new users and returns it's id in database.
func (s *Storage) Registration(
	ctx context.Context,
	login,
	pwd string,
) (string, int, error) {
	var r = 128
	passwd, err := hashPassword([]byte(pwd))
	if err != nil {
		return "", 0, err
	}
	h := md5.New()
	h.Write([]byte(randomString(r)))
	user := Users{Login: login, Pwd: string(passwd), Key: hex.EncodeToString(h.Sum(nil))}
	result := s.con.WithContext(ctx).Create(&user)
	if result.Error != nil {
		return "", 0, makeError(ErrDatabase, result.Error)
	}
	return user.Key, int(user.ID), nil
}

// hashPassword creates hash from password string.
func hashPassword(pwd []byte) ([]byte, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("password hash error: %w", err)
	}
	return hashedPassword, nil
}

// Login checks user data in database.
func (s *Storage) Login(
	ctx context.Context,
	login, pwd string,
) (string, int, error) {
	var user Users
	result := s.con.WithContext(ctx).Where("login = ?", login).First(&user)
	if result.Error != nil {
		return "", 0, fmt.Errorf("user login error: %w", result.Error)
	}
	err := bcrypt.CompareHashAndPassword([]byte(user.Pwd), []byte(pwd))
	if err != nil {
		return "", 0, gorm.ErrRecordNotFound
	}
	return user.Key, int(user.ID), nil
}

// GetCardsList returns users cards json.
func (s *Storage) GetCardsList(ctx context.Context, uid uint) ([]byte, error) {
	var c []Cards
	result := s.con.WithContext(ctx).Order(idOrder).Where(uidInQuery, uid).Find(&c)
	if result.Error != nil {
		return nil, makeError(ErrDatabase, result.Error)
	}
	if result.RowsAffected == 0 {
		return []byte(emptyJSON), nil
	}
	cards := make([]sendCardsInfo, 0)
	for _, item := range c {
		cards = append(cards, sendCardsInfo{ID: item.ID, Label: item.Label, Update: item.UpdatedAt})
	}
	data, err := json.Marshal(cards)
	if err != nil {
		return nil, makeError(ErrJSONMarshal, err)
	}
	return data, nil
}

// GetCard returns full info about one user's card.
func (s *Storage) GetCard(ctx context.Context, id, uid uint) ([]byte, error) {
	c := Cards{UID: uid, ID: id}
	result := s.con.WithContext(ctx).First(&c)
	if result.Error != nil {
		return nil, makeError(ErrDatabase, result.Error)
	}
	card := sendCardsInfo{Label: c.Label, Info: c.Value, Update: c.UpdatedAt}
	data, err := json.Marshal(&card)
	if err != nil {
		return nil, fmt.Errorf("card info convert error: %w", err)
	}
	return data, nil
}

// AddCard adds new card in database.
func (s *Storage) AddCard(ctx context.Context, uid uint, label, value string) error {
	card := Cards{Label: label, Value: value, UID: uid}
	result := s.con.WithContext(ctx).Create(&card)
	if result.Error != nil {
		return makeError(ErrDatabase, result.Error)
	}
	return nil
}

// DeleteCard deletes info about one user's card.
func (s *Storage) DeleteCard(ctx context.Context, id, uid uint) error {
	c := Cards{UID: uid, ID: id}
	result := s.con.WithContext(ctx).Delete(&c)
	if result.Error != nil {
		return makeError(ErrDatabase, result.Error)
	}
	return nil
}

// UpdateCard updates user's card information.
func (s *Storage) UpdateCard(
	ctx context.Context,
	id, uid uint,
	label, value string,
) error {
	c := Cards{UID: uid, ID: id}
	result := s.con.WithContext(ctx).Model(&c).Updates(Cards{Label: label, Value: value})
	if result.Error != nil {
		return makeError(ErrDatabase, result.Error)
	}
	return nil
}

// GetFilesList returns users cards json.
func (s *Storage) GetFilesList(ctx context.Context, uid uint) ([]byte, error) {
	var f []Files
	result := s.con.WithContext(ctx).Order(idOrder).Where(uidInQuery, uid).Find(&f)
	if result.Error != nil {
		return nil, makeError(ErrDatabase, result.Error)
	}
	if result.RowsAffected == 0 {
		return []byte(emptyJSON), nil
	}
	data, err := json.Marshal(f)
	if err != nil {
		return nil, makeError(ErrJSONMarshal, err)
	}
	return data, nil
}

// AddFile writes file info in database and returns new id for file.
func (s *Storage) AddFile(ctx context.Context, uid uint, data []byte) ([]byte, error) {
	var f Files
	err := json.Unmarshal(data, &f)
	if err != nil {
		return nil, makeError(ErrJSONUnmarshal, err)
	}
	f.UID = int(uid)
	result := s.con.WithContext(ctx).Create(&f)
	if result.Error != nil {
		return nil, makeError(ErrDatabase, result.Error)
	}
	return []byte(strconv.Itoa(int(f.ID))), nil
}

// AddFileData writes new one data in database.
func (s *Storage) AddFileData(
	ctx context.Context,
	uid, fid uint,
	index, pos, size int,
	data []byte,
) error {
	f := FileData{Index: index, Pos: pos, Size: size, UID: uid, FID: fid, Data: data}
	result := s.con.WithContext(ctx).Create(&f)
	if result.Error != nil {
		return makeError(ErrDatabase, result.Error)
	}
	return nil
}

// AddFileFinish sets file loaded flag.
func (s *Storage) AddFileFinish(
	ctx context.Context,
	id, uid uint,
) error {
	c := Files{ID: id, UID: int(uid)}
	result := s.con.WithContext(ctx).Model(&c).Updates(Files{Loaded: true})
	if result.Error != nil {
		return makeError(ErrDatabase, result.Error)
	}
	return nil
}

// func (s *Storage) SetOrderData(number string, status string, balance float32) error {
// 	var order Orders
// 	var user Users
// 	err := s.con.Transaction(func(tx *gorm.DB) error {
// 		result := tx.Where("number = ?", number).First(&order)
// 		if result.Error != nil {
// 			return fmt.Errorf("update order status, get order (%s) error: %w", number, result.Error)
// 		}
// 		result = tx.Where("id = ?", order.UID).First(&user)
// 		if result.Error != nil {
// 			return fmt.Errorf("update order status, get user (%d) error: %w", order.UID, result.Error)
// 		}
// 		user.Balance += balance
// 		order.Status = status
// 		order.Accrual = balance
// 		if err := tx.Save(&user).Error; err != nil {
// 			return fmt.Errorf("user balance update error: %w", err)
// 		}
// 		if err := tx.Save(&order).Error; err != nil {
// 			return fmt.Errorf("update order status and accural error: %w", err)
// 		}
// 		return nil
// 	})
// 	if err != nil {
// 		return fmt.Errorf("update order status transaction error: %w", err)
// 	}
// 	return nil
// }

// Close closes connection to database.
func (s *Storage) Close() error {
	db, err := s.con.DB()
	if err != nil {
		return fmt.Errorf("get db from gorm error: %w", err)
	}
	err = db.Close()
	if err != nil {
		return fmt.Errorf("close db connection error: %w", err)
	}
	return nil
}

// IsUniqueViolation checks error on uniqueViolation.
func (s *Storage) IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		return true
	}
	return false
}
