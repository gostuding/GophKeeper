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

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"

	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Gorm connection to database.
type Storage struct {
	con *gorm.DB
}

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

// randomString generats random string
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
	passwd, err := hashPassword([]byte(pwd))
	if err != nil {
		return "", 0, err
	}
	h := md5.New()
	h.Write([]byte(randomString(128)))
	user := Users{Login: login, Pwd: string(passwd), Key: hex.EncodeToString(h.Sum(nil))}
	result := s.con.WithContext(ctx).Create(&user)
	if result.Error != nil {
		return "", 0, fmt.Errorf("sql error: %w", result.Error)
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
	result := s.con.WithContext(ctx).Order("id desc").Where("uid = ?", uid).Find(&c)
	if result.Error != nil {
		return nil, fmt.Errorf("get cards error: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return []byte("[]"), nil
	}
	type info struct {
		Id    uint   `json:"id"`
		Label string `json:"label"`
	}
	cards := make([]info, 0)
	for _, item := range c {
		cards = append(cards, info{Id: item.ID, Label: item.Label})
	}
	data, err := json.Marshal(cards)
	if err != nil {
		return nil, fmt.Errorf("cards list convert error: %w", err)
	}
	return data, nil
}

// AddCard adds new card in database
func (s *Storage) AddCard(ctx context.Context, uid uint, label, value string) error {
	card := Cards{Label: label, Value: value, UID: uid}
	result := s.con.WithContext(ctx).Create(&card)
	if result.Error != nil {
		return fmt.Errorf("add new card error: %w", result.Error)
	}
	return nil
}

// func (s *Storage) AddOrder(ctx context.Context, uid int, order string) (int, error) {
// 	var item Orders
// 	orderOk := errors.New("order ok")
// 	orderConflict := errors.New("order conflict")
// 	err := s.con.Transaction(func(tx *gorm.DB) error {
// 		result := tx.Where("number = ? ", order).First(&item)
// 		if result.Error != nil {
// 			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
// 				result := tx.Create(&Orders{UID: uid, Number: order, Status: "NEW"})
// 				if result.Error != nil {
// 					return fmt.Errorf("create order error: %w", result.Error)
// 				}
// 				return nil
// 			}
// 			return fmt.Errorf("select order error: %w", result.Error)
// 		} else {
// 			if item.UID == uid {
// 				return orderOk
// 			}
// 			return orderConflict
// 		}
// 	})
// 	switch err { //nolint:errorlint //<- wrapped errors is on default
// 	case orderConflict:
// 		return http.StatusConflict, nil
// 	case orderOk:
// 		return http.StatusOK, nil
// 	case nil:
// 		return http.StatusAccepted, nil
// 	default:
// 		return http.StatusInternalServerError, err //nolint:wrapcheck // <-wrapped early
// 	}
// }

// func (s *Storage) getValues(ctx context.Context, uid int, values any) ([]byte, error) {
// 	result := s.con.WithContext(ctx).Order("id desc").Where("uid = ?", uid).Find(values)
// 	if result.Error != nil {
// 		return nil, fmt.Errorf("get values error: %w", result.Error)
// 	}
// 	if result.RowsAffected == 0 {
// 		return nil, nil
// 	}
// 	data, err := json.Marshal(values)
// 	if err != nil {
// 		return nil, fmt.Errorf("json convert error: %w", err)
// 	}
// 	return data, nil
// }

// func (s *Storage) GetOrders(ctx context.Context, uid int) ([]byte, error) {
// 	var orders []Orders
// 	return s.getValues(ctx, uid, &orders)
// }

// func (s *Storage) GetUserBalance(ctx context.Context, uid int) ([]byte, error) {
// 	var user Users
// 	result := s.con.WithContext(ctx).Where("id = ?", uid).First(&user) //nolint:all // more clearly
// 	if result.Error != nil {
// 		return nil, fmt.Errorf("get user balance error: %w", result.Error)
// 	}
// 	data, err := json.Marshal(BalanceStruct{Current: user.Balance, Withdrawn: user.Withdrawn})
// 	if err != nil {
// 		return nil, fmt.Errorf("convert user balance to json error: %w", err)
// 	}
// 	return data, nil
// }

// func (s *Storage) AddWithdraw(ctx context.Context, uid int, order string, sum float32) (int, error) {
// 	var user Users
// 	userNorFound := errors.New("user not found in database")
// 	lowUserBalance := errors.New("low balance level")
// 	err := s.con.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
// 		result := tx.Where("id = ?", uid).First(&user)
// 		if result.Error != nil {
// 			return fmt.Errorf("get user error: %w", userNorFound)
// 		}
// 		if user.Balance < sum {
// 			return lowUserBalance
// 		}
// 		user.Balance -= sum
// 		user.Withdrawn += sum
// 		if err := tx.Save(&user).Error; err != nil {
// 			return fmt.Errorf("update user balance error: %w", err)
// 		}
// 		withdraw := Withdraws{Sum: sum, UID: int(user.ID), Number: order}
// 		if err := tx.Create(&withdraw).Error; err != nil {
// 			return fmt.Errorf("create withdraw error: %w", err)
// 		}
// 		return nil
// 	})
// 	if err != nil {
// 		if errors.Is(err, userNorFound) {
// 			return http.StatusInternalServerError, err //nolint:wrapcheck //<-wrapped early
// 		}
// 		if errors.Is(err, lowUserBalance) {
// 			return http.StatusPaymentRequired, nil
// 		}
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
// 			return http.StatusConflict, errors.New("withdraw order number repeat error")
// 		}
// 		return http.StatusInternalServerError, fmt.Errorf("transaction error: %w", err)
// 	}
// 	return http.StatusOK, nil
// }

// func (s *Storage) GetWithdraws(ctx context.Context, uid int) ([]byte, error) {
// 	var withdraws []Withdraws
// 	return s.getValues(ctx, uid, &withdraws)
// }

// func (s *Storage) GetAccrualOrders() []string {
// 	var orders []Orders
// 	result := s.con.Order("id").Where("status NOT IN ?", []string{"INVALID", "PROCESSED"}).Find(&orders)
// 	if result.Error != nil || result.RowsAffected == 0 {
// 		return nil
// 	}
// 	numbers := make([]string, 0)
// 	for _, item := range orders {
// 		numbers = append(numbers, item.Number)
// 	}
// 	return numbers
// }

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

func (s *Storage) IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		return true
	}
	return false
}
