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
	"os"
	"path"
	"strconv"

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
	fileMode   = 0740
)

type (
	// Storage is struct for Gorm connection to database.
	Storage struct {
		con  *gorm.DB // connection to database
		Path string   // file storage path
	}
	userKeyData struct {
		Key         string `json:"key"`            // Server's part of user's encrypt key.
		Checker     string `json:"checker_string"` // Check string for user's path of key.
		InitChecker string `json:"checker_old"`    //
	}
)

// NewStorage creates and checks database connection.
func NewStorage(dsn string, maxCon int, spath string) (*Storage, error) {
	f, err := os.Stat(spath)
	if err != nil {
		return nil, fmt.Errorf("file storage path error: %w", err)
	}
	if !f.IsDir() {
		return nil, fmt.Errorf("file storage is not a dir")
	}
	tmp := path.Join(spath, "tmp")
	if err = os.Mkdir(tmp, fileMode); err != nil {
		return nil, fmt.Errorf("file storage write temp dir error: %w", err)
	}
	if err = os.Remove(tmp); err != nil {
		return nil, fmt.Errorf("file storage delete temp dir error: %w", err)
	}

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
		con:  con,
		Path: spath,
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

// GetKey sends part of the key to user.
func (s *Storage) GetKey(ctx context.Context, uid uint) ([]byte, error) {
	var usr Users
	res := s.con.WithContext(ctx).Where("id = ?", uid).First(&usr)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return nil, gorm.ErrRecordNotFound
		}
		return nil, fmt.Errorf("get key error: %w: %w", ErrDB, res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	keyData := userKeyData{Key: usr.Key, Checker: usr.CheckKey}
	data, err := json.Marshal(keyData)
	if err != nil {
		return nil, fmt.Errorf("key data marshal error: %w", err)
	}
	return data, nil
}

// SetKey checks data and sets part of the key to user.
func (s *Storage) SetKey(ctx context.Context, uid uint, data []byte) error {
	var usr Users
	res := s.con.WithContext(ctx).Where("id = ?", uid).First(&usr)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return gorm.ErrRecordNotFound
		}
		return makeError(ErrDatabase, res.Error)
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	var k userKeyData
	if err := json.Unmarshal(data, &k); err != nil {
		return makeError(ErrJSONUnmarshal, err)
	}
	if usr.CheckKey != k.InitChecker {
		return ErrKeysNotEqual
	}
	r := s.con.WithContext(ctx).Where(&Users{ID: usr.ID}).Updates(Users{Key: k.Key, CheckKey: k.Checker})
	if r.Error != nil {
		return makeError(ErrDatabase, r.Error)
	}
	return nil
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
	// user := Users{Login: login, Pwd: string(passwd), Key: hex.EncodeToString(h.Sum(nil))}
	user := Users{Login: login, Pwd: string(passwd)}
	result := s.con.WithContext(ctx).Create(&user)
	if result.Error != nil {
		return "", 0, makeError(ErrDatabase, result.Error)
	}
	h := md5.New()
	h.Write([]byte(randomString(r)))
	return hex.EncodeToString(h.Sum(nil)), int(user.ID), nil
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

// GetTextValues returns users cards json.
func (s *Storage) GetTextValues(ctx context.Context, t string, uid uint) ([]byte, error) {
	values := make([]SendDataInfo, 0)
	var result *gorm.DB
	var data []byte
	var err error
	switch t {
	case CardsType:
		var c []Cards
		result = s.con.WithContext(ctx).Order(idOrder).Where(uidInQuery, uid).Find(&c)
		for _, item := range c {
			values = append(values, SendDataInfo{ID: item.ID, Label: item.Label, UpdatedAt: item.UpdatedAt})
		}
	case CredsType:
		var c []CredsInfo
		result = s.con.WithContext(ctx).Order(idOrder).Where(uidInQuery, uid).Find(&c)
		for _, item := range c {
			values = append(values, SendDataInfo{ID: item.ID, Label: item.Label, UpdatedAt: item.UpdatedAt})
		}
	case DatasType:
		result = s.con.WithContext(ctx).Order(idOrder).Where(uidInQuery, uid).Find(&values)
	case FilesType:
		var f []Files
		result = s.con.WithContext(ctx).Order(idOrder).Where(uidInQuery, uid).Find(&f)
		data, err = json.Marshal(f)
		if err != nil {
			return nil, makeError(ErrJSONMarshal, err)
		}
	default:
		return nil, ErrUndefindedType
	}
	if result.Error != nil {
		return nil, fmt.Errorf("get values error: %w: %w", ErrDB, result.Error)
	}
	if result.RowsAffected == 0 {
		return []byte(emptyJSON), nil
	}
	if data == nil {
		data, err = json.Marshal(values)
		if err != nil {
			return nil, makeError(ErrJSONMarshal, err)
		}
	}
	return data, nil
}

// GetValue returns full info about one item.
func (s *Storage) GetValue(ctx context.Context, t string, id, uid uint) ([]byte, error) {
	var value SendDataInfo
	var result *gorm.DB
	switch t {
	case CardsType:
		c := Cards{}
		result = s.con.WithContext(ctx).Where(&Cards{UID: uid, ID: id}).First(&c)
		value.Label = c.Label
		value.Info = c.Value
		value.UpdatedAt = c.UpdatedAt
	case DatasType:
		result = s.con.WithContext(ctx).Where(&SendDataInfo{UID: uid, ID: id}).First(&value)
	case CredsType:
		c := CredsInfo{}
		result = s.con.WithContext(ctx).Where(&CredsInfo{UID: uid, ID: id}).First(&c)
		value.Label = c.Label
		value.Info = c.Info
		value.UpdatedAt = c.UpdatedAt
	default:
		return nil, ErrUndefindedType
	}
	if result.Error != nil {
		return nil, makeError(ErrDatabase, result.Error)
	}
	data, err := json.Marshal(&value)
	if err != nil {
		return nil, fmt.Errorf("info convert error: %w", err)
	}
	return data, nil
}

// AddTextValue adds new credential, card or datainfo object in database.
func (s *Storage) AddTextValue(ctx context.Context, obj any, uid uint, label, value string) error {
	var result *gorm.DB
	switch obj.(type) {
	case Cards:
		result = s.con.WithContext(ctx).Create(&Cards{Label: label, Value: value, UID: uid})
	case SendDataInfo:
		result = s.con.WithContext(ctx).Create(&SendDataInfo{Label: label, Info: value, UID: uid})
	case CredsInfo:
		result = s.con.WithContext(ctx).Create(&CredsInfo{Label: label, Info: value, UID: uid})
	default:
		return ErrUndefindedType
	}
	if result.Error != nil {
		return fmt.Errorf("add value error: %w: %w", ErrDB, result.Error)
	}
	return nil
}

// DeleteValue deletes info about one user's item.
func (s *Storage) DeleteValue(ctx context.Context, obj any) error {
	var result *gorm.DB
	switch x := obj.(type) {
	case Cards, *SendDataInfo, CredsInfo:
		result = s.con.WithContext(ctx).Delete(&obj)
		if result.Error != nil {
			return makeError(ErrDatabase, result.Error)
		}
	case Files:
		err := s.con.Transaction(func(tx *gorm.DB) error {
			result := tx.WithContext(ctx).Where(&FileData{UID: uint(x.UID), FID: x.ID}).Delete(&FileData{})
			if result.Error != nil {
				return makeError(ErrDatabase, result.Error)
			}
			result = tx.WithContext(ctx).Delete(&obj)
			if result.Error != nil {
				return makeError(ErrDatabase, result.Error)
			}
			err := os.RemoveAll(path.Join(s.Path, strconv.Itoa(x.UID), strconv.Itoa(int(x.ID))))
			if err != nil {
				return fmt.Errorf("file storage error: %w", err)
			}
			return nil
		})
		if err != nil {
			return makeError(ErrDatabase, err)
		}
	default:
		return ErrUndefindedType
	}
	return nil
}

// UpdateTextValue updates user's card information.
func (s *Storage) UpdateTextValue(ctx context.Context, obj any,
	id, uid uint, label, value string) error {
	var result *gorm.DB
	var itemID uint
	switch obj.(type) {
	case Cards:
		c := Cards{UID: uid, ID: id}
		result = s.con.WithContext(ctx).Where(&c).First(&c)
		itemID = c.ID
	case SendDataInfo:
		c := SendDataInfo{UID: uid, ID: id}
		result = s.con.WithContext(ctx).Where(&c).First(&c)
		itemID = c.ID
	case CredsInfo:
		c := CredsInfo{UID: uid, ID: id}
		result = s.con.WithContext(ctx).Where(&c).First(&c)
		itemID = c.ID
	default:
		return ErrUndefindedType
	}
	if result.Error != nil {
		return gorm.ErrRecordNotFound
	}
	switch obj.(type) {
	case Cards:
		result = s.con.WithContext(ctx).Where(&Cards{ID: itemID}).Updates(Cards{Label: label, Value: value})
	case SendDataInfo:
		result = s.con.WithContext(ctx).Where(&SendDataInfo{ID: itemID}).Updates(SendDataInfo{Label: label, Info: value})
	case CredsInfo:
		result = s.con.WithContext(ctx).Where(&CredsInfo{ID: itemID}).Updates(CredsInfo{Label: label, Info: value})
	}
	if result.Error != nil {
		return makeError(ErrDatabase, result.Error)
	}
	return nil
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
	err = os.MkdirAll(path.Join(s.Path, strconv.Itoa(int(uid)), strconv.Itoa(int(f.ID))), fileMode)
	if err != nil {
		s.con.Delete(f)
		return nil, fmt.Errorf("storage create dir error: %w", err)
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
	name := path.Join(s.Path, strconv.Itoa(int(uid)), strconv.Itoa(int(fid)), strconv.Itoa(index))
	if err := os.WriteFile(name, data, fileMode); err != nil {
		return fmt.Errorf("write file data error: %w", err)
	}
	f := FileData{Index: index, Pos: pos, Size: size, UID: uid, FID: fid}
	result := s.con.WithContext(ctx).Create(&f)
	if result.Error != nil {
		return makeError(ErrDatabase, result.Error)
	}
	return nil
}

// AddFileFinish sets file loaded flag.
func (s *Storage) AddFileFinish(
	ctx context.Context,
	id uint,
	uid int,
) error {
	c := Files{ID: id, UID: uid}
	result := s.con.WithContext(ctx).Model(&c).Updates(Files{Loaded: true})
	if result.Error != nil {
		return makeError(ErrDatabase, result.Error)
	}
	return nil
}

// GetPreloadFileInfo returns info about file from database.
func (s *Storage) GetPreloadFileInfo(ctx context.Context, id uint, uid int) ([]byte, error) {
	file := Files{}
	result := s.con.WithContext(ctx).Where(&Files{UID: uid, ID: id}).First(&file)
	if result.Error != nil {
		return nil, makeError(ErrDatabase, result.Error)
	}
	var maxIndex int
	row := s.con.WithContext(ctx).Model(&FileData{}).Where(&FileData{UID: uint(uid), FID: file.ID}).Select("max(index)")
	if row.Error != nil {
		return nil, makeError(ErrDatabase, result.Error)
	}
	result = row.Scan(&maxIndex)
	if result.Error != nil {
		return nil, makeError(ErrDatabase, result.Error)
	}
	v := fmt.Sprintf(`{"name": "%s", "maxindex": %d}`, file.Name, maxIndex)
	return []byte(v), nil
}

// GetFileData returns one file data from file store.
func (s *Storage) GetFileData(id int, uid int, index int) ([]byte, error) {
	data, err := os.ReadFile(path.Join(s.Path, strconv.Itoa(uid), strconv.Itoa(id), strconv.Itoa(index)))
	if err != nil {
		return nil, fmt.Errorf("read file index error: %w", err)
	}
	return data, nil
}

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
