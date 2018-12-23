package csrf

import (
	"database/sql"
	"time"
)

type Storage struct {
	filepath string
	base     *sql.DB
}

func NewStorage(filepath string) *Storage {
	return &Storage{filepath, nil}
}

func (s *Storage) CreateTables() error {
	database, err := sql.Open("sqlite3", s.filepath)

	if err != nil {
		return err
	}

	s.base = database

	for _, table := range tables {
		_, err = s.base.Exec("CREATE TABLE IF NOT EXISTS csrftokens (userid INTEGER, end DATETIME, token varchar(255));")
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Storage) SaveCSRF(csrf *CSRF) error {
	_, err := s.base.Exec("INSERT INTO csrftokens (userid, end, token) VALUES ($1, $2, $3);", csrf.UserID, csrf.End, csrf.Token)

	if err != nil {
		return err
	}
	return nil
}

func (s *Storage) GetCSRFByToken(token string) (*CSRF, error) {
	rows, err := s.base.Query("SELECT * FROM csrftokens WHERE token=$1;", token)

	if err != nil {
		return &CSRF{}, err
	}

	var userid uint
	var end time.Time
	var tk string

	if rows.Next() {
		err = rows.Scan(&userid, &end, &tk)

		if err != nil {
			return &CSRF{}, err
		}
	}
	return &CSRF{userid, end, token}, nil
}

func (s *Storage) DeleteCSRF(csrf *CSRF) error {
	_, err := s.base.Exec("DELETE FROM csrftokens WHERE token=$1;", csrf.Token)

	if err != nil {
		return err
	}
	return nil
}
