package store

import "github.com/JohnNON/goJAN/internal/app/model"

// UserRepository - интерфейс, описывающий хранилище пользователя
type UserRepository interface {
	Create(*model.User) error
	Find(int) (*model.User, error)
	FindByEmail(string) (*model.User, error)
}
