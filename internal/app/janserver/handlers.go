package janserver

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"text/template"
	"time"

	"github.com/JohnNON/goJAN/internal/app/model"
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/gorilla/csrf"
	"github.com/gorilla/schema"
)

const (
	win  = "Win"
	cont = "Continue"
)

var funcMap = template.FuncMap{
	"add": func(a, b int) int {
		return a + b
	},
	"formated": func(t int) string {
		var h int = int((time.Duration(t) * time.Second).Hours())
		var m int = int((time.Duration(t) * time.Second).Minutes()) % 60
		var s int = (t % 3600) % 60
		var str string
		if h < 10 {
			str = str + "0"
		}
		str = str + strconv.Itoa(h) + ":"

		if m < 10 {
			str = str + "0"
		}
		str = str + strconv.Itoa(m) + ":"

		if s < 10 {
			str = str + "0"
		}
		str = str + strconv.Itoa(s)

		return str
	},
}

func renderTemplate(s string) (*template.Template, error) {
	return template.ParseFiles(
		s,
		"./internal/templates/head.html",
		"./internal/templates/header.html",
		"./internal/templates/message.html",
		"./internal/templates/scripts.html",
		"./internal/templates/base.html")
}

func renderFuncTemplate(s string) (*template.Template, error) {
	tmpl := template.New(s)
	tmpl.Funcs(funcMap)
	return tmpl.ParseFiles(
		s,
		"./internal/templates/head.html",
		"./internal/templates/header.html",
		"./internal/templates/message.html",
		"./internal/templates/scripts.html",
		"./internal/templates/base.html")
}

func (s *server) handleLogin() http.HandlerFunc {
	type login struct {
		Email    string
		Password string
		_        string `schema:"Csrf"`
	}

	validateLogin := func(user *login) error {
		return validation.ValidateStruct(
			user,
			validation.Field(&user.Email, validation.Required, is.Email),
			validation.Field(&user.Password, validation.Required, is.Alphanumeric),
		)

	}

	var templateLoginPage *template.Template
	templateLoginPage = template.Must(renderTemplate("./internal/templates/login.html"))

	return func(w http.ResponseWriter, r *http.Request) {
		session, err := s.sessionStore.Get(r, sessionName)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		if r.Method == "POST" {

			l := &login{}
			s.readForm(r, l)

			err := validateLogin(l)
			if err == nil {

				u, err := s.store.User().FindByEmail(l.Email)
				if err != nil || !u.ComparePassword(l.Password) {
					session.Values["user_message"] = "Неправильные логин или пароль"
					if err := s.sessionStore.Save(r, w, session); err != nil {
						s.error(w, r, http.StatusInternalServerError, err)
						return
					}
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}

				session.Values["user_id"] = u.ID
				if err := s.sessionStore.Save(r, w, session); err != nil {
					s.error(w, r, http.StatusInternalServerError, err)
					return
				}
				http.Redirect(w, r, "/private/game", http.StatusFound)
				return

			}

			session.Values["user_message"] = "Неправильные логин или пароль"
			if err := s.sessionStore.Save(r, w, session); err != nil {
				s.error(w, r, http.StatusInternalServerError, err)
				return
			}

			http.Redirect(w, r, "/login", http.StatusFound)

		} else {

			if s.checkForMenu(r) {
				http.Redirect(w, r, "/index", http.StatusFound)
				return
			}

			var message string
			mes, ok := session.Values["user_message"]

			if !ok || mes == nil {
				message = "Войди в игру!"
			} else {
				message = mes.(string)
				session.Values["user_message"] = nil
				if err := s.sessionStore.Save(r, w, session); err != nil {
					s.error(w, r, http.StatusInternalServerError, err)
					return
				}
			}

			pageData := map[string]interface{}{
				"Title":          "Game with nums - Login!",
				"Message":        message,
				csrf.TemplateTag: csrf.TemplateField(r),
			}

			err := templateLoginPage.ExecuteTemplate(w, "base", pageData)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

		}
	}
}

func (s *server) handleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := s.sessionStore.Get(r, sessionName)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		id, ok := session.Values["user_id"]
		if !ok || id == nil {
			s.error(w, r, http.StatusUnauthorized, errNotAuthenticated)
			return
		}

		session.Values["user_id"] = nil
		session.Values["user_name"] = nil
		if err := s.sessionStore.Save(r, w, session); err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		http.Redirect(w, r, "/index", http.StatusFound)
	}
}

func (s *server) handleRegistration() http.HandlerFunc {
	type registration struct {
		Nickname       string
		Email          string
		Password       string
		PasswordRepeat string
		_              string `schema:"Csrf"`
	}

	requiredIf := func(cond bool) validation.RuleFunc {
		return func(value interface{}) error {
			if cond {
				return validation.Validate(value, validation.Required)
			}

			return nil
		}
	}

	validateLogin := func(user *registration) error {
		return validation.ValidateStruct(
			user,
			validation.Field(&user.Nickname,
				validation.Required),
			validation.Field(&user.Email,
				validation.Required,
				is.Email),
			validation.Field(&user.Password,
				validation.Required,
				validation.By(requiredIf(user.Password == user.PasswordRepeat)),
				validation.Length(8, 128),
				is.Alphanumeric),
			validation.Field(&user.PasswordRepeat,
				validation.Required,
				validation.By(requiredIf(user.Password == user.PasswordRepeat)),
				validation.Length(8, 128),
				is.Alphanumeric),
		)

	}

	var templateRegistrationPage *template.Template
	templateRegistrationPage = template.Must(renderTemplate("./internal/templates/registration.html"))

	return func(w http.ResponseWriter, r *http.Request) {
		session, err := s.sessionStore.Get(r, sessionName)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		if r.Method == "POST" {

			reg := &registration{}
			s.readForm(r, reg)

			err := validateLogin(reg)
			if err == nil {

				_, err := s.store.User().FindByEmail(reg.Email)
				if err == nil {
					session.Values["user_message"] = fmt.Sprintf("%s - уже зарегистрирована", reg.Email)
					if err := s.sessionStore.Save(r, w, session); err != nil {
						s.error(w, r, http.StatusInternalServerError, err)
						return
					}
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
				if reg.Password == reg.PasswordRepeat {
					u := &model.User{
						Email:    reg.Email,
						Password: reg.Password,
					}

					if err := s.store.User().Create(u); err != nil {
						s.error(w, r, http.StatusUnprocessableEntity, err)
						return
					}

					u.Sanitize()
				}
				session.Values["user_message"] = "Вы успешно зарегистрированы."
				if err := s.sessionStore.Save(r, w, session); err != nil {
					s.error(w, r, http.StatusInternalServerError, err)
					return
				}
				http.Redirect(w, r, "/login", http.StatusFound)
				return

			}

			session.Values["user_message"] = "Вы ввели недопустимые значения."
			if err := s.sessionStore.Save(r, w, session); err != nil {
				s.error(w, r, http.StatusInternalServerError, err)
				return
			}
			http.Redirect(w, r, "/registration", http.StatusFound)

		} else {

			if s.checkForMenu(r) {
				http.Redirect(w, r, "/index", http.StatusFound)
				return
			}

			var message string
			mes, ok := session.Values["user_message"]

			if !ok || mes == nil {
				message = "Присоединяйся к игре!"
			} else {
				message = mes.(string)
				session.Values["user_message"] = nil
				if err := s.sessionStore.Save(r, w, session); err != nil {
					s.error(w, r, http.StatusInternalServerError, err)
					return
				}
			}

			pageData := map[string]interface{}{
				"Title":          "Game with nums - Registration!",
				"Message":        message,
				csrf.TemplateTag: csrf.TemplateField(r),
			}

			err := templateRegistrationPage.ExecuteTemplate(w, "base", pageData)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

		}
	}
}

func (s *server) readForm(r *http.Request, data interface{}) {
	r.ParseForm()
	decoder := schema.NewDecoder()
	decodeErr := decoder.Decode(data, r.PostForm)
	if decodeErr != nil {
		log.Printf("error mapping parsed form data to struct: %e\n", decodeErr)
	}
}

func (s *server) checkForMenu(r *http.Request) bool {
	session, err := s.sessionStore.Get(r, sessionName)
	if err != nil {
		return false
	}

	id, ok := session.Values["user_id"]
	if !ok || id == nil {
		return false
	}

	return true
}
