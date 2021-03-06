package janserver

// Config - содержит конфигурацию для запуска сервера
type Config struct {
	BindAddr       string `toml:"bind_addr"`
	LogLevel       string `toml:"log_level"`
	DatabaseURL    string `toml:"database_url"`
	DatabaseDriver string `toml:"database_driver"`
	SessionKey     string `toml:"session_key"`
	SessionMaxAge  int    `toml:"session_maxage"`
	CsrfKey        string `toml:"csrf_key"`
	CsrfSecureFlag bool   `toml:"csrf_secure_flag"`
}

// NewConfig - инициализация конфига по умолчанию
func NewConfig() *Config {
	return &Config{
		BindAddr:       ":8080",
		LogLevel:       "debug",
		CsrfSecureFlag: false,
	}
}
