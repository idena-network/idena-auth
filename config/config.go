package config

import (
	"encoding/json"
	"github.com/pkg/errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

type Config struct {
	Server           ServerConfig
	Postgres         PostgresConfig
	Verbosity        int
	TokenLifeTimeSec int
}

type PostgresConfig struct {
	ConnStr    string
	ScriptsDir string
}

type ServerConfig struct {
	Port int
}

func LoadConfig(configPath string) *Config {
	if _, err := os.Stat(configPath); err != nil {
		panic(errors.Errorf("Config file can't be found, path: %v", configPath))
	}
	if jsonFile, err := os.Open(configPath); err != nil {
		panic(errors.Errorf("Config file can't be opened, path: %v", configPath))
	} else {
		conf := newDefaultConfig()
		byteValue, _ := ioutil.ReadAll(jsonFile)
		err := json.Unmarshal(byteValue, conf)
		if err != nil {
			panic(errors.Errorf("Cannot parse JSON config, path: %v", configPath))
		}
		return conf
	}
}

func newDefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port: 80,
		},
		Postgres: PostgresConfig{
			ScriptsDir: filepath.Join("resources"),
		},
		Verbosity:        5,
		TokenLifeTimeSec: 60,
	}
}
