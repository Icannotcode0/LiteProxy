package config

import (
	"encoding/json"
	"io"
	"os"

	config "github.com/Icannotcode0/LiteProxy/pkg/config"
	"github.com/sirupsen/logrus"
)

func LoadJSON(filePath string) (config.Socks5ServerConfig, error) {

	unloadConfig := config.Socks5ServerConfig{}

	file, err := os.Open(filePath)
	if err != nil {
		logrus.Errorf("Cannot Open File Path %s: %v", filePath, err)
		return unloadConfig, err
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		logrus.Errorf("Cannot Read File Path %s: %v", filePath, err)
		return unloadConfig, err
	}

	if err := json.Unmarshal(content, &unloadConfig); err != nil {

		logrus.Errorf("Cannot Decode File Path %s: %v", filePath, err)
		return unloadConfig, err
	}

	return unloadConfig, nil
}
