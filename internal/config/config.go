package config

import (
	"encoding/json"
	"github.com/sirupsen/logrus"
	"io"
	"os"

	auth "github.com/Icannotcode0/LiteProxy/internal/protocols/socks5/authetication"
	"github.com/Icannotcode0/LiteProxy/pkg/config"
)

type UnLoader struct {
	ServerConfig        config.Socks5ServerConfig `json:"server_config"`
	AuthContextUnLoader AuthUnLoader              `json:"credentials"`
}

type AuthUnLoader struct {
	UserPassWordCtx map[string]string `json:"up_credentials"`
	//GSSAPICtx       map[interface{}]interface{}
}

func LoadJSON(filePath string) (config.Socks5ServerConfig, error) {

	unloadConfig := UnLoader{}
	file, err := os.Open(filePath)
	if err != nil {
		// logrus.Errorf("Cannot Open File Path %s: %v", filePath, err)

		return config.Socks5ServerConfig{}, err
	}

	defer func() {
		if err := file.Close(); err != nil {
			logrus.Errorf("failed to close file: %v", err)
		}
	}()

	content, err := io.ReadAll(file)

	if err != nil {
		return config.Socks5ServerConfig{}, err
	}

	if err := json.Unmarshal(content, &unloadConfig); err != nil {

		logrus.Errorf("Cannot Decode File Path %s: %v", filePath, err)
		return config.Socks5ServerConfig{}, err
	}

	upCredentials := auth.UserPassAuth{}

	upCredentials.Vault = unloadConfig.AuthContextUnLoader.UserPassWordCtx

	unloadConfig.ServerConfig.AuthMethods = append(unloadConfig.ServerConfig.AuthMethods, upCredentials)

	return unloadConfig.ServerConfig, nil
}
