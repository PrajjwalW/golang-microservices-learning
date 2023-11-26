package main

import (
	"authentication/data"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

func (app *Config) Authenticate(w http.ResponseWriter, r *http.Request) {
	var requestPayload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	err := app.readJSON(w, r, &requestPayload)
	if err != nil {
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	//validate the user against the database
	user, err := app.Models.User.GetByEmail(requestPayload.Email)
	if err != nil {
		app.errorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}

	valid, err := user.PasswordMatches(requestPayload.Password)
	if err != nil || !valid {
		app.errorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}

	//log authentication
	err = app.logRequest("authentication", fmt.Sprintf("%s logged in", user.Email))
	if err != nil {
		app.errorJSON(w, err)
		return
	}

	payload := jsonResponse{
		Error:   false,
		Message: fmt.Sprintf("Logged in user %s", user.Email),
		Data:    user,
	}

	app.writeJSON(w, http.StatusAccepted, payload)

}

func (app *Config) logRequest(name, data string) error {
	var entry struct {
		Name string `json:"name"`
		Data string `json:"data"`
	}

	entry.Name = name
	entry.Data = data

	jsonData, _ := json.MarshalIndent(entry, "", "\t")
	logServiceURL := "http://localhost:8083/log"

	request, err := http.NewRequest("POST", logServiceURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	client := &http.Client{}
	_, err = client.Do(request)
	if err != nil {
		return err
	}
	return nil
}

func (app *Config) Register(w http.ResponseWriter, r *http.Request) {
	var requestPayload data.Models

	err := app.readJSON(w, r, &requestPayload.User)
	if err != nil {
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	//check user present with the same email
	user, _ := app.Models.User.GetByEmail(requestPayload.User.Email)
	if user != nil {
		app.errorJSON(w, errors.New("user present with same email, Try again"), http.StatusBadRequest)
		return
	}

	userId, err := app.Models.User.Insert(requestPayload.User)
	if err != nil {
		app.errorJSON(w, errors.New("error while registering user, Please try again"), http.StatusBadRequest)
		return
	}

	//log user registeration
	err = app.logRequest("registration", fmt.Sprintf("%d user registered with the email:%s", userId, requestPayload.User.Email))
	if err != nil {
		app.errorJSON(w, err)
		return
	}

	payload := jsonResponse{
		Error:   false,
		Message: "User Registered with UserID",
		Data:    userId,
	}

	app.writeJSON(w, http.StatusCreated, payload)
}
