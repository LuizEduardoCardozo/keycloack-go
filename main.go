package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

const (
	clientId     = "myclient"
	clientSecret = "dcf3529e-49db-4c87-a8f7-00e64e051299"
	issuer       = "http://localhost:8080/auth/realms/myrealm"
	callbackUrl  = "http://localhost:8000/auth/callbackurl"
	state        = "123"
)

func main() {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatal(err.Error())
	}

	config := oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  callbackUrl,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "roles"},
	}

	http.HandleFunc("/", func(rw http.ResponseWriter, request *http.Request) {
		http.Redirect(rw, request, config.AuthCodeURL(state), http.StatusFound)
	})

	http.HandleFunc("/auth/callbackurl", func(rw http.ResponseWriter, request *http.Request) {
		recivedState := request.URL.Query().Get("state")
		if recivedState != state {
			http.Error(rw, "States didnt matches", http.StatusBadRequest)
			return
		}

		recivedToken := request.URL.Query().Get("code")
		token, err := config.Exchange(ctx, recivedToken)
		if err != nil {
			http.Error(rw, "fail while exchanging the tokens", http.StatusInternalServerError)
			return
		}

		userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			http.Error(rw, "fail while retriveing user informations", http.StatusInternalServerError)
			return
		}

		idToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(rw, "fail when generating id token", http.StatusInternalServerError)
			return
		}

		resp := struct {
			AccessToken *oauth2.Token  `json:"access_token"`
			IDToken     string         `json:"id_token"`
			UserInfo    *oidc.UserInfo `json:"user_info"`
		}{
			token,
			idToken,
			userInfo,
		}

		respJson, err := json.Marshal(resp)
		if err != nil {
			http.Error(rw, "fail when marshalling the response json", http.StatusInternalServerError)
			return
		}

		rw.Write(respJson)

	})

	log.Fatal(http.ListenAndServe(":8000", nil))
}
