package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sashabaranov/go-openai"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/acme/autocert"
	"gopkg.in/telebot.v3"
)

const (
	Demo4   = 10
	Demo3   = 20
	DemoImg = 5
	//TODO
	//	FailURL         = "https://aishapro.com/fail"
	//	SuccessURL      = "https://aishapro.com/success"
	NotificationURL = "https://aishapro.com/notification"
)

type Status int8

const (
	NEW Status = iota + 1
	CANCELED
	AUTHORIZED
	PARTIAL_REVERSED
	REVERSED
	CONFIRMED
	PARTIAL_REFUNDED
	REFUNDED
)

var (
	HmacSecret       = []byte(os.Getenv("HMACSECRET"))
	TerminalPassword = os.Getenv("TERMINAL_PASSWORD")
	TerminalKey      = os.Getenv("TERMINAL_KEY")
	Token            = os.Getenv("TOKEN")
	OpenaiApiKey     = os.Getenv("OPENAI_API_KEY")
	OrderMtx         sync.Mutex
	client           *openai.Client
	db               *bolt.DB
	// cabtmpl          *template.Template
	// tariftmpl        *template.Template
	// demotmpl         *template.Template
	tmpl        *template.Template
	boltpath    string              = "db/boltdb"
	FileReaders map[string]MockFile = make(map[string]MockFile)
	defaultUser                     = User{
		Tarif:    "base",
		Model:    "gpt-4o",
		ImgRes:   "1024x1024",
		ImgQlt:   "standard",
		ImgStyle: "vivid",
		LastPay:  time.Now(),
		Deposit:  100,
		Remain:   200000,
		//		Remain4:   100,
		//		Remain3:   200,
		//		RemainImg: 50,
		Request4:  0,
		Request3:  0,
		Response4: 0,
		Response3: 0,
		Images:    0,
	}
)

// Tbank
type InitPayment struct {
	TerminalKey     string `json:"TerminalKey,omitempty"`
	Amount          uint64 `json:"Amount,omitempty"`
	OrderId         string `json:"OrderId,omitempty"`
	Token           string `json:"Token,omitempty"`
	Description     string `json:"Description,omitempty"`
	CustomerKey     string `json:"CustomerKey,omitempty"`
	Recurrent       string `json:"Recurrent,omitempty"`
	PayType         string `json:"PayType,omitempty"`
	Language        string `json:"Language,omitempty"`
	NotificationURL string `json:"NotificationURL,omitempty"`
	SuccessURL      string `json:"SuccessURL,omitempty"`
	FailURL         string `json:"FailURL,omitempty"`
	RedirectDueDate string `json:"RedirectDueDate,omitempty"`
	DATA            Data   `json:"DATA,omitempty"`
	//Receipt Receipt `json:"Receipt ,omitempty"`
}

type InitResponse struct {
	TerminalKey string `json:"TerminalKey"`
	Amount      uint64 `json:"Amount"`
	OrderId     string `json:"OrderId"`
	Success     bool   `json:"Success"`
	Status      string `json:"Status"`
	PaymentId   string `json:"PaymentId"`
	ErrorCode   string `json:"ErrorCode"`
	PaymentURL  string `json:"PaymentURL"`
	Message     string `json:"Message"`
	Details     string `json:"Details"`
}

type Notification struct {
	TerminalKey string      `json:"TerminalKey"`
	Amount      uint64      `json:"Amount"`
	OrderId     string      `json:"OrderId"`
	Success     bool        `json:"Success"`
	Status      string      `json:"Status"`
	PaymentId   json.Number `json:"PaymentId"`
	ErrorCode   string      `json:"ErrorCode"`
	Message     string      `json:"Message"`
	Details     string      `json:"Details"`
	RebillId    uint64      `json:"RebillId"`
	CardId      uint64      `json:"CardId"`
	Pan         string      `json:"Pan"`
	ExpDate     string      `json:"ExpDate"`
	Token       string      `json:"Token"`
	DATA        Data        `json:"DATA"`
}

type CanselRequest struct {
	TerminalKey       string      `json:"TerminalKey,omitempty"`
	PaymentId         json.Number `json:"PaymentId,omitempty"`
	Token             string      `jsIPon:"Token,omitempty"`
	IP                string      `json:"IP,omitempty"`
	Amount            uint64      `json:"Amount,omitempty"`
	ExternalRequestId string      `json:"ExternalRequestId,omitempty"`
}

type CanselResponse struct {
	TerminalKey       string `json:"TerminalKey"`
	OrderId           string `json:"OrderId"`
	Success           bool   `json:"Success"`
	OriginalAmount    uint64 `json:"OriginalAmount"`
	NewAmount         uint64 `json:"NewAmount"`
	PaymentId         string `json:"PaymentId"`
	ErrorCode         string `json:"ErrorCode"`
	Message           string `json:"Message"`
	Details           string `json:"Details"`
	ExternalRequestId string `json:"ExternalRequestId"`
}

type Order struct {
	OrderId string `json:"OrderId"`
	Amount  uint64 `json:"Amount"`
	UserId  string `json:"UserId"`
	Status  string `json:"Status"`
	Success bool   `json:"Success"`
}

type Data struct {
	OperationInitiatorType string `json:"OperationInitiatorType,omitempty"`
	CustomerID             string `json:"CustomerID,omitempty"`
}

func (i *InitPayment) CalcToken() {
	//	str := strconv.FormatUint(i.Amount, 10) + i.CustomerKey + i.Description + i.FailURL + i.Language + i.NotificationURL + i.OrderId + TerminalPassword + i.PayType + i.Recurrent + i.RedirectDueDate + i.SuccessURL + i.TerminalKey
	str := strconv.FormatUint(i.Amount, 10) + i.Description + i.Language + i.NotificationURL + i.OrderId + TerminalPassword + i.TerminalKey
	sha := sha256.Sum256([]byte(str))
	token := hex.EncodeToString(sha[:])
	i.Token = token
}

//type DATA

type MockFile struct {
	multipart.File
	Ch chan struct{}
}

type Pref struct {
	Tarif    string `json:"tarif"`
	Model    string `json:"model"`
	ImgRes   string `json:"imgres"`
	ImgQlt   string `json:"imgqlt"`
	ImgStyle string `json:"imgstyle"`
}

type User struct {
	ID string `json:"id"`
	//	Passw     string    `json:"passw"`
	Tarif          string    `json:"tarif"`
	Model          string    `json:"model"`
	ImgRes         string    `json:"imgres"`
	ImgQlt         string    `json:"imgqlt"`
	ImgStyle       string    `json:"imgstyle"`
	SpeechModel    string    `json:"speechmodel"`
	Voice          string    `json:"voice"`
	ResponseFormat string    `json:"responseformat"`
	Speed          float64   `json:"speed"`
	LastPay        time.Time `json:"lastpay"`
	Deposit        uint64    `json:"deposit"`
	Consumed       uint64    `json:"consumed"`
	Remain         uint64    `json:"remain"`
	//TODO for Speech
	Request4  int `json:"request4"`
	Request3  int `json:"request3"`
	Response4 int `json:"response4"`
	Response3 int `json:"response3"`
	Images    int `json:"imgages"`
}

func (user *User) IsAllowedCompl() (bool, string) {
	//TODO
	//if time.Since(user.LastPay).Hours() >= 720 {
	//	return false, "К сожалению оплаченный вами месяц истек"
	//}
	//if (user.Model == "gpt-4o") && (user.Remain4 <= 0) {
	//	user.Model = openai.GPT3Dot5Turbo
	//}
	//if user.Remain3 <= 0 {
	//	return false, "К сожалению вы исчерпали ресурс своего тарифа"
	//}
	return true, ""
}

func (user *User) Persist() error {
	usr, err := json.Marshal(user)
	if err != nil {
		return err
	}
	if err := db.Batch(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte("base")).Put([]byte(user.ID), []byte(usr)); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func (user *User) Used(u openai.Usage) error {
	if user.Model == "gpt-4o" {
		user.Request4 += u.PromptTokens
		user.Response4 += u.CompletionTokens
		user.Consumed += uint64((u.PromptTokens + (2 * u.CompletionTokens)) * 10)
	} else {
		user.Request3 += u.PromptTokens
		user.Response3 += u.CompletionTokens
		user.Consumed += uint64((u.PromptTokens + (2 * u.CompletionTokens)))
	}
	if user.Remain > uint64((u.PromptTokens + (2 * u.CompletionTokens))) {
		user.Remain -= uint64((u.PromptTokens + (2 * u.CompletionTokens)))
	} else {
		user.Remain = 0
	}
	return user.Persist()
	// usr, err := json.Marshal(user)
	//
	//	if err != nil {
	//		return err
	//	}
	//
	//	if err := db.Batch(func(tx *bolt.Tx) error {
	//		if err := tx.Bucket([]byte("base")).Put([]byte(user.ID), []byte(usr)); err != nil {
	//			return err
	//		}
	//		return nil
	//	}); err != nil {
	//
	//		return err
	//	}
}

func IsValidToken(tokenstring string) (*User, error) {
	token, err := jwt.Parse(tokenstring, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("Плохо подписан ключ. Попробуйте авторизоваться заново.")
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return HmacSecret, nil
	})
	if !token.Valid {
		return nil, errors.New("Плохой ключ. Попробуйте авторизоваться заново.")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("Поддельный ключ. Попробуйте авторизоваться заново.")
	}
	end, err := claims.GetExpirationTime()
	if (err != nil) || end.Time.Before(time.Now()) {
		return nil, errors.New("Ключ протух. Попробуйте авторизоваться заново.")
	}
	username, err := claims.GetSubject()
	if err != nil {
		return nil, err
	}
	user := new(User)
	if err := db.View(func(tx *bolt.Tx) error {
		passw := tx.Bucket([]byte("auth")).Get([]byte(username))
		if passw == nil {
			return errors.New("Нет такого пользователя")
		}
		usr := tx.Bucket([]byte("base")).Get([]byte(username))
		if err := json.Unmarshal(usr, user); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return user, nil
}

func IsValidUser(username, password string) (*User, error) {

	user := new(User)
	if err := db.View(func(tx *bolt.Tx) error {
		passw := tx.Bucket([]byte("auth")).Get([]byte(username))
		if passw == nil {
			return errors.New("Нет такого пользователя")
		}
		if string(passw) != password {
			return errors.New("Пароль не подходит")
		}
		usr := tx.Bucket([]byte("base")).Get([]byte(username))
		if err := json.Unmarshal(usr, user); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return user, nil
}

func About(w http.ResponseWriter, r *http.Request) {
	err := tmpl.ExecuteTemplate(w, "about", nil)
	if err != nil {
		panic(err)
	}
}

func Chat(w http.ResponseWriter, r *http.Request) {
	err := tmpl.ExecuteTemplate(w, "chat", nil)
	if err != nil {
		panic(err)
	}
}

func Cabinet(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("aishatoken")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Пароль не предоставлен"))
		return
	}
	tokenString := cookie.Value
	user, err := IsValidToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}

	err = tmpl.ExecuteTemplate(w, "cabinet", user)
	if err != nil {
		panic(err)
	}
}

func Register(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Требуется авторизация"))
		return
	}
	if err := db.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("auth")).Get([]byte(username)) != nil {
			return errors.New("Такой пользователь уже зарегистрирован")
		}
		return nil
	}); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Такой пользователь уже зарегистрирован"))
		return
	}
	u := defaultUser
	u.ID = username
	user, err := json.Marshal(u)
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte("base")).Put([]byte(username), []byte(user)); err != nil {
			return err
		}
		if err := tx.Bucket([]byte("auth")).Put([]byte(username), []byte(password)); err != nil {
			return err
		}
		return nil
	}); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Вы успешно зарегистрировались"))
}

func Login(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Пароль не предоставлен"))
		return
	}
	_, err := IsValidUser(username, password)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)

	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().AddDate(0, 1, 0)),
		Issuer:    "aishapro.com",
		Subject:   username,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(HmacSecret)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(ss))
}

func Tarif(w http.ResponseWriter, r *http.Request) {
	err := tmpl.ExecuteTemplate(w, "tarif", nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
}
func Completion(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Пароль не предоставлен"))
		return
	}
	tokenString = tokenString[len("Bearer "):]
	user, err := IsValidToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}
	if ok, msg := user.IsAllowedCompl(); !ok {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(msg))
		return
	}

	messages := make([]openai.ChatCompletionMessage, 0, 0)
	err = json.NewDecoder(r.Body).Decode(&messages)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model:    user.Model,
			Messages: messages,
		},
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	if err := user.Used(resp.Usage); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	//	io.WriteString(w, resp.Choices[0].Message.Content)
	//usage := resp.Usage.PromptTokens + resp.Usage.CompletionTokens*2
	//if user.Model == "gpt-4o" {
	//	usage = usage * 10
	//}
	err = json.NewEncoder(w).Encode(struct {
		Text  string `json:"Text"`
		Usage int    `json:"Usage"`
	}{resp.Choices[0].Message.Content, int(user.Consumed)})
	if err != nil {
		// TODO log or?
		panic(err)
	}
}
func Prefs(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Пароль не предоставлен"))
		return
	}
	tokenString = tokenString[len("Bearer "):]
	user, err := IsValidToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}
	prefs := new(Pref)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(prefs); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
	user.Tarif = prefs.Tarif
	user.Model = prefs.Model
	user.ImgRes = prefs.ImgRes
	user.ImgQlt = prefs.ImgQlt
	user.ImgStyle = prefs.ImgStyle
	if err := user.Persist(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Настройки успешно сохранены"))
	return
}

func Painting(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Пароль не предоставлен"))
		return
	}
	tokenString = tokenString[len("Bearer "):]
	user, err := IsValidToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}
	if ok, msg := user.IsAllowedCompl(); !ok {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(msg))
		return
	}
	prompt, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	respURL, err := client.CreateImage(
		context.Background(),
		openai.ImageRequest{
			Prompt:         string(prompt),
			Quality:        user.ImgQlt,
			Size:           user.ImgRes,
			Style:          user.ImgStyle,
			ResponseFormat: openai.CreateImageResponseFormatURL,
			N:              1,
			User:           user.ID,
		},
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	user.Images += 1
	tokens := 13333
	if (user.ImgRes == "1024×1792") || (user.ImgRes == "1792×1024") {
		tokens *= 2
	}
	if user.ImgQlt == "hd" {
		tokens *= 2
	}
	user.Consumed = uint64(tokens)
	if user.Remain > user.Consumed {
		user.Remain -= user.Consumed
	} else {
		user.Remain = 0
	}
	if err := user.Persist(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(struct {
		URL   string `json:"URL"`
		Usage int    `json:"Usage"`
	}{respURL.Data[0].URL, int(user.Consumed)})
	if err != nil {
		panic(err)
	}
	// w.Write([]byte(respURL.Data[0].URL))
}

func Vision(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Пароль не предоставлен"))
		fmt.Println("Пароль не предоставлен")
		return
	}
	tokenString = tokenString[len("Bearer "):]
	user, err := IsValidToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		fmt.Println("Не валидный токен", err)
		return
	}
	if ok, msg := user.IsAllowedCompl(); !ok {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(msg))
		fmt.Println("Не алловед компл")
		return
	}
	prompt := r.FormValue("prompt")
	fmt.Println("PROMPT ", prompt)
	urls := strings.Split(r.FormValue("files"), ",")
	fmt.Println("FILES ", urls)
	//TODO
	var msgs []openai.ChatCompletionMessage
	msg := openai.ChatCompletionMessage{
		Role: "user",
	}
	for _, v := range urls {

		// imgdata, err = io.ReadAll(file)
		//
		//	if err != nil {
		//		w.Write([]byte(err.Error()))
		//	}
		//
		// mime := header.Header.Get("Content-Type")
		// imgdata64 := base64.StdEncoding.EncodeToString(imgdata)
		// part.ImageURL.URL = "data:" + mime + ";base64," + imgdata64
		part := openai.ChatMessagePart{
			Type:     openai.ChatMessagePartTypeImageURL,
			ImageURL: new(openai.ChatMessageImageURL),
		}
		part.ImageURL.URL = "https://aishapro.com/files/" + v
		msg.MultiContent = append(msg.MultiContent, part)
		fmt.Println("part.ImageURL.URL ", part.ImageURL.URL)
	}
	tpart := openai.ChatMessagePart{
		Type: openai.ChatMessagePartTypeText,
		Text: prompt,
	}
	msg.MultiContent = append(msg.MultiContent, tpart)
	msgs = append(msgs, msg)
	req := openai.ChatCompletionRequest{
		Model:    user.Model,
		Messages: msgs,
	}
	resp, err := client.CreateChatCompletion(context.Background(), req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		fmt.Println("Request error ", err)
	}
	//for k, v := range FileReaders {
	//	close(v.Ch)
	//	delete(FileReaders, k)
	//}
	if err := user.Used(resp.Usage); err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(err.Error()))
		return
	}
	w.Header().Set("content-type", "application/json")
	err = json.NewEncoder(w).Encode(struct {
		Text  string `json:"Text"`
		Usage int    `json:"Usage"`
	}{resp.Choices[0].Message.Content, int(user.Consumed)})
	if err != nil {
		panic(err)
	}
}

func Files(w http.ResponseWriter, r *http.Request) {
	fname := strings.TrimPrefix(r.URL.RequestURI(), "/files/")
	fmt.Println("fname ", fname)
	reader, ok := FileReaders[fname]
	if !ok {
		http.NotFound(w, r)
		fmt.Println("FileReaders !ok")
		return
	}
	_, err := io.Copy(w, reader)
	if err != nil {
		fmt.Println("io.Copy err ", err)
		panic(err)
		//TODO
		//log.Println("File not found " + fname)
	}
	err = reader.Close()
	if err != nil {
		fmt.Println("reader.Close err ", err)
		panic(err)
		//TODO log.Println("Can't close file " + fname)
	}
	close(reader.Ch)
	delete(FileReaders, fname)
}

func Upload(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Пароль не предоставлен"))
		fmt.Println("Upload Пароль не предоставлен")
		return
	}
	tokenString = tokenString[len("Bearer "):]
	user, err := IsValidToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		fmt.Println("Upload InvalidToken err ", err)
		return
	}
	if ok, msg := user.IsAllowedCompl(); !ok {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(msg))
		fmt.Println("Upload !IsAllowedCompl")
		return
	}
	file, header, err := r.FormFile("image")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		fmt.Println(`Upload file, header, err := r.FormFile("image") error `, err)
		return
	}
	f := MockFile{file, make(chan struct{})}
	fmt.Println("MockFile ", header.Filename)
	FileReaders[header.Filename] = f
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Загружен файл " + header.Filename))
	fmt.Println("Загружен file ", header.Filename)
	<-f.Ch
	//w.Write([]byte("Загружен файл" + header.Filename))
	//delete(FileReaders, header.Filename)
	//print("delete " + header.Filename + "\n")
}

func UploadAssist(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Пароль не предоставлен"))
		fmt.Println("Upload Пароль не предоставлен")
		return
	}
	tokenString = tokenString[len("Bearer "):]
	user, err := IsValidToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		fmt.Println("Upload InvalidToken err ", err)
		return
	}
	if ok, msg := user.IsAllowedCompl(); !ok {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(msg))
		fmt.Println("Upload !IsAllowedCompl")
		return
	}
	pr, pw := io.Pipe()
	bw := multipart.NewWriter(pw) // body writer

	go func() {
		defer pw.Close()
		defer bw.Close()
		// text part
		err = bw.WriteField("purpose", "assistants")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			fmt.Println(`Multipart writeField error `, err)
			return
		}
		// file part
		part, err := bw.CreateFormFile("file", r.Header.Get("Filename"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			fmt.Println(`CreateFormFile error `, err)
			return
		}
		if _, err = io.Copy(part, r.Body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			fmt.Println(`io.Copy error `, err)
			return
		}
	}()
	req, err := http.NewRequest("POST", "https://api.openai.com/v1/files", pr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		fmt.Println(`UploadAssist req error `, err)
		return
	}

	req.Header.Set("Content-Type", bw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+OpenaiApiKey)
	fmt.Println("Send request to openai")
	resp, err := http.DefaultClient.Do(req)
	fmt.Println("Reseive responce from openai")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		fmt.Println(`UploadAssist resp error `, err)
		return
	}
	//io.Copy(os.Stdout, resp.Body)
	file := new(openai.File)
	err = json.NewDecoder(resp.Body).Decode(file)
	fmt.Println("Unmarshall responce")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		fmt.Println(`Openai decode resp error `, err)
//		return
	}
	fmt.Printf("%+v\n", file)
	fmt.Println("Write responce to client")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Загружен файл " + file.FileName))
}

func Payment(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Пароль не предоставлен"))
		return
	}
	tokenString = tokenString[len("Bearer "):]
	user, err := IsValidToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	amount, err := strconv.ParseUint(string(body), 10, 64)
	if err != nil || amount <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	amount = amount * 100
	var orderId string
	if err := db.Update(func(tx *bolt.Tx) error {
		ordi, err := tx.Bucket([]byte("orders")).NextSequence()
		if err != nil {
			return err
		}
		orderId = strconv.FormatUint(ordi, 10)
		//order := Order{
		//	OrderId: orderId,
		//	Amount:  amount,
		//	UserId:  user.ID,
		//}
		//jorder, err := json.Marshal(order)
		//if err != nil {
		//	return err
		//}
		//if err := tx.Bucket([]byte("orders")).Put([]byte(orderId), []byte(jorder)); err != nil {
		//	return err
		//
		//		}
		return nil
	}); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	req := &InitPayment{
		TerminalKey: TerminalKey,
		Amount:      amount,
		OrderId:     orderId,
		Description: "Пополнение счета",
		//		CustomerKey:     user.ID,
		Language:        "ru",
		NotificationURL: NotificationURL,
		//		SuccessURL:      SuccessURL,
		//		FailURL:         FailURL,
		//DATA: Data{
		//	OperationInitiatorType: "0",
		//},
	}
	req.CalcToken()
	//	req := &InitPayment{
	//		TerminalKey:     "1718987845676DEMO",
	//		Amount:          200000,
	//		OrderId:         "77",
	//		Description:     "Пополнение счета",
	//		NotificationURL: "https://aishapro.com/notification",
	//	}
	//str := "200000" + "Пополнение счета" + "https://aishapro.com/notification" + "77" + "9lAa1Uf&B#sarttU" + "1718987845676DEMO"
	//sha := sha256.Sum256([]byte(str))
	//token := hex.EncodeToString(sha[:])
	//req.Token = token
	//TEST

	// TEST
	jsn, err := json.Marshal(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	cont := bytes.NewReader(jsn)
	resp, err := http.Post("https://securepay.tinkoff.ru/v2/Init", "application/json", cont)
	// resp, err := http.Post("https://rest-api-test.tinkoff.ru/v2/init", "application/json", bytes.NewReader(jsn))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
		//TODO
	}
	if resp.StatusCode != 200 {
		w.WriteHeader(resp.StatusCode)
		w.Write([]byte("Платеж не проходит"))
		return
		//TODO
	}
	rspns := new(InitResponse)
	err = json.NewDecoder(resp.Body).Decode(rspns)
	if err != nil {
		panic(err)
	}
	order := &Order{
		OrderId: rspns.OrderId,
		Amount:  rspns.Amount,
		UserId:  user.ID,
		Status:  "New",
		Success: true,
	}
	jorder, err := json.Marshal(order)
	if err != nil {
		panic(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte("orders")).Put([]byte(rspns.PaymentId), []byte(jorder)); err != nil {
			return err
		}
		return nil
	}); err != nil {
		panic(err)
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(rspns.PaymentURL))
}

func Transcription(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Пароль не предоставлен"))
		return
	}
	tokenString = tokenString[len("Bearer "):]
	user, err := IsValidToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}
	if ok, msg := user.IsAllowedCompl(); !ok {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(msg))
		return
	}
	file, header, err := r.FormFile("audio")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		fmt.Println(`Upload file, header, err := r.FormFile("audio") error `, err)
		return
	}

	resp, err := client.CreateTranscription(
		context.Background(),
		openai.AudioRequest{
			Model:    openai.Whisper1,
			FilePath: header.Filename,
			Reader:   file,
			Format:   openai.AudioResponseFormatVerboseJSON,
			Prompt:   r.FormValue("prompt"),
		},
	)
	if err != nil {
		//TODO
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		fmt.Printf("Transcription error: %v\n", err)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("content-type", "application/json")
	usage := resp.Duration * 33.333
	err = json.NewEncoder(w).Encode(struct {
		Text  string `json:"Text"`
		Usage int    `json:"Usage"`
	}{Text: resp.Text, Usage: int(usage)})
	if err != nil {
		panic(err)
	}
	user.Consumed = uint64(usage)
	if user.Remain > user.Consumed {
		user.Remain -= user.Consumed
	} else {
		user.Remain = 0
	}
	err = user.Persist()
	if err != nil {
		panic(err)
	}
}

func Speech(w http.ResponseWriter, r *http.Request) {
	//TODO
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Пароль не предоставлен"))
		return
	}
	tokenString = tokenString[len("Bearer "):]
	user, err := IsValidToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}
	if ok, msg := user.IsAllowedCompl(); !ok {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(msg))
		return
	}
	prompt, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	req := openai.CreateSpeechRequest{
		//TODO use User.Prefs
		//Model: openai.SpeechModel(user.SpeechModel),
		Model: "tts-1",
		//Voice: openai.SpeechVoice(user.Voice),
		Voice: "alloy",
		//ResponseFormat: openai.SpeechResponseFormat(user.ResponseFormat),
		//Speed: user.Speed,
		Input: string(prompt),
	}
	resp, err := client.CreateSpeech(context.Background(), req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	user.Consumed = uint64(utf8.RuneCountInString(req.Input) * 30)
	if req.Model == "tts-1-hd" {
		user.Consumed += 2
	}
	if user.Remain > user.Consumed {
		user.Remain -= user.Consumed
	} else {
		user.Remain = 0
	}
	if err := user.Persist(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)
	//TODO w.Header().Set("content-type", "")
	w.Header().Set("content-type", "audio/mp3")
	io.Copy(w, resp)
}

func GetNotification(w http.ResponseWriter, r *http.Request) {
	notification := new(Notification)
	if err := json.NewDecoder(r.Body).Decode(notification); err != nil {
		//TODO
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
	if notification.Status != "CONFIRMED" {
		//TODO
	}
	order := new(Order)
	user := new(User)
	//TODO validate token
	if err := db.View(func(tx *bolt.Tx) error {

		//		b := make([]byte, 8)
		//		binary.LittleEndian.PutUint64(b, notification.PaymentId)
		ord := tx.Bucket([]byte("orders")).Get([]byte(notification.PaymentId.String()))
		if ord == nil {
			return errors.New("Нет такого платежа")
		}
		if err := json.Unmarshal(ord, order); err != nil {
			return err
		}
		if order.OrderId != notification.OrderId || order.Amount != notification.Amount {
			//TODO error
		}
		order.Status = notification.Status
		order.Success = notification.Success
		if notification.Status == "CONFIRMED" {
			username := order.UserId
			usr := tx.Bucket([]byte("base")).Get([]byte(username))
			if usr == nil {
				return errors.New("Нет такого пользователя")
			}
			if err := json.Unmarshal(usr, user); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		//TODO
		return
	}
	//	if notification.Status == "CONFIRMED" {
	//		user.Deposit += (notification.Amount / 100)
	//		user.LastPay = time.Now()
	//		juser, err := json.Marshal(user)
	//		fmt.Println("json marshall user in juser")
	//		if err != nil {
	//			fmt.Println("Error json.Marshal(user) ", err)
	//			//TODO
	//		}
	//		if err := db.Update(func(tx *bolt.Tx) error {
	//			b := make([]byte, 8)
	//			binary.LittleEndian.PutUint64(b[0:], notification.PaymentId)
	//			if err := tx.Bucket([]byte("base")).Put(b, []byte(juser)); err != nil {
	//				fmt.Println("Error put user.ID juser to bolt ", err)
	//				return err
	//			}
	//			return nil
	//		}); err != nil {
	//			//TODO
	//			return
	//		}
	//	}
	jorder, err := json.Marshal(order)
	if err != nil {
		//TODO
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte("orders")).Put([]byte(notification.PaymentId.String()), []byte(jorder)); err != nil {
			return err
		}
		if notification.Status == "CONFIRMED" {
			user.Deposit += (notification.Amount / 100)
			user.LastPay = time.Now()
			user.Remain += notification.Amount * 100
			juser, err := json.Marshal(user)
			if err != nil {
				return err
			}

			if err := tx.Bucket([]byte("base")).Put([]byte(user.ID), []byte(juser)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		//TODO
		panic(err)
	}
	//TODO else
}

// telegram

type Conversation struct {
	ID        int64
	Size      int
	StartTime time.Time
	Messages  []openai.ChatCompletionMessage
}

var Conversations map[int64]*Conversation = make(map[int64]*Conversation)

func Ontext(c telebot.Context) error {
	id := c.Sender().ID
	if c.Chat().Type != telebot.ChatPrivate {
		id = c.Chat().ID
	}
	user, err := ResolveUser(c.Sender().ID)
	if err != nil {
		return err
	}
	if ok, msg := user.IsAllowedCompl(); !ok {
		return errors.New(msg)
	}
	text := c.Text()
	// TODO PAINTING
	if strings.Contains(text, "Нарис") || strings.Contains(text, "нарис") || strings.Contains(text, "изобра") || strings.Contains(text, "картин") {
		respURL, err := client.CreateImage(
			context.Background(),
			openai.ImageRequest{
				Prompt:         text,
				Quality:        user.ImgQlt,
				Size:           user.ImgRes,
				Style:          user.ImgStyle,
				ResponseFormat: openai.CreateImageResponseFormatURL,
				N:              1,
				User:           user.ID,
			},
		)
		if err != nil {
			return err
		}
		user.Images += 1
		tokens := 13333
		if (user.ImgRes == "1024×1792") || (user.ImgRes == "1792×1024") {
			tokens *= 2
		}
		if user.ImgQlt == "hd" {
			tokens *= 2
		}
		user.Consumed += uint64(tokens)
		if user.Remain > user.Consumed {
			user.Remain -= user.Consumed
		} else {
			user.Remain = 0
		}
		if err := user.Persist(); err != nil {
			return err
		}
		photo := &telebot.Photo{File: telebot.FromURL(respURL.Data[0].URL)}
		c.Send(photo)
		return nil
	}
	//TODO
	conv := ResolveConv(id)
	conv.Messages = append(conv.Messages, openai.ChatCompletionMessage{Role: "user", Content: text})
	req := openai.ChatCompletionRequest{
		Model:    user.Model,
		Messages: conv.Messages,
	}
	resp, err := client.CreateChatCompletion(context.Background(), req)
	if err != nil {
		return err
	}
	//TODO списать ресурс
	if err := user.Used(resp.Usage); err != nil {
		return err
	}
	resptext := resp.Choices[0].Message.Content
	conv.Messages = append(conv.Messages, openai.ChatCompletionMessage{Role: "assistant", Content: resptext})
	return c.Send(resptext)
}

//func Onquery(c telebot.Context) error {
//	//TODO
//	//id := c.Sender().ID
//	user, err := ResolveUser(c.Sender().ID)
//	if err != nil {
//		return err
//	}
//	if ok, msg := user.IsAllowedCompl(); !ok {
//		return errors.New(msg)
//	}
//	text := c.Query().Text
//	fmt.Println("Query text ", text)
//	messages := make([]openai.ChatCompletionMessage, 0, 0)
//	messages = append(messages, openai.ChatCompletionMessage{Role: "user", Content: text})
//	req := openai.ChatCompletionRequest{
//		Model:    user.Model,
//		Messages: messages,
//	}
//	resp, err := client.CreateChatCompletion(context.Background(), req)
//	if err != nil {
//		return err
//	}
//	fmt.Println("openai resp ", resp)
//	//TODO списать ресурс
//	if err := user.Used(resp.Usage); err != nil {
//		return err
//	}
//	results := make(telebot.Results, 1)
//	fmt.Println("Result content ", resp.Choices[0].Message.Content)
//	var result BaseResult
//	result.SetContent(&telebot.InputTextMessageContent{
//			Text: resp.Choices[0].Message.Content,
//		})
//	result.SetResultID("foo")
//	results[0] = &result
//	fmt.Printf("%+v\n", results[0])
//	return c.Answer(&telebot.QueryResponse{
//		QueryID:   c.Query().ID,
//		Results:   results,
//		CacheTime: 60, // a minute
//	})
//}

func ResolveUser(u int64) (*User, error) {
	id := strconv.Itoa(int(u))
	user := new(User)
	if err := db.View(func(tx *bolt.Tx) error {
		usr := tx.Bucket([]byte("base")).Get([]byte(id))
		if usr == nil {
			return errors.New("Нет такого пользователя")
		}
		if err := json.Unmarshal(usr, user); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return user, nil
}

func ResolveConv(id int64) *Conversation {
	conv, ok := Conversations[id]
	if !ok {
		conv = new(Conversation)
		conv.ID = id
		Conversations[id] = conv
	}
	return conv
}

func main() {
	var err error
	tmpl, err = template.ParseFiles("tmpl/html.tmpl", "tmpl/tmpl.js")
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	// Let'sEncript
	//	certManager := autocert.Manager{
	//		Prompt:     autocert.AcceptTOS,
	//		HostPolicy: autocert.HostWhitelist("aishapro.com"), //Your domain here
	//		Cache:      autocert.DirCache("certs"),             //Folder for storing certificates
	//	}
	//	server := &http.Server{
	//		Addr:    ":https",
	//		Handler: mux,
	//		TLSConfig: &tls.Config{
	//			GetCertificate: certManager.GetCertificate,
	//			MinVersion:     tls.VersionTLS12, // improves cert reputation score at https://www.ssllabs.com/ssltest/
	//		},
	//	}

	//	go http.ListenAndServe(":http", certManager.HTTPHandler(nil))
	// telegram-bot
	tpref := telebot.Settings{
		Token:  Token,
		Poller: &telebot.LongPoller{Timeout: 10 * time.Second},
	}

	tbot, err := telebot.NewBot(tpref)
	if err != nil {
		log.Fatal(err)
		return
	}

	tbot.Handle(telebot.OnText, Ontext)
	//	tbot.Handle(telebot.OnQuery, Onquery)
	//TODO
	// go run compact(Conversations)
	go tbot.Start()
	// web interface
	//	cabtmpl, err = template.ParseFiles("tmpl/cabinet.tmpl")
	//	if err != nil {
	//		panic(err)
	//	}
	//	tariftmpl, err = template.ParseFiles("tmpl/tarif.tmpl")
	//	if err != nil {
	//		panic(err)
	//	}
	//	demotmpl, err = template.ParseFiles("tmpl/demo.tmpl")
	//	if err != nil {
	//		panic(err)
	//	}
	db, err = bolt.Open(boltpath, 0666, nil)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Fatal(err)
		}
	}()
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("base"))
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists([]byte("orders"))
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists([]byte("payments"))
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists([]byte("auth"))
		if err != nil {
			return err
		}

		return nil
	}); err != nil {
		panic(err)
	}
	client = openai.NewClient(OpenaiApiKey)
	fs := http.FileServer(http.Dir("./static"))
	mux.Handle("/", fs)
	mux.HandleFunc("/{$}", About)
	mux.HandleFunc("/vision", Vision)
	mux.HandleFunc("/chat", Chat)
	mux.HandleFunc("/cabinet", Cabinet)
	mux.HandleFunc("/register", Register)
	mux.HandleFunc("/login", Login)
	mux.HandleFunc("/tarif", Tarif)
	mux.HandleFunc("/completion", Completion)
	mux.HandleFunc("/prefs", Prefs)
	mux.HandleFunc("/painting", Painting)
	mux.HandleFunc("/files/", Files)
	mux.HandleFunc("/upload", Upload)
	mux.HandleFunc("/uploadassist", UploadAssist)
	mux.HandleFunc("/payment", Payment)
	mux.HandleFunc("/transcription", Transcription)
	mux.HandleFunc("/notification", GetNotification)
	mux.HandleFunc("/speech", Speech)
	// log.Fatal(server.ListenAndServeTLS("", ""))
	log.Fatal(http.Serve(autocert.NewListener("aishapro.com"), mux))
}
