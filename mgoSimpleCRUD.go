package mgoSimpleCRUD

import (
	"crypto"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"encoding/hex"
	"encoding/json"

	"errors"

	"github.com/Luc-cpl/jsonMap"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type Database struct {
	Session           *mgo.Session
	Database          string
	UserIdentityValue string
}

var DB Database

func ConnectToMongo() {

	maxWait := time.Duration(5 * time.Second)

	local, err := mgo.DialWithTimeout("localhost:27017", maxWait)

	if err == nil {
		fmt.Println("Connected to MongoDB.")
		defer local.Close()
		DB.Session = local.Clone()
	} else {
		fmt.Println("Unable to connect to local mongo instance!")
	}
	return
}

func main() {
	ConnectToMongo()

	userIdentity := "meu@email.com"
	pass := "teste"
	userID, err := LoginUser(userIdentity, pass)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(userID)
	}
	_, err = ReadId("users", userID)

	if err != nil {
		fmt.Println(err)
	}
	z := make(map[string]string)
	z[""] = "json:object nome"
	z["nome"] = `{"$regex": "t"}`

	value, err := Find("posts", z)
	if err != nil {
		fmt.Println(err)
	}
	err = DeleteDoc("posts", "5931c7240783e0bdd8bba6f9")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(value)
}

func CreateUser(userIdentity string, password string) (userID string, err error) {
	newSession := Session.Copy()
	defer newSession.Close()

	checkByt := []byte(`{"` + userIdentityValue + `": "` + userIdentity + `"}`)
	var checkInterface interface{}
	err = json.Unmarshal(checkByt, &checkInterface)
	n, err := newSession.DB(database).C("users").Find(checkInterface).Count()

	if err != nil {
		return "", err
	}

	if n != 0 {
		err = errors.New(userIdentityValue + " already registered")
		return "", err
	}

	salt := GenerateSalt(password)
	hash := GenerateHash(password, salt)

	u := make(map[string]string)
	u[""] = "json:object " + userIdentityValue + " password"
	u[userIdentityValue] = `"` + userIdentity + `"`
	u["password"] = "json:object salt hash"
	u["password salt"] = `"` + salt + `"`
	u["password hash"] = `"` + hash + `"`
	jsonByt := []byte(jsonMap.MakeJSON(u, ""))
	var jsonInterface interface{}
	json.Unmarshal(jsonByt, &jsonInterface)
	err = newSession.DB(database).C("users").Insert(jsonInterface)
	if err != nil {
		return "", err
	}
	err = newSession.DB(database).C("users").Find(checkInterface).One(&jsonInterface)
	if err != nil {
		return "", err
	}
	byt, _ := json.Marshal(jsonInterface)
	u, _ = jsonMap.GetMap(byt, "")
	userID = strings.Trim(u["_id"], `"`)

	return userID, nil
}

func LoginUser(userIdentity string, password string) (userID string, err error) {
	newSession := Session.Copy()
	defer newSession.Close()

	checkByt := []byte(`{"` + userIdentityValue + `": "` + userIdentity + `"}`)
	var checkInterface interface{}
	err = json.Unmarshal(checkByt, &checkInterface)

	var jsonInterface interface{}
	err = newSession.DB(database).C("users").Find(checkInterface).One(&jsonInterface)

	if err != nil {
		return "", err
	}

	byt, _ := json.Marshal(jsonInterface)
	u, _ := jsonMap.GetMap(byt, "")
	salt := strings.Trim(u["password salt"], `"`)
	serverHash := strings.Trim(u["password hash"], `"`)

	hash := GenerateHash(password, salt)

	if hash != serverHash {
		err = errors.New("wrong password")
		return "", err
	}

	userID = strings.Trim(u["_id"], `"`)

	return userID, nil
}

func GenerateSalt(password string) string {
	var letters = []rune("abcdefghijklmn" + password + "opqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890123456789" + password)
	b := make([]rune, 20)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func GenerateHash(password string, salt string) string {
	s := password + salt
	hash := crypto.SHA1.New()
	hash.Write([]byte(s))
	hashString := hex.EncodeToString(hash.Sum(nil))

	return hashString
}

func ReadId(collection string, docID string) (doc map[string]string, err error) {
	if collection == "" {
		err := errors.New("missing collection")
		return nil, err
	}
	if docID == "" {
		err := errors.New("missing docID")
		return nil, err
	}

	newSession := Session.Copy()
	defer newSession.Close()

	var jsonFind interface{}
	err = newSession.DB(database).C(collection).FindId(bson.ObjectIdHex(docID)).One(&jsonFind)
	if err != nil {
		return nil, err
	}

	byt, _ := json.Marshal(jsonFind)
	u, _ := jsonMap.GetMap(byt, "")

	return u, nil
}

func CreateInside(collection string, docID string, new map[string]string) error {
	if collection == "" {
		err := errors.New("missing collection")
		return err
	}
	if docID == "" {
		err := errors.New("missing docID")
		return err
	}
	newSession := Session.Copy()
	defer newSession.Close()

	var jsonFind interface{}
	err := newSession.DB(database).C(collection).FindId(bson.ObjectIdHex(docID)).One(&jsonFind)
	if err != nil {
		return err
	}

	byt, _ := json.Marshal(jsonFind)
	u, _ := jsonMap.GetMap(byt, "")
	newMap, err := jsonMap.Create(u, new)
	newMap["_id"] = `ObjectId(` + u["_id"] + `)`
	if err != nil {
		return err
	}

	s := jsonMap.MakeJSON(newMap, "")

	var jsonNew interface{}
	err = bson.UnmarshalJSON([]byte(s), &jsonNew)
	if err != nil {
		err = errors.New("check your json file")
		return err
	}
	err = newSession.DB(database).C(collection).Update(jsonFind, jsonNew)
	if err != nil {
		return err
	}

	return nil
}

func UpdateValue(collection string, docID string, new map[string]string) error {
	if collection == "" {
		err := errors.New("missing collection")
		return err
	}
	if docID == "" {
		err := errors.New("missing docID")
		return err
	}
	newSession := Session.Copy()
	defer newSession.Close()

	var jsonFind interface{}
	err := newSession.DB(database).C(collection).FindId(bson.ObjectIdHex(docID)).One(&jsonFind)
	if err != nil {
		return err
	}

	byt, _ := json.Marshal(jsonFind)
	u, _ := jsonMap.GetMap(byt, "")
	newMap, err := jsonMap.UpdateValue(u, new)
	newMap["_id"] = `ObjectId(` + u["_id"] + `)`
	if err != nil {
		return err
	}

	s := jsonMap.MakeJSON(newMap, "")

	var jsonNew interface{}
	err = bson.Unmarshal([]byte(s), &jsonNew)
	if err != nil {
		err = errors.New("check your json file")
		return err
	}
	err = newSession.DB(database).C(collection).Update(jsonFind, jsonNew)
	if err != nil {
		return err
	}

	return nil
}

func DeleteInside(collection string, docID string, new map[string]string) error {
	if collection == "" {
		err := errors.New("missing collection")
		return err
	}
	if docID == "" {
		err := errors.New("missing docID")
		return err
	}
	newSession := Session.Copy()
	defer newSession.Close()

	var jsonFind interface{}
	err := newSession.DB(database).C(collection).FindId(bson.ObjectIdHex(docID)).One(&jsonFind)
	if err != nil {
		return err
	}

	byt, _ := json.Marshal(jsonFind)
	u, _ := jsonMap.GetMap(byt, "")
	newMap, err := jsonMap.Delete(u, new)
	jsonMap.Delete(u, new)
	newMap["_id"] = `ObjectId(` + u["_id"] + `)`
	if err != nil {
		return err
	}

	s := jsonMap.MakeJSON(newMap, "")

	var jsonNew interface{}
	err = bson.Unmarshal([]byte(s), &jsonNew)
	if err != nil {
		err = errors.New("check your json file")
		return err
	}
	err = newSession.DB(database).C(collection).Update(jsonFind, jsonNew)
	if err != nil {
		return err
	}

	return nil
}

func CreateDoc(collection string, new map[string]string) error {
	if collection == "" {
		err := errors.New("missing collection")
		return err
	}
	newSession := Session.Copy()
	defer newSession.Close()

	s := jsonMap.MakeJSON(new, "")
	var jsonNew interface{}
	err := json.Unmarshal([]byte(s), &jsonNew)
	if err != nil {
		err = errors.New("check your json file")
		return err
	}

	err = newSession.DB(database).C(collection).Insert(jsonNew)

	return err
}

func Find(collection string, request map[string]string) (doc map[string]string, err error) {
	if collection == "" {
		err := errors.New("missing collection")
		return nil, err
	}
	newSession := Session.Copy()
	defer newSession.Close()

	s := jsonMap.MakeJSON(request, "")
	var jsonNew interface{}
	if s != "" {
		err = json.Unmarshal([]byte(s), &jsonNew)
		if err != nil {
			err = errors.New("check your json map")
			return nil, err
		}
	}

	var jsonFind []interface{}
	err = newSession.DB(database).C(collection).Find(jsonNew).All(&jsonFind)
	if err != nil {
		return nil, err
	}

	byt, _ := json.Marshal(jsonFind)
	u, _ := jsonMap.GetMap(byt, "")

	return u, nil
}

func FindOne(collection string, request map[string]string) (doc map[string]string, err error) {
	if collection == "" {
		err := errors.New("missing collection")
		return nil, err
	}
	newSession := Session.Copy()
	defer newSession.Close()

	s := jsonMap.MakeJSON(request, "")
	var jsonNew interface{}
	err = json.Unmarshal([]byte(s), &jsonNew)
	if err != nil {
		err = errors.New("check your json map")
		return nil, err
	}

	var jsonFind interface{}
	err = newSession.DB(database).C(collection).Find(jsonNew).One(&jsonFind)
	if err != nil {
		return nil, err
	}

	byt, _ := json.Marshal(jsonFind)
	u, _ := jsonMap.GetMap(byt, "")

	return u, nil
}

func DeleteDoc(collection string, docID string) error {
	if collection == "" {
		err := errors.New("missing collection")
		return err
	}
	if docID == "" {
		err := errors.New("missing docID")
		return err
	}

	newSession := Session.Copy()
	defer newSession.Close()

	err := newSession.DB(database).C(collection).RemoveId(bson.ObjectIdHex(docID))
	if err != nil {
		return err
	}

	return nil
}
