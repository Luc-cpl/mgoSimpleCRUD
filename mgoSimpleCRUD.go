package mgoSimpleCRUD

import (
	"crypto"
	"io/ioutil"
	"math/rand"
	"strconv"
	"strings"

	"encoding/hex"
	"encoding/json"

	"errors"

	"github.com/Luc-cpl/jsonMap"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type User struct {
	ID    string
	Admin bool
}

type Request struct {
	Method     string      `json:"method"`
	Collection string      `json:"collection"`
	Values     interface{} `json:"values"`
	Request    interface{} `json:"request"`
	ID         string      `json:"id"`
}
type Database struct {
	Session           *mgo.Session
	Database          string
	UserIdentityValue string
}

var DB Database

//CreateUser creates a user on an "users" collection on the database
func (DB Database) CreateUser(userIdentity string, password string) (userID string, err error) {
	newSession := DB.Session.Copy()
	defer newSession.Close()

	checkByt := []byte(`{"` + DB.UserIdentityValue + `": "` + userIdentity + `"}`)
	var checkInterface interface{}
	err = json.Unmarshal(checkByt, &checkInterface)
	n, err := newSession.DB(DB.Database).C("users").Find(checkInterface).Count()

	if err != nil {
		return "", err
	}

	if n != 0 {
		err = errors.New(DB.UserIdentityValue + " already registered")
		return "", err
	}

	salt := GenerateSalt(password)
	hash := GenerateHash(password, salt)

	u := make(map[string]string)
	u[""] = "json:object " + DB.UserIdentityValue + " password"
	u[DB.UserIdentityValue] = `"` + userIdentity + `"`
	u["password"] = "json:object salt hash"
	u["password salt"] = `"` + salt + `"`
	u["password hash"] = `"` + hash + `"`
	jsonByt := []byte(jsonMap.MakeJSON(u, ""))
	var jsonInterface interface{}
	json.Unmarshal(jsonByt, &jsonInterface)
	err = newSession.DB(DB.Database).C("users").Insert(jsonInterface)
	if err != nil {
		return "", err
	}
	err = newSession.DB(DB.Database).C("users").Find(checkInterface).One(&jsonInterface)
	if err != nil {
		return "", err
	}
	byt, _ := json.Marshal(jsonInterface)
	u, _ = jsonMap.GetMap(byt, "")
	userID = strings.Trim(u["_id"], `"`)

	return userID, nil
}

//LoginUser checks the parameters passed and the "users" collection and response whith an ID if the userIdentity and password is whright
func (DB Database) LoginUser(userIdentity string, password string) (userID string, err error) {
	newSession := DB.Session.Copy()
	defer newSession.Close()

	checkByt := []byte(`{"` + DB.UserIdentityValue + `": "` + userIdentity + `"}`)
	var checkInterface interface{}
	err = json.Unmarshal(checkByt, &checkInterface)

	var jsonInterface interface{}
	err = newSession.DB(DB.Database).C("users").Find(checkInterface).One(&jsonInterface)

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

//ReadId reads an ID pased in an collection on database
func (DB Database) ReadId(collection string, docID string) (doc map[string]string, err error) {
	if collection == "" {
		err := errors.New("missing collection")
		return nil, err
	}
	if docID == "" {
		err := errors.New("missing docID")
		return nil, err
	}

	newSession := DB.Session.Copy()
	defer newSession.Close()

	var jsonFind interface{}
	err = newSession.DB(DB.Database).C(collection).FindId(bson.ObjectIdHex(docID)).One(&jsonFind)
	if err != nil {
		return nil, err
	}

	byt, _ := json.Marshal(jsonFind)
	u, _ := jsonMap.GetMap(byt, "")

	return u, nil
}

//CreateInside creates value inside an object or arrai in a document on database
func (DB Database) CreateInside(collection string, originalMap map[string]string, new map[string]string) error {
	if collection == "" {
		err := errors.New("missing collection")
		return err
	}
	if originalMap == nil {
		err := errors.New("missing oldDoc")
		return err
	}
	originalMap["_id"] = `ObjectId(` + originalMap["_id"] + `)`
	o := []byte(jsonMap.MakeJSON(originalMap, ""))

	var jsonOld interface{}
	err := bson.UnmarshalJSON(o, &jsonOld)
	if err != nil {
		err = errors.New("check your original json file")
		return err
	}

	newSession := DB.Session.Copy()
	defer newSession.Close()

	newMap, err := jsonMap.Create(originalMap, new)
	newMap["_id"] = originalMap["_id"]
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
	err = newSession.DB(DB.Database).C(collection).Update(jsonOld, jsonNew)
	if err != nil {
		return err
	}

	return nil
}

//UpdateValue updates a value inside the database
func (DB Database) UpdateValue(collection string, oldMap map[string]string, new map[string]string) error {
	if collection == "" {
		err := errors.New("missing collection")
		return err
	}
	if oldMap == nil {
		err := errors.New("missing oldDoc")
		return err
	}
	oldMap["_id"] = `ObjectId(` + oldMap["_id"] + `)`
	o := []byte(jsonMap.MakeJSON(oldMap, ""))

	var jsonOld interface{}
	err := bson.UnmarshalJSON(o, &jsonOld)
	if err != nil {
		err = errors.New("check your old json file")
		return err
	}

	newSession := DB.Session.Copy()
	defer newSession.Close()
	newMap, err := jsonMap.UpdateValue(oldMap, new)
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

	err = newSession.DB(DB.Database).C(collection).Update(jsonOld, jsonNew)
	if err != nil {
		return err
	}

	return nil
}

//DeleteInside deletes a value inside a document on database
func (DB Database) DeleteInside(collection string, docID string, deleteMap map[string]string) error {
	if collection == "" {
		err := errors.New("missing collection")
		return err
	}
	if docID == "" {
		err := errors.New("missing docID")
		return err
	}
	newSession := DB.Session.Copy()
	defer newSession.Close()

	var jsonFind interface{}
	err := newSession.DB(DB.Database).C(collection).FindId(bson.ObjectIdHex(docID)).One(&jsonFind)
	if err != nil {
		return err
	}

	byt, _ := json.Marshal(jsonFind)
	u, _ := jsonMap.GetMap(byt, "")
	newMap, err := jsonMap.Delete(u, deleteMap)
	jsonMap.Delete(u, deleteMap)
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
	err = newSession.DB(DB.Database).C(collection).Update(jsonFind, jsonNew)
	if err != nil {
		return err
	}

	return nil
}

//CreateDoc creates a document on database
func (DB Database) CreateDoc(collection string, new map[string]string) error {
	if collection == "" {
		err := errors.New("missing collection")
		return err
	}
	newSession := DB.Session.Copy()
	defer newSession.Close()

	s := jsonMap.MakeJSON(new, "")
	var jsonNew interface{}
	err := json.Unmarshal([]byte(s), &jsonNew)
	if err != nil {
		err = errors.New("check your json file")
		return err
	}

	err = newSession.DB(DB.Database).C(collection).Insert(jsonNew)

	return err
}

//Find search for the request ia a collection and response whith all documents finded
func (DB Database) Find(collection string, request map[string]string) (doc []map[string]string, err error) {
	if collection == "" {
		err := errors.New("missing collection")
		return nil, err
	}
	newSession := DB.Session.Copy()
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
	err = newSession.DB(DB.Database).C(collection).Find(jsonNew).All(&jsonFind)
	if err != nil {
		return nil, err
	}
	u := make([]map[string]string, len(jsonFind))
	for n := range jsonFind {
		byt, _ := json.Marshal(jsonFind[n])
		u[n], _ = jsonMap.GetMap(byt, "")
	}

	return u, nil
}

//FindOne search for the request ia a collection and response whith one document finded
func (DB Database) FindOne(collection string, request map[string]string) (doc map[string]string, err error) {
	if collection == "" {
		err := errors.New("missing collection")
		return nil, err
	}
	newSession := DB.Session.Copy()
	defer newSession.Close()

	s := jsonMap.MakeJSON(request, "")
	var jsonNew interface{}
	err = json.Unmarshal([]byte(s), &jsonNew)
	if err != nil {
		err = errors.New("check your json map")
		return nil, err
	}

	var jsonFind interface{}
	err = newSession.DB(DB.Database).C(collection).Find(jsonNew).One(&jsonFind)
	if err != nil {
		return nil, err
	}

	byt, _ := json.Marshal(jsonFind)
	u, _ := jsonMap.GetMap(byt, "")

	return u, nil
}

//DeleteDoc deletes a document on database
func (DB Database) DeleteDoc(collection string, docID string) error {
	if collection == "" {
		err := errors.New("missing collection")
		return err
	}
	if docID == "" {
		err := errors.New("missing docID")
		return err
	}

	newSession := DB.Session.Copy()
	defer newSession.Close()

	err := newSession.DB(DB.Database).C(collection).RemoveId(bson.ObjectIdHex(docID))
	if err != nil {
		return err
	}

	return nil
}

//CRUDRequest reads a Request and connect the user whit the mongo database whit CRUD methods.
//See the jsonMap format to see how send the Request.Values and use a simple json according to your database in the Request.Request to find a specific field.
//Methods : "update" "find" "findOne" "readID" "createDoc" "create" "deleteDoc" "delete"
//the request json model:
//{"method": " the method to use ","collection": " the collection name ","values":{ the values to read, insert, update or delete }, "request":{ the request to find } "id":"the id of the object to find"}
func CRUDRequest(user User, request Request, authMapFile string) (response []byte, err error) {
	bytValues, _ := json.Marshal(request.Values)
	mapValues, err := jsonMap.GetMap(bytValues, "")
	if err != nil {
		return nil, err
	}
	bytRequest, _ := json.Marshal(request.Request)
	mapRequest, err := jsonMap.GetMap(bytRequest, "")
	if err != nil {
		return nil, err
	}

	var crudMehod string
	//define methods
	switch request.Method {
	case "update":
		delete(mapValues, "")
		crudMehod = "update"
	case "find":
		crudMehod = "read"
	case "findOne":
		crudMehod = "read"
	case "readID":
		crudMehod = "read"
	case "createDoc":
		crudMehod = "create"
	case "create":
		delete(mapValues, "")
		crudMehod = "create"
	case "deleteDoc":
		crudMehod = "delete"
	case "delete":
		delete(mapValues, "")
		crudMehod = "delete"
	default:
		err = errors.New("wrong method")
		return nil, err
	}

	authMap, err := loadAuthMap(authMapFile)
	if err != nil {
		return nil, err
	}
	auths, err := authRequest(user, request.Collection, mapValues, authMap)
	if err != nil {
		return nil, err
	}
	auth := false
	for n := range mapValues {
		if _, exist := auths[n]; exist == false {
			sa := strings.Split(n, " ")
			err = errors.New(sa[len(sa)-1] + "_auth dont find on authMap file")
			return nil, err
		}
	}
	u := make([]map[string]string, 1)
	method := request.Method
	bl := false
	if request.Method != "createDoc" {
		if request.ID != "" {
			u[0], err = DB.ReadId(request.Collection, request.ID)
			if err != nil {
				return nil, err
			}
		} else if request.Method == "findOne" {
			u[0], err = DB.FindOne(request.Collection, mapRequest)
			if err != nil {
				return nil, err
			}
		} else if request.Method == "findAll" {
			u, err = DB.Find(request.Collection, mapRequest)
			if err != nil {
				return nil, err
			}
		}
		r := make([]map[string]string, len(u))
		v := make(map[string]string)
		for t := range u {
			for n := range auths {
				array := strings.Split(auths[n], " ")
				gAuth := false
				aAuth := false
				uAuth := false
				cAuth := false
				scAuth := false
				admAuth := false
				blacklist := false
				for _, el := range array {
					el = strings.Trim(el, `"`)
					//find the auths needed
					switch el {
					case "g-" + crudMehod:
						gAuth = true
					case "a-" + crudMehod:
						aAuth = true
					case "u-" + crudMehod:
						uAuth = true
					case "c-" + crudMehod:
						cAuth = true
					case "sc-" + crudMehod:
						scAuth = true
					case "adm-" + crudMehod:
						admAuth = true
					case "blacklist":
						blacklist = true
					}
				}
				//check if user have the auths and fuels a map for read method
				if gAuth {
					if val, exist := u[t][n]; exist {
						v[n] = val
					}
					auth = true
				} else if user.ID != "" && aAuth {
					if val, exist := u[t][n]; exist {
						v[n] = val
					}
					auth = true
				} else if u[t]["_id"] == `"`+user.ID+`"` && uAuth {
					if val, exist := u[t][n]; exist {
						v[n] = val
					}
					auth = true
				} else if _, exist := u[t]["contacts "+user.ID]; exist && cAuth {
					if val, exist := u[t][n]; exist {
						v[n] = val
					}
					auth = true
				} else if _, exist := mapValues["contacts "+user.ID]; exist && scAuth {
					if mapValues["contacts"] == "json:object "+user.ID {
						if val, exist := u[t][n]; exist {
							v[n] = val
						}
						auth = true
					}
				} else if user.Admin && admAuth {
					if val, exist := u[t][n]; exist {
						v[n] = val
					}
					auth = true
				} else if _, exist := u[t]["blacklist "+user.ID]; exist && blacklist {
					auth = false
					bl = true
					if crudMehod != "read" {
						break
					}
				} else {
					auth = false
					if crudMehod != "read" {
						break
					}
				}
			}
			r[t] = v
		}
		response = joinTo(mapValues, r)
	} else {
		//auths check for create Doc
		array := strings.Split(auths[""], " ")
		gAuth := false
		aAuth := false
		admAuth := false
		for _, el := range array {
			el = strings.Trim(el, `"`)
			switch el {
			case "g-" + crudMehod:
				gAuth = true
			case "a-" + crudMehod:
				aAuth = true
			case "adm-" + crudMehod:
				admAuth = true
			}
		}
		if gAuth {
			auth = true
		} else if user.ID != "" && aAuth {
			auth = true
		} else if user.Admin && admAuth {
			auth = true
		} else {
			auth = false
		}
	}
	//execute the methods (create | update | delete)
	if auth {
		switch method {
		case "update":
			for n := range u {
				err = DB.UpdateValue(request.Collection, u[n], mapValues)
				if err != nil {
					break
				}
			}
			return nil, err
		case "createDoc":
			err = DB.CreateDoc(request.Collection, mapValues)
			if err != nil {
				break
			}
			return nil, err
		case "create":
			for n := range u {
				err = DB.CreateInside(request.Collection, u[n], mapValues)
				if err != nil {
					break
				}
			}
			return nil, err
		case "deleteDoc":
			for n := range u {
				err = DB.DeleteDoc(request.Collection, strings.Trim(u[n]["_id"], `"`))
				if err != nil {
					break
				}
			}
			return nil, err
		case "delete":
			for n := range u {
				err = DB.DeleteInside(request.Collection, strings.Trim(u[n]["_id"], `"`), mapValues)
				if err != nil {
					break
				}
			}
			return nil, err
		}
	} else if crudMehod != "read" && bl == false {
		err = errors.New("permission denied")
	}
	//send the response file for read method and if exists, an error
	return response, err
}

func joinTo(original map[string]string, new []map[string]string) []byte {
	arr := make([]map[string]string, len(new))
	for key, el := range new {
		newM := make(map[string]string)
		for n := range original {
			if _, exist := el[n]; exist == false {
				newM[n] = original[n]
			} else {
				newM[n] = el[n]
			}
		}
		arr[key] = newM
	}
	newS := "["
	for i := 0; i < len(arr); i++ {
		switch i {
		case 0:
			newS += jsonMap.MakeJSON(arr[i], "")
		default:
			newS += "," + jsonMap.MakeJSON(arr[i], "")
		}
	}
	newS += "]"

	response := []byte(newS)

	return response
}

func loadAuthMap(path string) (authMap map[string]string, err error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return jsonMap.GetMap(file, "")
}

func authRequest(user User, collection string, createMap map[string]string, authMap map[string]string) (auths map[string]string, err error) {
	arr := strings.Split(strings.TrimLeft(authMap[""], "json:array "), " ")
	response := make(map[string]string)
	auth := false
	for keyO := range createMap {
		key := strings.Replace(keyO, user.ID, "&user_id", -1)
		keyArr := strings.Split(key, " ")
		for k := range keyArr {
			_, err := strconv.Atoi(keyArr[k])
			if err == nil {
				keyArr[k] = "0"
			} else if keyArr[k] == "&new" {
				keyArr[k] = "0"
			}
		}
		key = strings.Join(keyArr, " ")
		for n := range arr {
			if key != "" && n == 0 {
				key = " " + key
			}
			if val, exist := authMap[arr[n]+" "+collection+key+"_auth"]; exist {
				response[keyO] = val
				auth = true
			} else if val, exist := authMap[arr[n]+" "+collection+key]; exist {
				trim := strings.TrimLeft(val, "json:object ")
				trim = strings.TrimLeft(trim, "json:array ")
				if trim == val {
					response[keyO] = val
					auth = true
				}
			}
		}
	}
	if auth == false {
		err = errors.New("auth flag not find")
		return nil, err
	}
	return response, err
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
