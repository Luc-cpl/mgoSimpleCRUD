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

	n, err := newSession.DB(DB.Database).C("users").Find(checkInterface).Count()

	if err != nil {
		return "", err
	}

	if n != 0 {
		err = errors.New(DB.UserIdentityValue + " already registered")
		return "", err
	}

	err = newSession.DB(DB.Database).C("users").Insert(jsonInterface)
	if err != nil {
		return "", err
	}
	for i := 0; i < 100000; i++ {
		err = newSession.DB(DB.Database).C("users").Find(checkInterface).One(&jsonInterface)
		if err == nil {
			break
		}
	}
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
	if bson.IsObjectIdHex(docID) == false {
		err = errors.New("the passed id is not a object id")
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
	for i := 0; i < 100000; i++ {
		err = newSession.DB(DB.Database).C(collection).Update(jsonOld, jsonNew)
		if err == nil {
			break
		}
	}
	if err != nil {
		err = errors.New("failed on document update")
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

	for i := 0; i < 100000; i++ {
		err = newSession.DB(DB.Database).C(collection).Update(jsonOld, jsonNew)
		if err == nil {
			break
		}
	}
	if err != nil {
		err = errors.New("failed on document update")
		return err
	}

	return nil
}

//DeleteInside deletes a value inside a document on database
func (DB Database) DeleteInside(collection string, originalMap map[string]string, deleteMap map[string]string) error {
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
	newMap, err := jsonMap.Delete(originalMap, deleteMap)
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

	for i := 0; i < 100000; i++ {
		err = newSession.DB(DB.Database).C(collection).Update(jsonOld, jsonNew)
		if err == nil {
			break
		}
	}
	if err != nil {
		err = errors.New("failed on document update")
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
	var jsonNew interface{}
	if len(request) != 1 {
		s := jsonMap.MakeJSON(request, "")
		if s != "" {
			err = json.Unmarshal([]byte(s), &jsonNew)
			if err != nil {
				err = errors.New("check your json map")
				return nil, err
			}
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

	var jsonNew interface{}
	if len(request) != 1 {
		s := jsonMap.MakeJSON(request, "")
		if s != "" {
			err = json.Unmarshal([]byte(s), &jsonNew)
			if err != nil {
				err = errors.New("check your json map")
				return nil, err
			}
		}
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
	bytRequest, _ := json.Marshal(request.Request)
	mapRequest, err := jsonMap.GetMap(bytRequest, "")
	if err != nil {
		return nil, err
	}

	u := make([]map[string]string, 1)
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
		} else {
			u, err = DB.Find(request.Collection, mapRequest)
			if err != nil {
				return nil, err
			}
		}
	}

	mapValueArr := make([]map[string]string, len(u))
	var crudMethod string
	for z := range u {
		mapValues, err := jsonMap.GetMap(bytValues, "")
		if err != nil {
			return nil, err
		}
		//define methods
		switch request.Method {
		case "update":
			delete(mapValues, "")
			crudMethod = "update"
		case "find":
			crudMethod = "read"
		case "findOne":
			crudMethod = "read"
		case "readID":
			crudMethod = "read"
		case "createDoc":
			crudMethod = "create"
		case "create":
			delete(mapValues, "")
			crudMethod = "create"
		case "deleteDoc":
			mapValues[""] = ""
			crudMethod = "delete"
		case "delete":
			delete(mapValues, "")
			crudMethod = "delete"
		default:
			err = errors.New("wrong method")
			return nil, err
		}

		arr := makeArr(u[z], mapValues)
		mapValueArr[z] = arr
	}

	authMap, err := loadAuthMap(authMapFile)
	if err != nil {
		return nil, err
	}

	r := make([]map[string]string, len(u))
	z := 0
	for y := 0; y < len(mapValueArr); y++ {
		auths := make(map[string]string)
		auths, err = authRequest(user, request.Collection, mapValueArr[y], authMap)
		if err != nil {
			return nil, err
		}

		for n := range mapValueArr[y] {
			if _, exist := auths[n]; exist == false {
				sa := strings.Split(n, " ")
				err = errors.New(sa[len(sa)-1] + "_auth dont find on authMap file")
				return nil, err
			}
		}

		if request.Method != "createDoc" {
			v := make(map[string]string)
			auth := false
			var errU error
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
					case "g-" + crudMethod:
						gAuth = true
					case "a-" + crudMethod:
						aAuth = true
					case "u-" + crudMethod:
						uAuth = true
					case "c-" + crudMethod:
						cAuth = true
					case "sc-" + crudMethod:
						scAuth = true
					case "adm-" + crudMethod:
						admAuth = true
					case "g-all":
						gAuth = true
					case "a-all":
						aAuth = true
					case "u-all":
						uAuth = true
					case "c-all":
						cAuth = true
					case "sc-all":
						scAuth = true
					case "adm-all":
						admAuth = true
					case "blacklist":
						blacklist = true
					}
				}
				//check if user have the auths and fuels a map for read method
				if gAuth {
					if val, exist := u[y][n]; exist {
						v[n] = val
					}
					auth = true
				} else if user.ID != "" && aAuth {
					if val, exist := u[y][n]; exist {
						v[n] = val
					}
					auth = true
				} else if u[y]["_id"] == `"`+user.ID+`"` && uAuth {
					if val, exist := u[y][n]; exist {
						v[n] = val
					}
					auth = true
				} else if _, exist := u[y]["contacts "+user.ID]; exist && cAuth {
					if val, exist := u[y][n]; exist {
						v[n] = val
					}
					auth = true
				} else if _, exist := mapValueArr[y]["contacts "+user.ID]; exist && scAuth {
					if mapValueArr[y]["contacts"] == "json:object "+user.ID {
						if val, exist := u[y][n]; exist {
							v[n] = val
						}
						auth = true
					} else {
						auth = false
						if crudMethod != "read" {
							break
						}
					}
				} else if user.Admin && admAuth {
					if val, exist := u[y][n]; exist {
						v[n] = val
					}
					auth = true
				} else if _, exist := u[y]["blacklist "+user.ID]; exist && blacklist {
					auth = false
					bl = true
					delete(v, n)
					if crudMethod != "read" {
						break
					}
				} else {
					auth = false
					if crudMethod != "read" {
						break
					}
				}
			}
			if auth {
				switch crudMethod {
				case "create":
					errU = DB.CreateInside(request.Collection, u[y], mapValueArr[y])
					if errU != nil {
						return nil, err
					}
				case "delete":
					switch request.Method {
					case "delete":
						errU = DB.DeleteInside(request.Collection, u[y], mapValueArr[y])
					case "deleteDoc":
						errU = DB.DeleteDoc(request.Collection, strings.Trim(u[y]["_id"], `"`))
					}
				case "update":
					errU = DB.UpdateValue(request.Collection, u[y], mapValueArr[y])
				}
				if bl && crudMethod != "read" {
					z++
				}
				if errU == nil {
					z++
				}
			}
			if crudMethod == "read" {
				r[y] = v
			}

		} else if request.Method == "createDoc" && y == 1 {
			//auths check for create Doc
			auth := false
			array := strings.Split(auths[""], " ")
			gAuth := false
			aAuth := false
			admAuth := false
			for _, el := range array {
				el = strings.Trim(el, `"`)
				switch el {
				case "g-" + crudMethod:
					gAuth = true
				case "a-" + crudMethod:
					aAuth = true
				case "adm-" + crudMethod:
					admAuth = true
				case "g-all":
					gAuth = true
				case "a-all":
					aAuth = true
				case "adm-all":
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
			if auth {
				err = DB.CreateDoc(request.Collection, mapValueArr[y])
				if err != nil {
					response = []byte(`{"` + crudMethod + `": 0 }`)
				} else {
					response = []byte(`{"` + crudMethod + `": 1 }`)
				}
			}

		}
	}

	if crudMethod == "read" {
		response = joinTo(mapValueArr, r)
	} else {
		response = []byte(`{"` + crudMethod + `": ` + strconv.Itoa(z) + ` }`)
	}

	//send the response file for read method and if exists, an error
	return response, err
}

func joinTo(original []map[string]string, new []map[string]string) []byte {
	arr := make([]map[string]string, len(new))

	for key, el := range new {
		newM := make(map[string]string)
		for n := range original[key] {
			if val, exist := el[n]; exist {
				newM[n] = val
			} else {
				newM[n] = original[key][n]
			}
		}

		if newM != nil {
			arr[key] = newM
		}
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
		key := strings.Replace(keyO, user.ID, "&obj_id", -1)
		keyArr := strings.Split(key, " ")
		for k := range keyArr {
			_, err := strconv.Atoi(keyArr[k])
			if err != nil && strings.Contains(keyArr[k], "&new") == false {
				if k == 0 {
					key = keyArr[k]
				} else if bson.IsObjectIdHex(keyArr[k]) {
					key += " &obj_id"
				} else if strings.Contains(keyArr[k], "&arr:") == false {
					key += " " + keyArr[k]
				}
			} else if k != len(keyArr)-1 {
				key += " 0"
			}
		}
		if key != "" {
			key = " " + key
		}
		for n := range arr {
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

func makeArr(original map[string]string, new map[string]string) map[string]string {
	new2 := make(map[string]string)
	del := make(map[string]string)
	new2 = new
	finished := false
	for finished == false {
		finished = true
		for n := range new2 {
			if strings.HasPrefix(new2[n], "json:object &arr:") {
				finished = false
				arr := strings.Split(new2[n], " ")
				sArr := strings.Split(strings.TrimLeft(new2[n], "json:object &arr:"), "-")
				t := strings.TrimRight(n, " "+arr[1])
				tArr := strings.Split(original[t], " ")
				n1, _ := strconv.Atoi(tArr[len(tArr)-1])
				n1++
				n0, err := strconv.Atoi(sArr[0])
				if err == nil {
					if len(sArr) == 2 {
						nt, err := strconv.Atoi(sArr[1])
						if err == nil && nt < n1 {
							n1 = nt
						}
					}
				} else {
					n0 = 1
				}
				new2[n] = "json:array"
				for i := n0 - 1; i < n1; i++ {
					new2[n] += " " + strconv.Itoa(i)
					for k := range new2 {
						if strings.HasPrefix(k, n+" "+arr[1]) {
							nK := strings.TrimSpace(n + " " + strconv.Itoa(i) + " " + strings.TrimLeft(k, n+" "+arr[1]))
							new2[nK] = new2[k]
							del[k] = ""
						}
					}
				}
				if n0 > n1 {
					new2[n] += " "
					for k := range new2 {
						if strings.HasPrefix(k, n+" "+arr[1]) {
							//sp := strings.Split(n, " ")
							//dl := sp[len(sp)-1]
							//dkey := strings.TrimRight(n, " "+dl)
							//dMap := make(map[string]string)
							//dMap[dkey] = dl
							//new2, _ = jsonMap.Delete(new2, dMap)
							del[k] = ""
						}
					}
				}
			}
		}
	}
	for n := range del {
		delete(new2, n)
	}

	return new2
}
