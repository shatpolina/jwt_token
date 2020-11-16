package main

import (
    "fmt"
    "net/http"
    "io/ioutil"
    "encoding/json"
    "github.com/gorilla/mux"
    "golang.org/x/crypto/bcrypt"
    "go.mongodb.org/mongo-driver/mongo"
)

type DBAccess struct {
    URI string `json:"uri"`
}

type User struct {
    GUID uint `json:"guid"`
}

func createBcrypt(data string) ([]byte, error) {
    return bcrypt.GenerateFromPassword([]byte(data), bcrypt.DefaultCost)
}

func main() {
    dbAccessString, err := ioutil.ReadFile("./dbaccess.json")
    if (err != nil) {
        fmt.Println(err)
        return
    }

    var dbAccess DBAccess
    err = json.Unmarshal(dbAccessString, &dbAccess)
    if (err != nil) {
        fmt.Println(err)
        return
    }

    dbClient, dbContext, err = initDB(dbAccess.URI)
    if (err != nil) {
        fmt.Println(err)
        return
    }
    defer dbClient.Disconnect(dbContext)

    fmt.Println("Connected to DB")

    r := mux.NewRouter()

    r.HandleFunc("/", mainPage).Methods("GET")
    r.HandleFunc("/tokenCreate", tokenCreate).Methods("PUT")
    r.HandleFunc("/tokenRefresh", tokenRefresh).Methods("POST")
    r.HandleFunc("/tokenDelete", tokenDelete).Methods("DELETE")
    r.HandleFunc("/tokenDeleteAll", tokenDeleteAll).Methods("DELETE")

    http.ListenAndServe(":3000", r)
}

func mainPage(w http.ResponseWriter, r *http.Request) {
    dat, err := ioutil.ReadFile("./index.html")
    if (err != nil) {
        fmt.Println(err)
        w.WriteHeader(http.StatusInternalServerError)
        return
    }

    fmt.Fprint(w, string(dat))
}

func tokenCreate(w http.ResponseWriter, r *http.Request) {
    var user User
    err := json.NewDecoder(r.Body).Decode(&user)
    if (err != nil) {
        fmt.Println(err)
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    err = makeTransaction(func(ctx mongo.SessionContext) error {
        var pair TokenPair
        err := generateAndInsertTokens(ctx, user.GUID, &pair)
        if (err != nil) {
            w.WriteHeader(http.StatusInternalServerError)
            return err
        }

        json.NewEncoder(w).Encode(pair)
        return nil
    })

    if (err != nil) {
        fmt.Println(err)
    }
}

func tokenRefresh(w http.ResponseWriter, r *http.Request) {
    type CommandRefresh struct {
        Tokens TokenPair `json:"tokens"`
    }

    var data CommandRefresh
    err := json.NewDecoder(r.Body).Decode(&data)
    if (err != nil) {
        fmt.Println(err)
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    var token Token
    err = tokenVerify(w, r, data.Tokens.Refresh, "refresh", &token)
    if (err != nil) {
        fmt.Println(err)
        return
    }

    err = makeTransaction(func(ctx mongo.SessionContext) error {
        var pair TokenPair
        err = findByAccess(ctx, data.Tokens.Access, &pair)
        if (err != nil) {
            w.WriteHeader(http.StatusUnauthorized)
            return err
        }

        err = bcrypt.CompareHashAndPassword([]byte(pair.Refresh), []byte(data.Tokens.Refresh))
        if (err != nil) {
            w.WriteHeader(http.StatusUnauthorized)
            return err
        }

        err = deleteByAccess(ctx, data.Tokens.Access)
        if (err != nil) {
            w.WriteHeader(http.StatusInternalServerError)
            return err
        }

        err = generateAndInsertTokens(ctx, token.GUID, &pair)
        if (err != nil) {
            w.WriteHeader(http.StatusInternalServerError)
            return err
        }

        json.NewEncoder(w).Encode(pair)
        return nil
    })

    if (err != nil) {
        fmt.Println(err)
    }
}

func tokenDelete(w http.ResponseWriter, r *http.Request) {
    type CommandDelete struct {
        Tokens TokenPair `json:"tokens"`
    }

    var data CommandDelete
    err := json.NewDecoder(r.Body).Decode(&data)
    if (err != nil) {
        fmt.Println(err)
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    var token Token
    err = tokenVerify(w, r, data.Tokens.Access, "access", &token)
    if (err != nil) {
        fmt.Println(err)
        return
    }

    err = makeTransaction(func(ctx mongo.SessionContext) error {
        var pair TokenPair
        err = findByAccess(ctx, data.Tokens.Access, &pair)
        if (err != nil) {
            w.WriteHeader(http.StatusUnauthorized)
            return err
        }

        err = bcrypt.CompareHashAndPassword([]byte(pair.Refresh), []byte(data.Tokens.Refresh))
        if (err != nil) {
            w.WriteHeader(http.StatusUnauthorized)
            return err
        }

        err = deleteByAccess(ctx, data.Tokens.Access)
        if (err != nil) {
            w.WriteHeader(http.StatusInternalServerError)
            return err
        }

        return nil
    })

    if (err != nil) {
        fmt.Println(err)
    }
}

func tokenDeleteAll(w http.ResponseWriter, r *http.Request) {
    type CommandDeleteAll struct {
        AccessToken string `json:"token"`
    }

    var data CommandDeleteAll
    err := json.NewDecoder(r.Body).Decode(&data)
    if (err != nil) {
        fmt.Println(err)
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    var token Token
    err = tokenVerify(w, r, data.AccessToken, "access", &token)
    if (err != nil) {
        fmt.Println(err)
        return
    }

    err = makeTransaction(func(ctx mongo.SessionContext) error {
        var pair TokenPair
        err = findByAccess(ctx, data.AccessToken, &pair)
        if (err != nil) {
            w.WriteHeader(http.StatusUnauthorized)
            return err
        }

        err = deleteByUser(ctx, token.GUID)
        if (err != nil) {
            w.WriteHeader(http.StatusUnauthorized)
            return err
        }

        return nil
    })

    if (err != nil) {
        fmt.Println(err)
    }
}
