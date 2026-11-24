// Seed the databases that do not come with a command-line client in the
// reference environment, using the dependencies pinned by go-auth's go.mod.
package main

import (
	"context"
	"database/sql"
	"log"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatal("usage: seed sqlite|mongo target password-hash")
	}
	var err error
	switch os.Args[1] {
	case "sqlite":
		err = seedSQLite(os.Args[2], os.Args[3])
	case "mongo":
		err = seedMongo(os.Args[2], os.Args[3])
	default:
		log.Fatalf("unknown fixture: %s", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

func seedSQLite(path, hash string) error {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE users (name TEXT PRIMARY KEY, hash TEXT);
		CREATE TABLE acl (name TEXT, access INTEGER, topic TEXT);
		INSERT INTO acl VALUES ('alice',1,'allowed'), ('alice',2,'allowed'), ('alice',4,'allowed');`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO users VALUES ('alice', ?)`, hash)
	return err
}

func seedMongo(uri, hash string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return err
	}
	defer client.Disconnect(ctx)
	db := client.Database("mosquitto")
	_, err = db.Collection("users").InsertOne(ctx, bson.M{
		"username": "alice",
		"password": hash,
		"acls":     bson.A{bson.M{"topic": "allowed", "acc": 3}},
	})
	return err
}
