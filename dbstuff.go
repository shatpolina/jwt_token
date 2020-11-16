package main

import (
    "time"
    "context"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    "go.mongodb.org/mongo-driver/bson/primitive"
)

var dbClient *mongo.Client
var dbContext context.Context

func initDB(uri string) (*mongo.Client, context.Context, error) {
    client, err := mongo.NewClient(options.Client().ApplyURI("mongodb://localhost:27017"))
    if err != nil {
        return nil, nil, err
    }

    ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
    err = client.Connect(ctx)
    if err != nil {
        return nil, nil, err
    }

    _, err = client.Database("jwt").Collection("users").Indexes().CreateOne(
        ctx,
        mongo.IndexModel{
            Keys: bson.D{{Key: "guid", Value: 1}},
            Options: options.Index().SetUnique(true),
        },
    )

    if (err != nil) {
        return nil, nil, err
    }

    return client, ctx, nil
}

func findByAccess(ctx context.Context, tokenString string, outPair *TokenPair) error {
    tokens := dbClient.Database("jwt").Collection("tokens")
    filter := bson.D{
        {Key: "access", Value: tokenString},
    }
    return tokens.FindOne(context.TODO(), filter).Decode(outPair)
}

func deleteByAccess(ctx context.Context, tokenString string) error {
    tokens := dbClient.Database("jwt").Collection("tokens")
    filter := bson.D{
        {Key: "access", Value: tokenString},
    }
    _, err := tokens.DeleteOne(context.TODO(), filter)

    return err
}

func deleteByUser(ctx context.Context, GUID uint) error {
    tokens := dbClient.Database("jwt").Collection("tokens")
    filter := bson.D{
        {Key: "guid", Value: GUID},
    }
    _, err := tokens.DeleteMany(context.TODO(), filter)

    return err
}

func generateAndInsertTokens(ctx context.Context, guid uint, pair *TokenPair) error {
    tokens := dbClient.Database("jwt").Collection("tokens")
    row, err := tokens.InsertOne(ctx, bson.D{
        {Key: "guid", Value: guid},
        {Key: "access", Value: ""},
        {Key: "refresh", Value: ""},
    })
    if (err != nil) {
        return err
    }

    objectId := row.InsertedID.(primitive.ObjectID)

    err = generatePair(objectId.Hex(), guid, pair)
    if (err != nil) {
        return err
    }

    var hashedRefresh []byte
    hashedRefresh, err = createBcrypt(pair.Refresh)
    if (err != nil) {
        return err
    }

    _, err = tokens.UpdateOne(ctx, bson.M{"_id": bson.M{"$eq": objectId}},
        bson.D{{Key: "$set", Value: bson.D{
            {Key: "access", Value: pair.Access},
            {Key: "refresh", Value: hashedRefresh},
        }}},
    )

    return err
}

func makeTransaction(callback func(ctx mongo.SessionContext) error) error {
    session, err := dbClient.StartSession()
    if (err != nil) {
        return err
    }

    err = session.StartTransaction()
    if (err != nil) {
        return err
    }

    err = mongo.WithSession(context.TODO(), session, func(ctx mongo.SessionContext) error {
        err := callback(ctx)
        if (err != nil) {
            return err
        }
        return session.CommitTransaction(ctx)
    })
    if (err != nil) {
        return err
    }

    session.EndSession(context.TODO())

    return nil
}
