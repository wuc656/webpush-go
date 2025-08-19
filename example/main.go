package main

import (
	"encoding/json"
	"log"

	webpush "github.com/wuc656/webpush-go"
)

const (
	subscription    = ``
	vapidPublicKey  = ""
	vapidPrivateKey = ""
)

func main() {
	// Decode subscription
	s := &webpush.Subscription{}
	json.Unmarshal([]byte(subscription), s)

	// Send Notification
	resp, err := webpush.SendNotification([]byte("Test"), s, &webpush.Options{
		Subscriber:      "example@example.com", // Do not include "mailto:"
		VAPIDPublicKey:  vapidPublicKey,
		VAPIDPrivateKey: vapidPrivateKey,
		TTL:             30,
	})
	if err != nil {
		log.Printf("Failed to send notification: %v", err)
	}
	if resp != nil {
		defer resp.Body.Close()
	}
}
