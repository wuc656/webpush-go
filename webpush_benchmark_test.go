package webpush

import "testing"

func BenchmarkSendNotification(b *testing.B) {
	vapidPrivateKey, vapidPublicKey, err := GenerateVAPIDKeys()
	if err != nil {
		b.Fatal(err)
	}

	subscription := getStandardEncodedTestSubscription()
	options := &Options{
		HTTPClient:      &testHTTPClient{},
		Subscriber:      "test@example.com",
		VAPIDPublicKey:  vapidPublicKey,
		VAPIDPrivateKey: vapidPrivateKey,
		TTL:             30,
	}

	message := []byte("Test")

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		resp, err := SendNotification(message, subscription, options)
		if err != nil {
			b.Fatal(err)
		}
		if resp.StatusCode != 201 {
			b.Fatalf("unexpected status code: got %d, want 201", resp.StatusCode)
		}
	}
}
