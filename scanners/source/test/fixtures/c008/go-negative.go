package fetcher

import "net/http"

func SecureClient() *http.Client {
	return &http.Client{}
}
