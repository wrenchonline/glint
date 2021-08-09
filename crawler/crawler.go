package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

func main() {
	// create a test server to serve the page
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `
							<html lang="en">
							<head>
								<script>
									setTimeout(() => {
										document.dispatchEvent(new Event('myCustomEvent'))
									}, 3000)
								</script>
							</head>
							<body>
							</body>
							</html>
							`,
		)
	}))
	defer ts.Close()

	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, time.Minute)
	defer cancel()

	var timestamp int

	err := chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument("__fired__ = null; document.addEventListener('myCustomEvent', (e) => {__fired__ = Date.now();})").
				Do(ctx)
			return err
		}),
		chromedp.Navigate(ts.URL),
		chromedp.Poll("__fired__", &timestamp, chromedp.WithPollingInterval(time.Second)),
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Print(timestamp)
}
