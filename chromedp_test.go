package main

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

func Test_Name(t *testing.T) {
	// create chrome instance
	ctx, cancel := chromedp.NewContext(
		context.Background(),
		chromedp.WithLogf(log.Printf),
	)
	defer cancel()

	// create a timeout
	ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// navigate to a page, wait for an element, click
	var example string
	err := chromedp.Run(ctx,
		chromedp.Navigate(`https://www.baidu.com/`),
		// // wait for footer element is visible (ie, page is loaded)
		// chromedp.WaitVisible(`body > footer`),
		// // find and click "Expand All" link
		// chromedp.Click(`#pkg-examples > div`, chromedp.NodeVisible),
		// // retrieve the value of the textarea
		// chromedp.Value(`#example_After .play .input textarea`, &example),
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Go's time.After example:\n%s", example)
}
