package crawler

import "context"

func (tab *Tab) watch(ctx context.Context, typename string) {
	for {
		select {
		case <-ctx.Done():
			if typename == "Button" {
				// tab.ButtonCancel = nil
			}
			return
		default:

		}
	}
}
