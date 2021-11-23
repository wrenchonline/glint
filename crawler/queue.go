package crawler

import (
	"wenscan/log"
)

func (tab *Tab) Watch() {
	var (
		b  bool
		bq bool
	)

	for {
		select {
		case b = <-tab.Eventchanel.ButtonCheckUrl:
			tab.lock.Lock()
			if b {
				tab.Eventchanel.EventInfo["Button"] = true
				tab.Eventchanel.QueueRep <- "checkButton"
			} else {
				tab.Eventchanel.EventInfo["Button"] = false
				tab.Eventchanel.QueueRep <- "checkButton"
			}
			tab.lock.Unlock()
		case <-tab.Eventchanel.exit:
			bq = true
			goto end
		}

	end:
		if bq {
			log.Debug("Watch Thread Exit")
			break
		}
	}
}
