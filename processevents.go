package auth

import (
	"log"

	"github.com/puffinframework/event"
)

func (self *memStore) MustProcessEvents() {
	if err := self.eventStore.ForEachEventHeader(self.LastEventDt, func(header event.Header) (bool, error) {
		var err error

		switch header.Type {
		case "SignedUp":
			evt := SignedUpEvent{Header: header}
			self.eventStore.MustLoadEvent(header, &evt.Data)
			err = self.onSignedUpEvent(evt)
		}

		if err != nil {
			self.LastEventDt = header.CreatedAt
		}

		return err == nil, err

	}); err != nil {
		log.Panic(err)
	}
}
