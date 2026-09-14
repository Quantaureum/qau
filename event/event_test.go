// Quantaureum Node source, version 1.0.0.
package event

import (
	"sync"
	"testing"
	"time"
)

func TestNewFeed(t *testing.T) {
	f := NewFeed()
	if f == nil {
		t.Fatal("expected non-nil feed")
	}
	if f.Len() != 0 {
		t.Errorf("expected 0 subs, got %d", f.Len())
	}
}

func TestNewFeedWithBuffer(t *testing.T) {
	f := NewFeedWithBuffer(50)
	if f == nil {
		t.Fatal("expected non-nil feed")
	}
	if f.Len() != 0 {
		t.Errorf("expected 0 subs, got %d", f.Len())
	}
}

func TestSubscribe(t *testing.T) {
	f := NewFeed()
	ch := make(chan int, 10)
	sub, err := f.Subscribe(ch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sub == nil {
		t.Fatal("expected non-nil subscription")
	}
	if f.Len() != 1 {
		t.Errorf("expected 1 sub, got %d", f.Len())
	}
}

func TestSubscribe_NotAChannel(t *testing.T) {
	f := NewFeed()
	_, err := f.Subscribe(42)
	if err != ErrNotAChannel {
		t.Errorf("expected ErrNotAChannel, got %v", err)
	}
}

func TestSubscribe_NotSendable(t *testing.T) {
	f := NewFeed()
	ch := make(<-chan int)
	_, err := f.Subscribe(ch)
	if err != ErrNotSendable {
		t.Errorf("expected ErrNotSendable, got %v", err)
	}
}

func TestSend(t *testing.T) {
	f := NewFeed()
	ch := make(chan int, 10)
	f.Subscribe(ch)

	sent := f.Send(42)
	if sent != 1 {
		t.Errorf("expected 1 sent, got %d", sent)
	}

	select {
	case v := <-ch:
		if v != 42 {
			t.Errorf("expected 42, got %d", v)
		}
	default:
		t.Error("expected value on channel")
	}
}

func TestSend_NoSubscribers(t *testing.T) {
	f := NewFeed()
	sent := f.Send(42)
	if sent != 0 {
		t.Errorf("expected 0 sent, got %d", sent)
	}
}

func TestSend_MultipleSubscribers(t *testing.T) {
	f := NewFeed()
	ch1 := make(chan int, 10)
	ch2 := make(chan int, 10)
	ch3 := make(chan int, 10)
	f.Subscribe(ch1)
	f.Subscribe(ch2)
	f.Subscribe(ch3)

	sent := f.Send(100)
	if sent != 3 {
		t.Errorf("expected 3 sent, got %d", sent)
	}
}

func TestUnsubscribe(t *testing.T) {
	f := NewFeed()
	ch := make(chan int, 10)
	sub, _ := f.Subscribe(ch)
	if f.Len() != 1 {
		t.Fatalf("expected 1 sub, got %d", f.Len())
	}

	sub.Unsubscribe()
	if f.Len() != 0 {
		t.Errorf("expected 0 subs, got %d", f.Len())
	}
}

func TestUnsubscribe_Double(t *testing.T) {
	f := NewFeed()
	ch := make(chan int, 10)
	sub, _ := f.Subscribe(ch)

	sub.Unsubscribe()
	sub.Unsubscribe()
	if f.Len() != 0 {
		t.Errorf("expected 0 subs, got %d", f.Len())
	}
}

func TestSend_AfterUnsubscribe(t *testing.T) {
	f := NewFeed()
	ch := make(chan int, 10)
	sub, _ := f.Subscribe(ch)
	sub.Unsubscribe()

	sent := f.Send(42)
	if sent != 0 {
		t.Errorf("expected 0 sent, got %d", sent)
	}
}

func TestSend_String(t *testing.T) {
	f := NewFeed()
	ch := make(chan string, 10)
	f.Subscribe(ch)

	sent := f.Send("hello")
	if sent != 1 {
		t.Errorf("expected 1 sent, got %d", sent)
	}

	select {
	case v := <-ch:
		if v != "hello" {
			t.Errorf("expected hello, got %s", v)
		}
	default:
		t.Error("expected value on channel")
	}
}

func TestSend_FullChannel(t *testing.T) {
	f := NewFeedWithBuffer(1)
	ch := make(chan int, 1)
	f.Subscribe(ch)

	ch <- 1

	sent := f.Send(2)
	if sent != 0 {
		t.Errorf("expected 0 sent (channel full), got %d", sent)
	}
}

func TestSend_Concurrent(t *testing.T) {
	f := NewFeed()
	ch := make(chan int, 100)
	f.Subscribe(ch)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(v int) {
			defer wg.Done()
			f.Send(v)
		}(i)
	}
	wg.Wait()
}

func TestSend_Struct(t *testing.T) {
	type Event struct {
		Name string
		Data int
	}

	f := NewFeed()
	ch := make(chan Event, 10)
	f.Subscribe(ch)

	evt := Event{Name: "test", Data: 42}
	sent := f.Send(evt)
	if sent != 1 {
		t.Errorf("expected 1 sent, got %d", sent)
	}

	select {
	case v := <-ch:
		if v.Name != "test" || v.Data != 42 {
			t.Errorf("got %+v", v)
		}
	default:
		t.Error("expected value")
	}
}

func TestSend_ConvertibleType(t *testing.T) {
	f := NewFeed()
	ch := make(chan int, 10)
	f.Subscribe(ch)

	type myInt int
	f.Send(myInt(42))

	select {
	case v := <-ch:
		if v != 42 {
			t.Errorf("expected 42, got %d", v)
		}
	default:
		t.Error("expected value")
	}
}

func TestUnsubscribe_WhileSending(t *testing.T) {
	f := NewFeed()
	ch := make(chan int, 10)
	sub, _ := f.Subscribe(ch)

	go func() {
		time.Sleep(10 * time.Millisecond)
		sub.Unsubscribe()
	}()

	f.Send(42)
}

func TestErrSubscriptionClosed(t *testing.T) {
	f := NewFeed()
	ch := make(chan int, 10)
	sub, _ := f.Subscribe(ch)
	sub.Unsubscribe()

	err := sub.Err()
	if err == nil {
		t.Error("expected error after unsubscribe")
	}
}

func TestNewTypeMux(t *testing.T) {
	mux := NewTypeMux()
	if mux == nil {
		t.Fatal("expected non-nil TypeMux")
	}
}

func TestTypeMux_Subscribe(t *testing.T) {
	mux := NewTypeMux()
	sub, err := mux.Subscribe("hello")
	if err != nil {
		t.Fatal(err)
	}
	if sub == nil {
		t.Fatal("expected non-nil subscription")
	}
	if sub.Chan() == nil {
		t.Error("expected non-nil channel")
	}
	if sub.Closed() {
		t.Error("expected subscription to be open")
	}
}

func TestTypeMux_Subscribe_MultipleTypes(t *testing.T) {
	mux := NewTypeMux()
	sub, err := mux.Subscribe("hello", 42, true)
	if err != nil {
		t.Fatal(err)
	}
	if sub == nil {
		t.Fatal("expected non-nil subscription")
	}
}

func TestTypeMux_Post(t *testing.T) {
	mux := NewTypeMux()
	sub, err := mux.Subscribe("test_event")
	if err != nil {
		t.Fatal(err)
	}

	err = mux.Post("test_event")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case ev := <-sub.Chan():
		if ev.Data != "test_event" {
			t.Errorf("expected test_event, got %v", ev.Data)
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for event")
	}
}

func TestTypeMux_Post_WrongType(t *testing.T) {
	mux := NewTypeMux()
	sub, err := mux.Subscribe("test_type")
	if err != nil {
		t.Fatal(err)
	}

	err = mux.Post(42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case <-sub.Chan():
		t.Error("expected no event for wrong type")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestTypeMux_Post_Struct(t *testing.T) {
	type MyEvent struct {
		Name string
		Val  int
	}
	mux := NewTypeMux()
	sub, err := mux.Subscribe(MyEvent{})
	if err != nil {
		t.Fatal(err)
	}

	evt := MyEvent{Name: "test", Val: 42}
	err = mux.Post(evt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case ev := <-sub.Chan():
		got, ok := ev.Data.(MyEvent)
		if !ok {
			t.Fatal("expected MyEvent type")
		}
		if got.Name != "test" || got.Val != 42 {
			t.Errorf("got %+v", got)
		}
	case <-time.After(time.Second):
		t.Error("timeout")
	}
}

func TestTypeMux_Post_MultipleSubscribers(t *testing.T) {
	mux := NewTypeMux()
	sub1, err := mux.Subscribe("shared")
	if err != nil {
		t.Fatal(err)
	}
	sub2, err := mux.Subscribe("shared")
	if err != nil {
		t.Fatal(err)
	}
	sub3, err := mux.Subscribe("shared")
	if err != nil {
		t.Fatal(err)
	}

	mux.Post("shared")

	for i, sub := range []*TypeMuxSubscription{sub1, sub2, sub3} {
		select {
		case <-sub.Chan():
		case <-time.After(time.Second):
			t.Errorf("sub %d: timeout", i)
		}
	}
}

func TestTypeMux_Unsubscribe(t *testing.T) {
	mux := NewTypeMux()
	sub, err := mux.Subscribe("evt")
	if err != nil {
		t.Fatal(err)
	}

	mux.Post("evt")
	<-sub.Chan()

	sub.Unsubscribe()
	if !sub.Closed() {
		t.Error("expected closed after unsubscribe")
	}
}

func TestTypeMux_Post_AfterUnsubscribe(t *testing.T) {
	mux := NewTypeMux()
	sub, err := mux.Subscribe("evt")
	if err != nil {
		t.Fatal(err)
	}
	sub.Unsubscribe()

	err = mux.Post("evt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTypeMux_Stop(t *testing.T) {
	mux := NewTypeMux()
	sub, err := mux.Subscribe("evt")
	if err != nil {
		t.Fatal(err)
	}

	mux.Stop()
	if !sub.Closed() {
		t.Error("expected subscription closed after mux stop")
	}
}

func TestTypeMux_Post_AfterStop(t *testing.T) {
	mux := NewTypeMux()
	_, _ = mux.Subscribe("evt")
	mux.Stop()

	err := mux.Post("evt")
	if err != ErrMuxClosed {
		t.Errorf("expected ErrMuxClosed, got %v", err)
	}
}

func TestTypeMux_DoubleStop(t *testing.T) {
	mux := NewTypeMux()
	mux.Stop()
	mux.Stop()
}

func TestTypeMux_ClosedSubscription(t *testing.T) {
	mux := NewTypeMux()

	mux.Stop()
	// L10-015 FIX: Subscribe now returns nil, ErrMuxClosed when mux is stopped
	sub, err := mux.Subscribe("evt")
	if err != ErrMuxClosed {
		t.Fatalf("expected ErrMuxClosed, got %v", err)
	}
	if sub != nil {
		t.Error("expected nil subscription when mux stopped")
	}
}

func TestErrTooManyMuxSubscriptions(t *testing.T) {
	if ErrTooManyMuxSubscriptions.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

func TestErrMuxClosed(t *testing.T) {
	if ErrMuxClosed.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

func TestDefaultTimeNow(t *testing.T) {
	ts := defaultTimeNow()
	if ts <= 0 {
		t.Error("expected positive timestamp")
	}
}

func TestTimeNow_WithMock(t *testing.T) {
	orig := timeNowFunc
	defer func() { timeNowFunc = orig }()

	timeNowFunc = func() int64 { return 1234567890 }
	if timeNow() != 1234567890 {
		t.Error("expected mocked timestamp")
	}

	timeNowFunc = func() int64 { return 0 }
	if timeNow() != 0 {
		t.Error("expected zero timestamp")
	}
}

func TestSend_IncompatibleType(t *testing.T) {
	f := NewFeed()
	ch := make(chan int, 10)
	f.Subscribe(ch)

	sent := f.Send("cannot_convert_to_int")
	if sent != 0 {
		t.Errorf("expected 0 sent for incompatible type, got %d", sent)
	}
}

func TestTypeMux_DeliverChannelFull(t *testing.T) {
	mux := NewTypeMux()
	sub, err := mux.Subscribe("drop")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 210; i++ {
		mux.Post("drop")
	}

	_ = sub
}

func TestTypeMux_Subscribe_WhenMuxStopped(t *testing.T) {
	mux := NewTypeMux()
	mux.Stop()

	// L10-015 FIX: Subscribe now returns nil, ErrMuxClosed when mux is stopped
	sub, err := mux.Subscribe("late")
	if err != ErrMuxClosed {
		t.Fatalf("expected ErrMuxClosed, got %v", err)
	}
	if sub != nil {
		t.Fatal("expected nil subscription when mux stopped")
	}
}

func TestTypeMux_Subscribe_MaxLimit(t *testing.T) {
	mux := NewTypeMux()
	mux.maxSubs = 2
	_, _ = mux.Subscribe("t1")
	_, _ = mux.Subscribe("t2")

	sub, _ := mux.Subscribe("t3")
	if sub != nil {
		t.Error("expected nil when max subscriptions reached")
	}
}

func TestFeed_Len(t *testing.T) {
	f := NewFeed()
	if f.Len() != 0 {
		t.Errorf("expected 0, got %d", f.Len())
	}

	ch := make(chan int, 10)
	f.Subscribe(ch)
	if f.Len() != 1 {
		t.Errorf("expected 1, got %d", f.Len())
	}

	ch2 := make(chan int, 10)
	sub, _ := f.Subscribe(ch2)
	if f.Len() != 2 {
		t.Errorf("expected 2, got %d", f.Len())
	}

	sub.Unsubscribe()
	if f.Len() != 1 {
		t.Errorf("expected 1 after unsubscribe, got %d", f.Len())
	}
}

func TestFeed_Subscribe_MaxLimit(t *testing.T) {
	f := NewFeed()
	f.maxSubs = 2
	ch1 := make(chan int, 10)
	ch2 := make(chan int, 10)
	f.Subscribe(ch1)
	f.Subscribe(ch2)

	ch3 := make(chan int, 10)
	_, err := f.Subscribe(ch3)
	if err != ErrTooManySubscriptions {
		t.Errorf("expected ErrTooManySubscriptions, got %v", err)
	}
}

func TestErrTooManySubscriptions(t *testing.T) {
	if ErrTooManySubscriptions.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

func TestErrNotAChannel(t *testing.T) {
	if ErrNotAChannel.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

func TestErrNotSendable(t *testing.T) {
	if ErrNotSendable.Error() == "" {
		t.Error("expected non-empty error message")
	}
}
