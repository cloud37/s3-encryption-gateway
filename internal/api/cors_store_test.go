package api

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

type redisCommandCounterHook struct {
	mu       sync.Mutex
	commands []string
}

func (h *redisCommandCounterHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *redisCommandCounterHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		h.mu.Lock()
		h.commands = append(h.commands, strings.ToUpper(cmd.Name()))
		h.mu.Unlock()
		return next(ctx, cmd)
	}
}
func (h *redisCommandCounterHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		h.mu.Lock()
		for _, cmd := range cmds {
			h.commands = append(h.commands, strings.ToUpper(cmd.Name()))
		}
		h.mu.Unlock()
		return next(ctx, cmds)
	}
}
func (h *redisCommandCounterHook) snapshot() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.commands...)
}
func (h *redisCommandCounterHook) reset() {
	h.mu.Lock()
	h.commands = nil
	h.mu.Unlock()
}

func TestValkeyCORSStore_ReplicaVisibilityAndNoTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	clientA := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer clientA.Close()
	clientB := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer clientB.Close()
	a, b := NewValkeyCORSStore(clientA), NewValkeyCORSStore(clientB)
	cfg, err := parseCORSXML([]byte(corsTestXML))
	require.NoError(t, err)
	require.NoError(t, a.Put(context.Background(), "bucket", cfg))
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if err := a.Put(context.Background(), "bucket", cfg); err != nil {
					errs <- err
					return
				}
				got, err := b.Get(context.Background(), "bucket")
				if err != nil {
					errs <- err
					return
				}
				if got.Rules[0].ID != "web" {
					errs <- errors.New("replica observed partial policy")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, time.Duration(0), mr.TTL(corsKey("bucket")))
	got, err := b.Get(context.Background(), "bucket")
	require.NoError(t, err)
	require.Equal(t, cfg, got)
}

func TestValkeyCORSStore_MissingVersusUnavailable(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewValkeyCORSStore(client)
	_, err := store.Get(context.Background(), "bucket")
	require.ErrorIs(t, err, ErrCORSNotFound)
	require.False(t, errors.Is(err, ErrCORSUnavailable))
	require.NoError(t, client.Close())
	_, err = store.Get(context.Background(), "bucket")
	require.ErrorIs(t, err, ErrCORSUnavailable)
}

func TestValkeyCORSStore_RejectsCorruptRecord(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	require.NoError(t, client.Set(context.Background(), corsKey("bucket"), `<CORSConfiguration><evil/></CORSConfiguration>`, 0).Err())
	_, err := NewValkeyCORSStore(client).Get(context.Background(), "bucket")
	require.ErrorIs(t, err, ErrCORSUnavailable)
}

func TestValkeyCORSStore_ResetThenRestorePolicy(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	store := NewValkeyCORSStore(client)
	cfg, err := parseCORSXML([]byte(corsTestXML))
	require.NoError(t, err)
	require.NoError(t, store.Put(context.Background(), "bucket", cfg))
	backup, err := client.Get(context.Background(), corsKey("bucket")).Bytes()
	require.NoError(t, err)
	mr.FlushAll()
	_, err = store.Get(context.Background(), "bucket")
	require.ErrorIs(t, err, ErrCORSNotFound)
	restored, err := parseCORSXML(backup)
	require.NoError(t, err)
	require.NoError(t, store.Put(context.Background(), "bucket", restored))
	got, err := store.Get(context.Background(), "bucket")
	require.NoError(t, err)
	_, ok := matchCORSRule(got, "https://app.example.com", "PUT", []string{"content-type"})
	require.True(t, ok)
}

func TestValkeyCORSStore_AtomicReplacementAndDeleteIdempotent(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	store := NewValkeyCORSStore(client)
	first, err := parseCORSXML([]byte(corsTestXML))
	require.NoError(t, err)
	second, err := parseCORSXML([]byte(`<CORSConfiguration><CORSRule><ID>replacement</ID><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`))
	require.NoError(t, err)
	require.NoError(t, store.Put(context.Background(), "bucket", first))
	require.NoError(t, store.Put(context.Background(), "bucket", second))
	got, err := store.Get(context.Background(), "bucket")
	require.NoError(t, err)
	require.Equal(t, "replacement", got.Rules[0].ID)
	require.NoError(t, store.Delete(context.Background(), "bucket"))
	require.NoError(t, store.Delete(context.Background(), "bucket"))
}

func TestValkeyCORSStore_GetReturnsCallerOwnedCopy(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	store := NewValkeyCORSStore(client)
	cfg, err := parseCORSXML([]byte(corsTestXML))
	require.NoError(t, err)
	require.NoError(t, store.Put(context.Background(), "bucket", cfg))
	got, err := store.Get(context.Background(), "bucket")
	require.NoError(t, err)
	got.Rules[0].AllowedOrigins[0] = "https://mutated.example"
	*got.Rules[0].MaxAgeSeconds = 1
	fresh, err := store.Get(context.Background(), "bucket")
	require.NoError(t, err)
	require.Equal(t, "https://app.example.com", fresh.Rules[0].AllowedOrigins[0])
	require.Equal(t, 3600, *fresh.Rules[0].MaxAgeSeconds)
}

func TestValkeyCORSStore_GetSingleCommandMissingMappingAndContext(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	hook := &redisCommandCounterHook{}
	client.AddHook(hook)
	require.NoError(t, client.Ping(context.Background()).Err())
	hook.reset() // exclude HELLO/CLIENT connection setup commands
	store := NewValkeyCORSStore(client)
	_, err := store.Get(context.Background(), "bucket")
	require.ErrorIs(t, err, ErrCORSNotFound)
	require.Equal(t, []string{"GET"}, hook.snapshot())
	hook.reset()
	cfg, err := parseCORSXML([]byte(corsTestXML))
	require.NoError(t, err)
	require.NoError(t, store.Put(context.Background(), "bucket", cfg))
	// GET must be one atomic Redis command rather than EXISTS/STRLEN/GETRANGE.
	hook.reset()
	got, err := store.Get(context.Background(), "bucket")
	require.NoError(t, err)
	commands := hook.snapshot()
	require.Equal(t, []string{"GET"}, commands)
	require.Equal(t, cfg, got)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = store.Get(ctx, "bucket")
	require.ErrorIs(t, err, ErrCORSUnavailable)
}

func TestNewValkeyCORSStore_NilAndTypedNilClient(t *testing.T) {
	var typedNil *redis.Client
	for _, client := range []redis.UniversalClient{nil, typedNil} {
		store := NewValkeyCORSStore(client)
		_, err := store.Get(context.Background(), "bucket")
		require.ErrorIs(t, err, ErrCORSUnavailable)
	}
}

func TestValkeyCORSStore_ContextAndBucketValidation(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	store := NewValkeyCORSStore(client)
	cfg, err := parseCORSXML([]byte(corsTestXML))
	require.NoError(t, err)
	require.ErrorIs(t, store.Put(nil, "bucket", cfg), ErrCORSUnavailable)
	require.ErrorIs(t, store.Delete(context.Background(), "bad/bucket"), ErrCORSUnavailable)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, store.Put(ctx, "bucket", cfg), ErrCORSUnavailable)
}

func TestValkeyCORSStore_ConcurrentReplacementAndDeletionIsAtomicSnapshot(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	store := NewValkeyCORSStore(client)
	a, err := parseCORSXML([]byte(`<CORSConfiguration><CORSRule><ID>a</ID><AllowedOrigin>https://a.example</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`))
	require.NoError(t, err)
	b, err := parseCORSXML([]byte(`<CORSConfiguration><CORSRule><ID>b</ID><AllowedOrigin>https://b.example</AllowedOrigin><AllowedMethod>PUT</AllowedMethod></CORSRule></CORSConfiguration>`))
	require.NoError(t, err)
	require.NoError(t, store.Put(context.Background(), "bucket", a))
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				if writer == 2 {
					if err := store.Delete(context.Background(), "bucket"); err != nil {
						errs <- err
						return
					}
					continue
				}
				if err := store.Put(context.Background(), "bucket", a); err != nil {
					errs <- err
					return
				}
				if err := store.Put(context.Background(), "bucket", b); err != nil {
					errs <- err
					return
				}
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 120; j++ {
			got, err := store.Get(context.Background(), "bucket")
			if err != nil {
				if errors.Is(err, ErrCORSNotFound) {
					continue
				}
				errs <- err
				return
			}
			if got.Rules[0].ID != "a" && got.Rules[0].ID != "b" {
				errs <- errors.New("partial policy snapshot")
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.NoError(t, store.Delete(context.Background(), "bucket"))
	_, err = store.Get(context.Background(), "bucket")
	require.ErrorIs(t, err, ErrCORSNotFound)
}
