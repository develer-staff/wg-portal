package wireguard

import (
	"context"
	"testing"
	"time"

	"github.com/h44z/wg-portal/internal/config"
	"github.com/h44z/wg-portal/internal/domain"
)

// --- Test mocks ---

type mockBus struct{}

func (f *mockBus) Publish(topic string, args ...any)    {}
func (f *mockBus) Subscribe(topic string, fn any) error { return nil }

type mockController struct {
	deletedPeers []domain.PeerIdentifier
}

func (f *mockController) GetId() domain.InterfaceBackend { return "local" }
func (f *mockController) GetInterfaces(_ context.Context) ([]domain.PhysicalInterface, error) {
	return nil, nil
}
func (f *mockController) GetInterface(_ context.Context, id domain.InterfaceIdentifier) (
	*domain.PhysicalInterface,
	error,
) {
	return &domain.PhysicalInterface{Identifier: id}, nil
}
func (f *mockController) GetPeers(_ context.Context, _ domain.InterfaceIdentifier) ([]domain.PhysicalPeer, error) {
	return nil, nil
}
func (f *mockController) SaveInterface(
	_ context.Context,
	_ domain.InterfaceIdentifier,
	updateFunc func(pi *domain.PhysicalInterface) (*domain.PhysicalInterface, error),
) error {
	_, _ = updateFunc(&domain.PhysicalInterface{})
	return nil
}
func (f *mockController) DeleteInterface(_ context.Context, _ domain.InterfaceIdentifier) error {
	return nil
}
func (f *mockController) SavePeer(
	_ context.Context,
	_ domain.InterfaceIdentifier,
	_ domain.PeerIdentifier,
	updateFunc func(pp *domain.PhysicalPeer) (*domain.PhysicalPeer, error),
) error {
	_, _ = updateFunc(&domain.PhysicalPeer{})
	return nil
}
func (f *mockController) DeletePeer(
	_ context.Context,
	_ domain.InterfaceIdentifier,
	id domain.PeerIdentifier,
) error {
	f.deletedPeers = append(f.deletedPeers, id)
	return nil
}
func (f *mockController) PingAddresses(_ context.Context, _ string) (*domain.PingerResult, error) {
	return nil, nil
}

type mockDB struct {
	savedPeers map[domain.PeerIdentifier]*domain.Peer
	iface      *domain.Interface
	interfaces []domain.Interface
	users      []domain.User
}

func (f *mockDB) GetInterface(ctx context.Context, id domain.InterfaceIdentifier) (*domain.Interface, error) {
	if f.iface != nil && f.iface.Identifier == id {
		return f.iface, nil
	}
	return &domain.Interface{Identifier: id}, nil
}
func (f *mockDB) GetInterfaceAndPeers(ctx context.Context, id domain.InterfaceIdentifier) (
	*domain.Interface,
	[]domain.Peer,
	error,
) {
	return f.iface, nil, nil
}
func (f *mockDB) GetPeersStats(ctx context.Context, ids ...domain.PeerIdentifier) ([]domain.PeerStatus, error) {
	return nil, nil
}
func (f *mockDB) GetAllInterfaces(ctx context.Context) ([]domain.Interface, error) {
	if f.interfaces != nil {
		return f.interfaces, nil
	}
	if f.iface != nil {
		return []domain.Interface{*f.iface}, nil
	}
	return nil, nil
}
func (f *mockDB) GetInterfaceIps(ctx context.Context) (map[domain.InterfaceIdentifier][]domain.Cidr, error) {
	return nil, nil
}
func (f *mockDB) SaveInterface(
	ctx context.Context,
	id domain.InterfaceIdentifier,
	updateFunc func(in *domain.Interface) (*domain.Interface, error),
) error {
	if f.iface == nil {
		f.iface = &domain.Interface{Identifier: id}
	}
	var err error
	f.iface, err = updateFunc(f.iface)
	return err
}
func (f *mockDB) DeleteInterface(ctx context.Context, id domain.InterfaceIdentifier) error {
	return nil
}
func (f *mockDB) GetInterfacePeers(ctx context.Context, id domain.InterfaceIdentifier) ([]domain.Peer, error) {
	peers := make([]domain.Peer, 0)
	for _, peer := range f.savedPeers {
		if peer.InterfaceIdentifier == id {
			peers = append(peers, *peer)
		}
	}
	return peers, nil
}
func (f *mockDB) GetUserPeers(ctx context.Context, id domain.UserIdentifier) ([]domain.Peer, error) {
	return nil, nil
}
func (f *mockDB) SavePeer(
	ctx context.Context,
	id domain.PeerIdentifier,
	updateFunc func(in *domain.Peer) (*domain.Peer, error),
) error {
	if f.savedPeers == nil {
		f.savedPeers = make(map[domain.PeerIdentifier]*domain.Peer)
	}
	existing := f.savedPeers[id]
	if existing == nil {
		existing = &domain.Peer{Identifier: id}
	}
	updated, err := updateFunc(existing)
	if err != nil {
		return err
	}
	f.savedPeers[updated.Identifier] = updated
	return nil
}
func (f *mockDB) DeletePeer(ctx context.Context, id domain.PeerIdentifier) error {
	delete(f.savedPeers, id)
	return nil
}
func (f *mockDB) GetPeer(ctx context.Context, id domain.PeerIdentifier) (*domain.Peer, error) {
	if peer := f.savedPeers[id]; peer != nil {
		return peer, nil
	}
	return nil, domain.ErrNotFound
}
func (f *mockDB) GetUsedIpsPerSubnet(ctx context.Context, subnets []domain.Cidr) (
	map[domain.Cidr][]domain.Cidr,
	error,
) {
	return map[domain.Cidr][]domain.Cidr{}, nil
}
func (f *mockDB) GetUser(ctx context.Context, id domain.UserIdentifier) (*domain.User, error) {
	return &domain.User{
		Identifier: id,
		IsAdmin:    false,
	}, nil
}
func (f *mockDB) GetAllUsers(ctx context.Context) ([]domain.User, error) {
	return f.users, nil
}

// --- Test ---

func TestCreatePeer_SetsIdentifier_FromPublicKey(t *testing.T) {
	// Arrange
	cfg := &config.Config{}
	cfg.Core.SelfProvisioningAllowed = true
	cfg.Core.EditableKeys = true
	cfg.Advanced.LimitAdditionalUserPeers = 0

	bus := &mockBus{}

	// Prepare a controller manager with our mock controller
	ctrlMgr := &ControllerManager{
		controllers: map[domain.InterfaceBackend]backendInstance{
			config.LocalBackendName: {Implementation: &mockController{}},
		},
	}

	db := &mockDB{iface: &domain.Interface{Identifier: "wg0", Type: domain.InterfaceTypeServer}}

	m := Manager{
		cfg: cfg,
		bus: bus,
		db:  db,
		wg:  ctrlMgr,
	}

	userId := domain.UserIdentifier("user@example.com")
	ctx := domain.SetUserInfo(context.Background(), &domain.ContextUserInfo{Id: userId, IsAdmin: false})

	pubKey := "TEST_PUBLIC_KEY_ABC123"

	input := &domain.Peer{
		Identifier:          "should_be_overwritten",
		UserIdentifier:      userId,
		InterfaceIdentifier: domain.InterfaceIdentifier("wg0"),
		ExpiresAt:           new(time.Time),
		Interface: domain.PeerInterfaceConfig{
			KeyPair: domain.KeyPair{PublicKey: pubKey},
		},
	}

	// Act
	earliestExpiry := time.Now().Add(peerLifetime)
	out, err := m.CreatePeer(ctx, input)
	latestExpiry := time.Now().Add(peerLifetime)

	// Assert
	if err != nil {
		t.Fatalf("CreatePeer returned error: %v", err)
	}

	expectedId := domain.PeerIdentifier(pubKey)
	if out.Identifier != expectedId {
		t.Fatalf("expected Identifier to be set from public key %q, got %q", expectedId, out.Identifier)
	}

	// Ensure the saved peer in DB also has the expected identifier
	if db.savedPeers[expectedId] == nil {
		t.Fatalf("expected peer with identifier %q to be saved in DB", expectedId)
	}
	if out.ExpiresAt == nil ||
		out.ExpiresAt.Before(earliestExpiry) ||
		out.ExpiresAt.After(latestExpiry) {
		t.Fatalf("expected expiry between %s and %s, got %v", earliestExpiry, latestExpiry, out.ExpiresAt)
	}
}

func TestCreateMultiplePeers_SetsExpiration(t *testing.T) {
	cfg := &config.Config{}
	bus := &mockBus{}
	controller := &mockController{}
	ctrlMgr := &ControllerManager{
		controllers: map[domain.InterfaceBackend]backendInstance{
			config.LocalBackendName: {Implementation: controller},
		},
	}
	db := &mockDB{iface: &domain.Interface{Identifier: "wg0", Type: domain.InterfaceTypeServer}}
	m := Manager{cfg: cfg, bus: bus, db: db, wg: ctrlMgr}
	ctx := domain.SetUserInfo(context.Background(), &domain.ContextUserInfo{IsAdmin: true})

	earliestExpiry := time.Now().Add(peerLifetime)
	peers, err := m.CreateMultiplePeers(ctx, "wg0", &domain.PeerCreationRequest{
		UserIdentifiers: []string{"user1", "user2"},
	})
	latestExpiry := time.Now().Add(peerLifetime)

	if err != nil {
		t.Fatalf("CreateMultiplePeers returned error: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers))
	}
	for _, peer := range peers {
		if peer.ExpiresAt == nil ||
			peer.ExpiresAt.Before(earliestExpiry) ||
			peer.ExpiresAt.After(latestExpiry) {
			t.Errorf("expected expiry between %s and %s, got %v", earliestExpiry, latestExpiry, peer.ExpiresAt)
		}
	}
}

func TestUpdatePeer_PreservesExpiration(t *testing.T) {
	tests := []struct {
		name         string
		newPublicKey string
	}{
		{name: "normal update", newPublicKey: "original-key"},
		{name: "public key replacement", newPublicKey: "replacement-key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{}
			bus := &mockBus{}
			controller := &mockController{}
			ctrlMgr := &ControllerManager{
				controllers: map[domain.InterfaceBackend]backendInstance{
					config.LocalBackendName: {Implementation: controller},
				},
			}
			originalExpiry := time.Now().Add(24 * time.Hour)
			attemptedExpiry := time.Now().Add(48 * time.Hour)
			existingPeer := &domain.Peer{
				Identifier:          "original-key",
				UserIdentifier:      "user1",
				InterfaceIdentifier: "wg0",
				ExpiresAt:           &originalExpiry,
				Interface: domain.PeerInterfaceConfig{
					KeyPair: domain.KeyPair{PublicKey: "original-key"},
				},
			}
			db := &mockDB{
				iface: &domain.Interface{Identifier: "wg0", Type: domain.InterfaceTypeServer},
				savedPeers: map[domain.PeerIdentifier]*domain.Peer{
					existingPeer.Identifier: existingPeer,
				},
			}
			m := Manager{cfg: cfg, bus: bus, db: db, wg: ctrlMgr}
			ctx := domain.SetUserInfo(context.Background(), &domain.ContextUserInfo{IsAdmin: true})

			update := *existingPeer
			update.ExpiresAt = &attemptedExpiry
			update.Interface.PublicKey = tt.newPublicKey

			updated, err := m.UpdatePeer(ctx, &update)

			if err != nil {
				t.Fatalf("UpdatePeer returned error: %v", err)
			}
			if updated.ExpiresAt == nil || !updated.ExpiresAt.Equal(originalExpiry) {
				t.Fatalf("expected expiry %s to be preserved, got %v", originalExpiry, updated.ExpiresAt)
			}
		})
	}
}

func TestCheckExpiredPeers_DeletesExpiredPeers(t *testing.T) {
	now := time.Now()
	expiredAt := now.Add(-time.Hour)
	futureExpiry := now.Add(time.Hour)
	disabledAt := now.Add(-2 * time.Hour)

	peers := []domain.Peer{
		{
			Identifier:          "expired",
			InterfaceIdentifier: "wg0",
			ExpiresAt:           &expiredAt,
		},
		{
			Identifier:          "expired-disabled",
			InterfaceIdentifier: "wg0",
			ExpiresAt:           &expiredAt,
			Disabled:            &disabledAt,
			IsDynamic:           true,
		},
		{
			Identifier:          "future",
			InterfaceIdentifier: "wg0",
			ExpiresAt:           &futureExpiry,
		},
		{
			Identifier:          "permanent",
			InterfaceIdentifier: "wg0",
		},
	}

	savedPeers := make(map[domain.PeerIdentifier]*domain.Peer, len(peers))
	for i := range peers {
		savedPeers[peers[i].Identifier] = &peers[i]
	}

	cfg := &config.Config{}
	bus := &mockBus{}
	controller := &mockController{}
	ctrlMgr := &ControllerManager{
		controllers: map[domain.InterfaceBackend]backendInstance{
			config.LocalBackendName: {Implementation: controller},
		},
	}
	db := &mockDB{
		iface:      &domain.Interface{Identifier: "wg0", Type: domain.InterfaceTypeServer},
		savedPeers: savedPeers,
	}
	m := Manager{cfg: cfg, bus: bus, db: db, wg: ctrlMgr}
	adminCtx := domain.SetUserInfo(context.Background(), &domain.ContextUserInfo{IsAdmin: true})
	ctx := domain.SetUserInfo(context.Background(), domain.SystemAdminContextUserInfo())

	if err := m.DeletePeer(adminCtx, "expired-disabled"); err == nil {
		t.Fatal("expected direct deletion of a dynamic peer to be rejected")
	}
	m.checkExpiredPeers(ctx, peers)

	for _, id := range []domain.PeerIdentifier{"expired", "expired-disabled"} {
		if db.savedPeers[id] != nil {
			t.Errorf("expected expired peer %q to be deleted", id)
		}
	}
	for _, id := range []domain.PeerIdentifier{"future", "permanent"} {
		if db.savedPeers[id] == nil {
			t.Errorf("expected unexpired peer %q to remain", id)
		}
	}
	if len(controller.deletedPeers) != 2 {
		t.Fatalf("expected 2 controller deletions, got %d", len(controller.deletedPeers))
	}
}

func TestCreateDefaultPeer_RespectsInterfaceFlag(t *testing.T) {
	// Arrange
	cfg := &config.Config{}
	cfg.Core.CreateDefaultPeerOnLogin = true

	bus := &mockBus{}
	ctrlMgr := &ControllerManager{
		controllers: map[domain.InterfaceBackend]backendInstance{
			config.LocalBackendName: {Implementation: &mockController{}},
		},
	}

	db := &mockDB{
		iface: &domain.Interface{
			Identifier:        "wg0",
			Type:              domain.InterfaceTypeServer,
			CreateDefaultPeer: false, // Flag is disabled!
		},
	}

	m := Manager{
		cfg: cfg,
		bus: bus,
		db:  db,
		wg:  ctrlMgr,
	}

	userId := domain.UserIdentifier("user@example.com")
	ctx := domain.SetUserInfo(context.Background(), &domain.ContextUserInfo{Id: userId, IsAdmin: true})

	// Act
	err := m.CreateDefaultPeer(ctx, userId)

	// Assert
	if err != nil {
		t.Fatalf("CreateDefaultPeer returned error: %v", err)
	}

	if len(db.savedPeers) != 0 {
		t.Fatalf("expected no peers to be created because interface flag is false, but got %d", len(db.savedPeers))
	}

	// Now enable the flag and try again
	db.iface.CreateDefaultPeer = true
	err = m.CreateDefaultPeer(ctx, userId)

	if err != nil {
		t.Fatalf("CreateDefaultPeer returned error after enabling flag: %v", err)
	}

	if len(db.savedPeers) != 1 {
		t.Fatalf("expected 1 peer to be created because interface flag is true, but got %d", len(db.savedPeers))
	}
}
