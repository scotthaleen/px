package database

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/scotthaleen/go-toolbelt/sqlite"
)

func TestDSNUsesPathOnlyFileURI(t *testing.T) {
	for _, test := range []struct {
		name     string
		path     string
		wantPath string
	}{
		{name: "unix", path: "/var/lib/px/state.db", wantPath: "/var/lib/px/state.db"},
		{name: "windows", path: `C:\Users\jaguar\AppData\Roaming\px\agent\state.db`, wantPath: "/C:/Users/jaguar/AppData/Roaming/px/agent/state.db"},
		{name: "windows forward slash", path: `D:/PX State/server.db`, wantPath: "/D:/PX State/server.db"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dsn := DSN(test.path)
			parsed, err := url.Parse(dsn)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Scheme != "file" || parsed.Host != "" || parsed.Path != test.wantPath {
				t.Fatalf("DSN %q parsed as scheme=%q host=%q path=%q", dsn, parsed.Scheme, parsed.Host, parsed.Path)
			}
			pragmas := parsed.Query()["_pragma"]
			if got := strings.Join(pragmas, ","); got != "busy_timeout(5000),foreign_keys(1),journal_mode(WAL)" {
				t.Fatalf("pragmas = %q", got)
			}
		})
	}
}

func TestTransferConfirmationMigrationPreservesLegacyCommittedState(t *testing.T) {
	cfg, err := Config(KindAgent, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	store := sqlite.New(cfg)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer store.Stop(context.Background())
	sub, err := fs.Sub(migrationFiles, "migrations/agent")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, store.DB(), sub, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(context.Background(), 5); err != nil {
		t.Fatal(err)
	}
	now := int64(1_700_000_000)
	if _, err := store.DB().Exec(`insert into contexts (name, server_url, server_id, device_id, private_key_path, public_key_path, label, state, enabled, offered_root, inbox_root, created_at, updated_at) values ('home', 'http://server', 'server', 'device', 'private', 'public', 'device', 'connected', 1, 'offered', 'inbox', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 64)
	if _, err := store.DB().Exec(`insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, state, created_at, updated_at, expires_at, manifest_version, visibility) values ('receive', ?, 'home', 'peer', 'peer', 'file', 1, ?, 32768, 8, 'token', 1, 'committed', ?, ?, ?, 3, 'private')`, id, strings.Repeat("0", 64), now, now, now+3600); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(context.Background(), 6); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := store.DB().QueryRow(`select state from transfer_resumes where transfer_id = ?`, id).Scan(&state); err != nil || state != "committed" {
		t.Fatalf("migrated state = %q, %v", state, err)
	}
	corruptID := strings.Repeat("b", 64)
	if _, err := store.DB().Exec(`insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, state, created_at, updated_at, expires_at, manifest_version, visibility) values ('receive', ?, 'home', 'peer', 'peer', 'file', 1, ?, 32768, 8, 'token', 0, 'corrupt', ?, ?, ?, 3, 'private')`, corruptID, strings.Repeat("0", 64), now, now, now+3600); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(context.Background(), 5); err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRow(`select state from transfer_resumes where transfer_id = ?`, corruptID).Scan(&state); err != nil || state != "transferring" {
		t.Fatalf("rolled back corrupt state = %q, %v", state, err)
	}
}

func TestOfferedRootAuthorityMigrationFailsLegacyBroadRootsClosed(t *testing.T) {
	cfg, err := Config(KindAgent, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	store := sqlite.New(cfg)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer store.Stop(context.Background())
	sub, err := fs.Sub(migrationFiles, "migrations/agent")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, store.DB(), sub, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(context.Background(), 8); err != nil {
		t.Fatal(err)
	}
	now := int64(1_700_000_000)
	if _, err := store.DB().Exec(`insert into contexts (name, server_url, server_id, device_id, private_key_path, public_key_path, label, state, enabled, offered_root, inbox_root, created_at, updated_at) values ('home', 'http://server', 'server', 'device', 'private', 'public', 'device', 'connected', 1, '/', 'inbox', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	for index, state := range []string{"transferring", "committing", "committed_pending_confirmation"} {
		id := fmt.Sprintf("%064x", index+1)
		if _, err := store.DB().Exec(`insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, state, created_at, updated_at, expires_at, manifest_version, visibility) values ('receive', ?, 'home', 'peer', 'peer', 'file', 1, ?, 32768, 8, 'token', 0, ?, ?, ?, ?, 3, 'public')`, id, strings.Repeat("0", 64), state, now, now, now+3600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := provider.UpTo(context.Background(), 9); err != nil {
		t.Fatal(err)
	}
	var scope string
	var revision, acknowledged int
	if err := store.DB().QueryRow(`select offered_root_scope, offered_root_revision, filesystem_root_acknowledged from contexts where name = 'home'`).Scan(&scope, &revision, &acknowledged); err != nil {
		t.Fatal(err)
	}
	if scope != "narrow" || revision != 1 || acknowledged != 0 {
		t.Fatalf("legacy authority = scope %q, revision %d, acknowledged %d", scope, revision, acknowledged)
	}
	var backfilled int
	if err := store.DB().QueryRow(`select count(*) from transfer_resumes where direction = 'receive' and visibility = 'public' and offered_root_revision = 1`).Scan(&backfilled); err != nil || backfilled != 3 {
		t.Fatalf("backfilled public receive rows = %d, %v", backfilled, err)
	}
}

func TestTransferConfirmationRollbackRejectsPendingCleanup(t *testing.T) {
	cfg, err := Config(KindAgent, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	store := sqlite.New(cfg)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer store.Stop(context.Background())
	sub, err := fs.Sub(migrationFiles, "migrations/agent")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, store.DB(), sub, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("c", 64)
	if _, err := store.DB().Exec(`insert into transfer_cleanup (direction, transfer_id, original_name, staged_name, phase, created_at) values ('receive', ?, ?, '.cleanup-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'intent', 1700000000)`, id, id+".part"); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(context.Background(), 5); err == nil {
		t.Fatal("rollback with pending cleanup succeeded")
	}
	var markers int
	if err := store.DB().QueryRow(`select count(*) from transfer_cleanup`).Scan(&markers); err != nil || markers != 1 {
		t.Fatalf("pending cleanup markers = %d, %v", markers, err)
	}
}

func TestMigrations(t *testing.T) {
	for _, kind := range []Kind{KindAgent, KindServer} {
		t.Run(string(kind), func(t *testing.T) {
			cfg, err := Config(kind, filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			store := sqlite.New(cfg)
			if err := store.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := store.Stop(context.Background()); err != nil {
					t.Error(err)
				}
			})

			var component string
			if err := store.DB().QueryRowContext(context.Background(), `select component from app_metadata where component = ?`, kind).Scan(&component); err != nil {
				t.Fatal(err)
			}
			if component != string(kind) {
				t.Fatalf("component = %q, want %q", component, kind)
			}
		})
	}
}

func TestPutReplacementMigrationPreservesCreateRowsAndGuardsModeEvidence(t *testing.T) {
	cfg, err := Config(KindAgent, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	store := sqlite.New(cfg)
	if err := store.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Stop(context.Background()) })
	sub, err := fs.Sub(migrationFiles, "migrations/agent")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, store.DB(), sub, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(t.Context(), 11); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`insert into contexts(name,server_url,server_id,device_id,private_key_path,public_key_path,label,state,enabled,offered_root,inbox_root,created_at,updated_at) values('home','http://server','server','device','private','public','device','connected',1,'offered','inbox',1,1)`); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	digest := strings.Repeat("0", 64)
	insert := `insert into put_transfers(direction,transfer_id,context_name,peer_device_id,local_device_id,peer_label,destination,mode,source_size,source_sha256,chunk_size,ack_window,put_root_revision,source_path,state,created_at,updated_at,expires_at,next_retry_at) values('send',?,'home','peer','device','peer','result','create',1,?,32768,8,1,'/source','transferring',1,1,2,1)`
	if _, err := store.DB().Exec(insert, id, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(t.Context(), 12); err != nil {
		t.Fatal(err)
	}
	var mode string
	var protocolVersion int
	var expected sql.NullString
	if err := store.DB().QueryRow(`select protocol_version,mode,expected_sha256 from put_transfers where transfer_id=?`, id).Scan(&protocolVersion, &mode, &expected); err != nil || protocolVersion != 2 || mode != "create" || expected.Valid {
		t.Fatalf("migrated create row protocol=%d mode=%q expected=%q valid=%t err=%v", protocolVersion, mode, expected.String, expected.Valid, err)
	}
	if _, err := store.DB().Exec(`update put_transfers set expected_sha256=? where transfer_id=?`, digest, id); err == nil {
		t.Fatal("create row accepted replacement CAS digest")
	}
	if _, err := store.DB().Exec(`insert into put_transfers(direction,transfer_id,context_name,peer_device_id,local_device_id,peer_label,destination,mode,source_size,source_sha256,chunk_size,ack_window,put_root_revision,source_path,state,created_at,updated_at,expires_at,next_retry_at) values('send',?,'home','peer','device','peer','result','replace',1,?,32768,8,1,'/source','transferring',1,1,2,1)`, strings.Repeat("b", 32), digest); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(t.Context(), 11); err == nil {
		t.Fatal("replacement row allowed lossy migration rollback")
	}
}

func TestWindowsPutReplacementMigrationPreservesUnixRowsAndGuardsBackupEvidence(t *testing.T) {
	cfg, err := Config(KindAgent, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	store := sqlite.New(cfg)
	if err := store.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Stop(context.Background()) })
	sub, err := fs.Sub(migrationFiles, "migrations/agent")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, store.DB(), sub, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(t.Context(), 12); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`insert into contexts(name,server_url,server_id,device_id,private_key_path,public_key_path,label,state,enabled,offered_root,inbox_root,put_root,allow_put,put_root_revision,created_at,updated_at) values('home','http://server','server','device','private','public','device','connected',1,'offered','inbox','put',1,1,1,1)`); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	digest := strings.Repeat("0", 64)
	identity := "unix1:0000000000000001:0000000000000002"
	if _, err := store.DB().Exec(`insert into put_transfers(direction,transfer_id,context_name,peer_device_id,local_device_id,peer_label,destination,mode,source_size,source_sha256,chunk_size,ack_window,put_root_revision,parent_path,parent_identity,stage_name,old_identity,old_uid,old_gid,old_mode,state,created_at,updated_at,expires_at,next_retry_at) values('receive',?,'home','peer','device','peer','result','replace',1,?,32768,8,1,'/put',?,'.px-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.put',?,1,1,384,'stage_intent',1,1,2,1)`, id, digest, identity, identity); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(t.Context(), 13); err != nil {
		t.Fatal(err)
	}
	var backupName, backupIdentity sql.NullString
	var backupSize, backupRemoved int64
	if err := store.DB().QueryRow(`select backup_name,backup_identity,backup_size,backup_removed from put_transfers where transfer_id=?`, id).Scan(&backupName, &backupIdentity, &backupSize, &backupRemoved); err != nil {
		t.Fatal(err)
	}
	if backupName.Valid || backupIdentity.Valid || backupSize != 0 || backupRemoved != 0 {
		t.Fatalf("legacy backup evidence name=%q identity=%q size=%d removed=%d", backupName.String, backupIdentity.String, backupSize, backupRemoved)
	}
	backupNameValue := ".px-" + id + ".bak"
	if _, err := store.DB().Exec(`update put_transfers set old_metadata='windowsmeta:test',backup_name=?,backup_identity=?,backup_size=1 where transfer_id=?`, backupNameValue, identity, id); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(t.Context(), 12); err == nil {
		t.Fatal("backup evidence allowed lossy migration rollback")
	}
}

func TestPutAcceptCurrentMigrationConstrainsResolutionAndGuardsRollback(t *testing.T) {
	cfg, err := Config(KindAgent, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	store := sqlite.New(cfg)
	if err := store.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Stop(context.Background()) })
	sub, err := fs.Sub(migrationFiles, "migrations/agent")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, store.DB(), sub, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(t.Context(), 13); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`insert into contexts(name,server_url,server_id,device_id,private_key_path,public_key_path,label,state,enabled,offered_root,inbox_root,put_root,allow_put,put_root_revision,created_at,updated_at) values('home','http://server','server','device','private','public','device','connected',1,'offered','inbox','put',1,7,1,1)`); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	digest := strings.Repeat("0", 64)
	identity := "unix1:0000000000000001:0000000000000002"
	stageName := ".px-" + id + ".put"
	if _, err := store.DB().Exec(`insert into put_transfers(direction,transfer_id,context_name,peer_device_id,local_device_id,peer_label,destination,mode,source_size,source_sha256,chunk_size,ack_window,put_root_revision,parent_path,parent_identity,stage_name,stage_identity,state,acknowledged_bytes,created_at,updated_at,expires_at,next_retry_at) values('receive',?,'home','peer','device','peer','result','create',1,?,32768,8,7,'/put',?,?,?,'outcome_unknown',1,1,1,2,1)`, id, digest, identity, stageName, identity); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(t.Context(), 14); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`update put_transfers set resolution_destination_identity=? where transfer_id=?`, identity, id); err == nil {
		t.Fatal("ordinary state accepted resolution evidence")
	}
	if _, err := store.DB().Exec(`update put_transfers set state='resolved_accept_current',resolution_destination_identity=?,parent_path=null,parent_identity=null,stage_name=null,stage_identity=null,resolved_at=2 where transfer_id=?`, identity, id); err == nil {
		t.Fatal("outcome-unknown row skipped accept-current intent")
	}
	if _, err := store.DB().Exec(`update put_transfers set state='accept_current_intent',resolution_destination_identity=? where transfer_id=?`, identity, id); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`update put_transfers set parent_path=null,parent_identity=null,stage_name=null,stage_identity=null,stage_removed=0,parent_synced=0,state='resolved_accept_current',resolved_at=2 where transfer_id=?`, id); err != nil {
		t.Fatal(err)
	}
	var state string
	var created, replaced int
	var durability sql.NullString
	if err := store.DB().QueryRow(`select state,created,replaced,durability from put_transfers where transfer_id=?`, id).Scan(&state, &created, &replaced, &durability); err != nil || state != "resolved_accept_current" || created != 0 || replaced != 0 || durability.Valid {
		t.Fatalf("resolved state=%q created=%d replaced=%d durability=%q valid=%t err=%v", state, created, replaced, durability.String, durability.Valid, err)
	}
	if _, err := provider.DownTo(t.Context(), 13); err == nil {
		t.Fatal("resolution evidence allowed lossy migration rollback")
	}
}

func TestRecentMigrationCreatesEmptyJournalAndGuardsRollback(t *testing.T) {
	cfg, err := Config(KindAgent, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	store := sqlite.New(cfg)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Stop(context.Background()) })
	sub, err := fs.Sub(migrationFiles, "migrations/agent")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, store.DB(), sub, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	now := int64(1_700_000_000)
	if _, err := store.DB().Exec(`insert into contexts(name,server_url,server_id,device_id,private_key_path,public_key_path,label,state,enabled,offered_root,inbox_root,created_at,updated_at) values('home','http://server','server','device','private','public','device','connected',1,'offered','inbox',?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`insert into transfer_resumes(direction,transfer_id,context_name,peer_device_id,peer_label,destination_name,source_size,source_sha256,chunk_size,ack_window,resume_token,acknowledged_bytes,state,created_at,updated_at,expires_at,manifest_version,visibility) values('send',?,'home','peer','peer','file',1,?,32768,8,'token',1,'transferring',?,?,?,3,'private')`, strings.Repeat("a", 64), strings.Repeat("0", 64), now, now, now+1); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(context.Background(), 11); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.DB().QueryRow(`select count(*) from recent_observations`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("backfilled rows = %d, %v", count, err)
	}
	if _, err := store.DB().Exec(`insert into recent_observations(context_name,direction,transfer_id,kind,peer_device_id,peer_label,destination_name,visibility,bytes,observed_at) values('home','send',?,'sender_observed_commit',?,'peer','file','private',1,?)`, strings.Repeat("b", 64), strings.Repeat("A", 43), now); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(context.Background(), 10); err == nil {
		t.Fatal("rollback with recent rows succeeded")
	}
}

func TestGetCleanupMigrationConstraintsAndRollbackGuard(t *testing.T) {
	cfg, err := Config(KindAgent, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	store := sqlite.New(cfg)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Stop(context.Background()) })
	sub, err := fs.Sub(migrationFiles, "migrations/agent")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, store.DB(), sub, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 64)
	token := strings.Repeat("b", 64)
	insert := `insert into get_cleanup(cleanup_id,parent_path,parent_identity,stage_name,marker_name,marker_token,declared_bytes,phase,created_at,updated_at,expires_at,next_retry_at) values(?,?,?,?,?,?,?,'reserved',1,1,2,2)`
	if _, err := store.DB().Exec(insert, id, "/tmp", "linux1:0000000000000001:0000000000000002", ".px-"+id+".get", ".owner-"+token, token, int64(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(insert, strings.ToUpper(id), "/tmp", "identity", ".px-"+id+".get", ".owner-"+token, token, int64(1)); err == nil {
		t.Fatal("invalid cleanup ID passed SQL validation")
	}
	if _, err := store.DB().Exec(`update get_cleanup set lease_token=? where cleanup_id=?`, strings.Repeat("c", 64), id); err == nil {
		t.Fatal("unpaired cleanup lease passed SQL validation")
	}
	if _, err := store.DB().Exec(`update get_cleanup set lease_token=?,lease_expires_at=2 where cleanup_id=?`, "invalid", id); err == nil {
		t.Fatal("invalid cleanup lease token passed SQL validation")
	}
	if _, err := provider.DownTo(context.Background(), 6); err == nil {
		t.Fatal("rollback with pending get cleanup succeeded")
	}
	if _, err := store.DB().Exec(`delete from get_cleanup`); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(context.Background(), 6); err != nil {
		t.Fatalf("empty rollback failed: %v", err)
	}
}

func TestEnrollmentFactMigrationBackfillsOnlyPendingAndRollsBackSafely(t *testing.T) {
	store, provider := serverMigrationStore(t)
	ctx := context.Background()
	if _, err := provider.DownTo(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`insert into pending_enrollments(code, device_id, device_key, label, label_key, source_ip, created_at, expires_at) values ('ABCD-2345', 'pending-device', 'pending-key', 'pending', 'pending', '192.0.2.1', 100, 200)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`insert into members(device_id, device_key, label, label_key, revision, credential, created_at) values ('member-device', 'member-key', 'member', 'member', 1, '{}', 50)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`insert into audit_events(occurred_at, actor_type, action) values (50, 'local', 'legacy.action')`); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 4); err != nil {
		t.Fatal(err)
	}
	var pendingID, memberID string
	if err := store.DB().QueryRow(`select enrollment_id from pending_enrollments`).Scan(&pendingID); err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRow(`select enrollment_id from members`).Scan(&memberID); err != nil {
		t.Fatal(err)
	}
	if len(pendingID) != 32 || len(memberID) != 32 || pendingID == memberID {
		t.Fatalf("migration IDs pending=%q member=%q", pendingID, memberID)
	}
	var kind, deviceID, label string
	var occurred, expires int64
	if err := store.DB().QueryRow(`select kind, device_id, label, occurred_at, expires_at from enrollment_facts`).Scan(&kind, &deviceID, &label, &occurred, &expires); err != nil {
		t.Fatal(err)
	}
	if kind != "enrollment.pending_admitted" || deviceID != "pending-device" || label != "pending" || occurred != 100 || expires != 200 {
		t.Fatalf("backfilled fact = %q %q %q %d %d", kind, deviceID, label, occurred, expires)
	}
	var memberFacts int
	if err := store.DB().QueryRow(`select count(*) from enrollment_facts where enrollment_id = ?`, memberID).Scan(&memberFacts); err != nil || memberFacts != 0 {
		t.Fatalf("synthetic member facts = %d, %v", memberFacts, err)
	}
	if _, err := store.DB().Exec(`update audit_events set action = 'changed' where action = 'legacy.action'`); err == nil {
		t.Fatal("migrated legacy audit event was mutable")
	}
	if _, err := provider.DownTo(ctx, 3); err != nil {
		t.Fatalf("safe rollback failed: %v", err)
	}
	if _, err := store.DB().Exec(`select enrollment_id from members`); err == nil {
		t.Fatal("enrollment_id survived rollback")
	}
}

func TestEnrollmentFactMigrationRejectsLossyRollback(t *testing.T) {
	store, provider := serverMigrationStore(t)
	ctx := context.Background()
	enrollmentID := strings.Repeat("a", 32)
	if _, err := store.DB().Exec(`insert into pending_enrollments(code, device_id, device_key, label, label_key, source_ip, created_at, expires_at, enrollment_id) values ('ABCD-2345', 'pending-device', 'pending-key', 'pending', 'pending', '192.0.2.1', 100, 200, ?)`, enrollmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`insert into enrollment_facts(kind, enrollment_id, occurred_at, device_id, label, expires_at) values ('enrollment.pending_admitted', ?, 100, 'pending-device', 'pending', 200)`, enrollmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`insert into enrollment_facts(kind, enrollment_id, occurred_at, device_id, label) values ('enrollment.pending_expired', ?, 200, 'pending-device', 'pending')`, enrollmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(ctx, 3); err == nil {
		t.Fatal("lossy enrollment rollback succeeded")
	}
	var facts int
	if err := store.DB().QueryRow(`select count(*) from enrollment_facts`).Scan(&facts); err != nil || facts != 2 {
		t.Fatalf("facts after rejected rollback = %d, %v", facts, err)
	}
}

func TestEnrollmentFactMigrationRejectsNullableAdapterIdentityAndOpenRejections(t *testing.T) {
	store, _ := serverMigrationStore(t)
	if _, err := store.DB().Exec(`insert into enrollment_adapters(adapter_id, active, credential_hash, created_at, updated_at) values (null, 1, zeroblob(32), 1, 1)`); err == nil {
		t.Fatal("nullable adapter primary key succeeded")
	}
	if _, err := store.DB().Exec(`insert into enrollment_adapters(adapter_id, active, credential_hash, created_at, updated_at) values ('valid', 1, zeroblob(32), 1, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`insert into audit_events(occurred_at, actor_type, actor_id, action) values (1, 'adapter', 'valid', 'member.approved')`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`update audit_events set actor_id = 'changed' where actor_type = 'adapter'`); err == nil {
		t.Fatal("adapter audit event was mutable")
	}
	if _, err := store.DB().Exec(`update enrollment_adapters set adapter_id = null where adapter_id = 'valid'`); err == nil {
		t.Fatal("nullable adapter identity update succeeded")
	}
	if _, err := store.DB().Exec(`insert into enrollment_command_receipts(adapter_id, command_id, fingerprint, schema_version, action, enrollment_id, state, admitted_at, settled_at, rejection_code) values ('valid', 'command', zeroblob(32), 1, 'enrollment.approve', ?, 'rejected', 1, 2, 'provider_error')`, strings.Repeat("a", 32)); err == nil {
		t.Fatal("open rejection code succeeded")
	}
	if _, err := store.DB().Exec(`insert into enrollment_command_receipts(adapter_id, command_id, fingerprint, schema_version, action, enrollment_id, state, admitted_at, settled_at) values ('valid', 'null-rejection', zeroblob(32), 1, 'enrollment.approve', ?, 'rejected', 1, 2)`, strings.Repeat("a", 32)); err == nil {
		t.Fatal("nullable rejection code succeeded through SQLite CHECK semantics")
	}
	if _, err := store.DB().Exec(`insert into enrollment_command_receipts(adapter_id, command_id, fingerprint, schema_version, action, enrollment_id, state, admitted_at, settled_at, result_device_id, result_label) values ('valid', 'null-revision', zeroblob(32), 1, 'enrollment.approve', ?, 'committed', 1, 2, 'device', 'label')`, strings.Repeat("a", 32)); err == nil {
		t.Fatal("nullable committed revision succeeded through SQLite CHECK semantics")
	}
	enrollmentID := strings.Repeat("b", 32)
	if _, err := store.DB().Exec(`insert into enrollment_facts(kind, enrollment_id, occurred_at, device_id, label, expires_at) values ('enrollment.pending_admitted', ?, 1, 'device', 'label', 2)`, enrollmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`insert into enrollment_facts(kind, enrollment_id, occurred_at, device_id, label) values ('enrollment.member_approved', ?, 2, 'device', 'label')`, enrollmentID); err == nil {
		t.Fatal("nullable approval revision succeeded through SQLite CHECK semantics")
	}
}

func TestServerDatabaseLifecycleRestartMigratesVersionThreeEnrollmentState(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	cfg, err := Config(KindServer, path)
	if err != nil {
		t.Fatal(err)
	}
	first := sqlite.New(cfg)
	if err := first.Start(ctx); err != nil {
		t.Fatal(err)
	}
	sub, err := fs.Sub(migrationFiles, "migrations/server")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, first.DB(), sub, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := first.DB().Exec(`insert into pending_enrollments(code, device_id, device_key, label, label_key, source_ip, created_at, expires_at) values ('ABCD-2345', 'restart-device', 'restart-key', 'restart', 'restart', '192.0.2.1', 100, 200)`); err != nil {
		t.Fatal(err)
	}
	if err := first.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	second := sqlite.New(cfg)
	if err := second.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Stop(context.Background()) })
	var version int
	if err := second.DB().QueryRow(`select max(version_id) from goose_db_version where is_applied = 1`).Scan(&version); err != nil || version != 5 {
		t.Fatalf("migration version = %d, %v", version, err)
	}
	var facts int
	if err := second.DB().QueryRow(`select count(*) from enrollment_facts where device_id = 'restart-device' and kind = 'enrollment.pending_admitted'`).Scan(&facts); err != nil || facts != 1 {
		t.Fatalf("restart backfill facts = %d, %v", facts, err)
	}
}

func TestEnrollmentInviteMigrationConstraintsAndRollbackGuard(t *testing.T) {
	store, provider := serverMigrationStore(t)
	ctx := context.Background()
	inviteID := strings.Repeat("a", 32)
	insert := `insert into enrollment_invites(invite_id, verifier, label, label_key, issuer_type, issuer_device_id, created_at, expires_at) values (?, ?, ?, ?, ?, ?, ?, ?)`
	valid := []any{inviteID, make([]byte, 32), "Hal", "hal", "local", nil, int64(1), int64(61)}
	assertRejected := func(name string, values ...any) {
		t.Helper()
		if _, err := store.DB().Exec(insert, values...); err == nil {
			t.Fatalf("%s succeeded", name)
		}
	}
	changed := func(index int, value any) []any {
		values := append([]any(nil), valid...)
		values[index] = value
		return values
	}
	assertRejected("null invite ID", changed(0, nil)...)
	assertRejected("uppercase invite ID", changed(0, strings.ToUpper(inviteID))...)
	assertRejected("text verifier", changed(1, strings.Repeat("x", 32))...)
	assertRejected("short verifier", changed(1, make([]byte, 31))...)
	for _, label := range []string{"", "-bad", "bad label", strings.Repeat("a", 64)} {
		assertRejected("invalid label "+label, changed(2, label)...)
	}
	assertRejected("uppercase label key", changed(3, "Hal")...)
	assertRejected("mismatched label key", changed(3, "other")...)
	assertRejected("real created timestamp", changed(6, 1.5)...)
	assertRejected("text expiry timestamp", changed(7, "not-a-time")...)
	assertRejected("short lifetime", changed(7, int64(60))...)
	assertRejected("long lifetime", changed(7, int64(604802))...)
	assertRejected("local issuer ID", changed(5, strings.Repeat("A", 43))...)
	memberValues := append([]any(nil), valid...)
	memberValues[4] = "member"
	memberValues[5] = "malformed"
	assertRejected("malformed member issuer", memberValues...)
	memberValues[5] = strings.Repeat("A", 43)
	assertRejected("nonexistent member issuer", memberValues...)
	if _, err := store.DB().Exec(insert, valid...); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`update enrollment_invites set label = 'changed' where invite_id = ?`, inviteID); err == nil {
		t.Fatal("active invite was mutable")
	}
	if _, err := store.DB().Exec(`insert into audit_events(occurred_at, actor_type, action, target_invite_id, target_label) values (2, 'system', 'invite.expired', ?, 'Hal')`, inviteID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`update audit_events set target_invite_id = null where target_invite_id = ?`, inviteID); err == nil {
		t.Fatal("invite audit was mutable")
	}
	if _, err := provider.DownTo(ctx, 4); err == nil {
		t.Fatal("lossy invite rollback succeeded")
	}
	var invites, audits int
	store.DB().QueryRow(`select count(*) from enrollment_invites`).Scan(&invites)
	store.DB().QueryRow(`select count(*) from audit_events where target_invite_id = ?`, inviteID).Scan(&audits)
	if invites != 1 || audits != 1 {
		t.Fatalf("guard rollback invites=%d audits=%d", invites, audits)
	}
}

func TestEnrollmentInviteMigrationMemberCapacityAndAuditShapes(t *testing.T) {
	store, _ := serverMigrationStore(t)
	memberID := strings.Repeat("A", 43)
	if _, err := store.DB().Exec(`insert into members(device_id, device_key, label, label_key, revision, credential, created_at, enrollment_id) values (?, ?, 'issuer', 'issuer', 1, '{}', 1, ?)`, memberID, memberID, strings.Repeat("b", 32)); err != nil {
		t.Fatal(err)
	}
	insert := `insert into enrollment_invites(invite_id, verifier, label, label_key, issuer_type, issuer_device_id, created_at, expires_at) values (?, zeroblob(32), ?, ?, 'member', ?, 1, 61)`
	for index := range 16 {
		label := fmt.Sprintf("member-%02d", index)
		if _, err := store.DB().Exec(insert, fmt.Sprintf("%032x", index+1), label, label, memberID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.DB().Exec(insert, strings.Repeat("f", 32), "member-16", "member-16", memberID); err == nil {
		t.Fatal("17th active member invite succeeded")
	}

	validID := strings.Repeat("c", 32)
	validDevice := strings.Repeat("A", 43)
	validAudit := []string{
		`insert into audit_events(occurred_at,actor_type,action,target_invite_id,target_label) values (1,'local','invite.created','` + validID + `','Hal')`,
		`insert into audit_events(occurred_at,actor_type,actor_device_id,action,target_invite_id,target_label) values (1,'member','` + validDevice + `','invite.revoked','` + validID + `','Hal')`,
		`insert into audit_events(occurred_at,actor_type,actor_device_id,action,target_invite_id,target_label,target_device_id,target_revision) values (1,'device','` + validDevice + `','invite.redeemed','` + validID + `','Hal','` + validDevice + `',1)`,
		`insert into audit_events(occurred_at,actor_type,action,target_invite_id,target_label) values (1,'system','invite.expired','` + validID + `','Hal')`,
	}
	for _, statement := range validAudit {
		if _, err := store.DB().Exec(statement); err != nil {
			t.Fatalf("valid invite audit failed: %v", err)
		}
	}
	invalidAudit := []string{
		`insert into audit_events(occurred_at,actor_type,action) values (1,'system','legacy.action')`,
		`insert into audit_events(occurred_at,actor_type,action) values (1,'local','invite.unknown')`,
		`insert into audit_events(occurred_at,actor_type,action,target_invite_id,target_label) values (1,'device','invite.created','` + validID + `','Hal')`,
		`insert into audit_events(occurred_at,actor_type,action,target_label) values (1,'local','invite.created','Hal')`,
		`insert into audit_events(occurred_at,actor_type,action,target_invite_id,target_label) values (1,'local','invite.created','` + validID + `','-bad')`,
		`insert into audit_events(occurred_at,actor_type,actor_device_id,action,target_invite_id,target_label,target_device_id,target_revision) values (1,'device','` + validDevice + `','invite.redeemed','` + validID + `','Hal','other',1)`,
		`insert into audit_events(occurred_at,actor_type,actor_device_id,action,target_invite_id,target_label,target_device_id,target_revision) values (1,'device','` + validDevice + `','invite.redeemed','` + validID + `','Hal','` + validDevice + `',2)`,
		`insert into audit_events(occurred_at,actor_type,action,target_invite_id,target_label,target_device_id) values (1,'local','invite.revoked','` + validID + `','Hal','device')`,
		`insert into audit_events(occurred_at,actor_type,action,target_invite_id,target_label) values (1,'local','invite.expired','` + validID + `','Hal')`,
		`insert into audit_events(occurred_at,actor_type,action,target_invite_id) values (1,'local','legacy.action','` + validID + `')`,
	}
	for _, statement := range invalidAudit {
		if _, err := store.DB().Exec(statement); err == nil {
			t.Fatalf("invalid invite audit succeeded: %s", statement)
		}
	}
}

func TestEnrollmentInviteMigrationAllowsEmptyRollback(t *testing.T) {
	store, provider := serverMigrationStore(t)
	if _, err := provider.DownTo(context.Background(), 4); err != nil {
		t.Fatalf("empty invite rollback failed: %v", err)
	}
	if _, err := store.DB().Exec(`select target_invite_id from audit_events`); err == nil {
		t.Fatal("invite audit column survived rollback")
	}
}

func serverMigrationStore(t *testing.T) (*sqlite.Store, *goose.Provider) {
	t.Helper()
	cfg, err := Config(KindServer, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	store := sqlite.New(cfg)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Stop(context.Background()) })
	sub, err := fs.Sub(migrationFiles, "migrations/server")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, store.DB(), sub, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	return store, provider
}
