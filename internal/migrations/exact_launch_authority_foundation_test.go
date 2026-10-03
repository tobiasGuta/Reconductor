package migrations

import (
	"context"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestExactAuthorityPopulatedUpgradeAndIdentityConstraints(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "exact_22_upgrade_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	pool, err := pgxpool.New(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyEmbeddedMigrationsThrough(t, ctx, pool, 21)
	programID, scopeID, policyID := domain.NewID(), domain.NewID(), domain.NewID()
	definitionID, taskID := domain.NewID(), domain.NewID()
	for _, item := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO programs(id,name,platform,scope_reference,policy_reference)
			VALUES($1,$2,'integration','synthetic://legacy','legacy-policy')`, []any{programID, "exact-populated-" + string(programID)}},
		{`INSERT INTO scopes(id,program_id,version,definition) VALUES($1,$2,1,'{}')`, []any{scopeID, programID}},
		{`INSERT INTO policies(id,program_id,version,definition) VALUES($1,$2,1,'{}')`, []any{policyID, programID}},
		{`INSERT INTO workflow_definitions(id,name,version,definition) VALUES($1,$2,'1','{}')`, []any{definitionID, "exact-populated-" + string(definitionID)}},
		{`INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by)
			VALUES($1,$2,'legacy',$3,'pending','reviewer')`, []any{taskID, programID, definitionID}},
		{`INSERT INTO approvals(id,request_id,task_id,action_request_id,requested_risk_level,reason,decision)
			VALUES($1,$2,$3,$4,'low','legacy','approved')`, []any{domain.NewID(), domain.NewID(), taskID, domain.NewID()}},
	} {
		if _, err := pool.Exec(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var status string
	var epoch int64
	var scopePointer, policyPointer *domain.ID
	if err := pool.QueryRow(ctx, `SELECT status,authority_epoch,active_scope_id,active_policy_id
		FROM program_launch_authority WHERE program_id=$1`, programID).Scan(&status, &epoch, &scopePointer, &policyPointer); err != nil {
		t.Fatal(err)
	}
	if status != "BLOCKED" || epoch != 0 || scopePointer != nil || policyPointer != nil {
		t.Fatalf("populated upgrade authority=%q epoch=%d scope=%v policy=%v", status, epoch, scopePointer, policyPointer)
	}
	var kind string
	if err := pool.QueryRow(ctx, `SELECT approval_kind FROM approvals WHERE task_id=$1`, taskID).Scan(&kind); err != nil || kind != "workflow_step" {
		t.Fatalf("legacy approval kind=%q err=%v", kind, err)
	}
	assertRejected := func(label, statement string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, statement, args...); err == nil {
			t.Fatalf("accepted %s", label)
		}
	}
	// Even after a newer epoch exists, ordinary DML cannot recreate an old one.
	if _, err := pool.Exec(ctx, `UPDATE program_launch_authority SET authority_epoch=10 WHERE program_id=$1`, programID); err != nil {
		t.Fatal(err)
	}
	assertRejected("authority delete", `DELETE FROM program_launch_authority WHERE program_id=$1`, programID)
	assertRejected("authority identity mutation", `UPDATE program_launch_authority SET program_id=$2,authority_epoch=11 WHERE program_id=$1`, programID, domain.NewID())
	assertRejected("stale epoch", `UPDATE program_launch_authority SET authority_epoch=1 WHERE program_id=$1`, programID)
	assertRejected("incomplete READY", `UPDATE program_launch_authority SET status='READY',authority_epoch=11 WHERE program_id=$1`, programID)
	if err := pool.QueryRow(ctx, `SELECT authority_epoch FROM program_launch_authority WHERE program_id=$1`, programID).Scan(&epoch); err != nil || epoch != 10 {
		t.Fatalf("authority epoch after rejected reset=%d err=%v", epoch, err)
	}
	hash := strings.Repeat("a", 64)
	assertRejected("scope NULL hash", `INSERT INTO scopes(id,program_id,version,definition,material_schema,evaluator_revision,canonical_material,material_sha256,scope_digest)
		VALUES($1,$2,2,'{}','exact-launch-scope/v1','reconductor-scope/v1','{}'::bytea,NULL,$3)`, domain.NewID(), programID, hash)
	assertRejected("scope NULL digest", `INSERT INTO scopes(id,program_id,version,definition,material_schema,evaluator_revision,canonical_material,material_sha256,scope_digest)
		VALUES($1,$2,2,'{}','exact-launch-scope/v1','reconductor-scope/v1','{}'::bytea,$3,NULL)`, domain.NewID(), programID, hash)
	assertRejected("policy NULL hash", `INSERT INTO policies(id,program_id,version,definition,material_schema,evaluator_revision,canonical_material,material_sha256)
		VALUES($1,$2,2,'{}','exact-launch-policy/v1','reconductor-policy/v1','{}'::bytea,NULL)`, domain.NewID(), programID)
	var legacyNull bool
	if err := pool.QueryRow(ctx, `SELECT (SELECT canonical_material IS NULL AND material_sha256 IS NULL FROM scopes WHERE id=$1)
		AND (SELECT canonical_material IS NULL AND material_sha256 IS NULL FROM policies WHERE id=$2)`, scopeID, policyID).Scan(&legacyNull); err != nil || !legacyNull {
		t.Fatalf("legacy material changed=%v err=%v", legacyNull, err)
	}
	providerAttemptID, anotherAttemptID := domain.NewID(), domain.NewID()
	for _, id := range []domain.ID{providerAttemptID, anotherAttemptID} {
		if _, err := pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,safe_message)
			VALUES($1,'review_fixture_attempt','review','review',$2,'fixture attempt')`, id, programID); err != nil {
			t.Fatal(err)
		}
	}
	insertExact := `INSERT INTO approvals(id,request_id,task_id,action_request_id,requested_risk_level,reason,decision,
		approval_kind,action_sha256,review_context_sha256,bound_provider_attempt_id)
		VALUES($1,$2,$3,$4,'low','review','pending','exact_action',$5,$6,$7)`
	assertRejected("exact NULL action hash", insertExact, domain.NewID(), domain.NewID(), taskID, domain.NewID(), nil, hash, providerAttemptID)
	assertRejected("exact NULL review hash", insertExact, domain.NewID(), domain.NewID(), taskID, domain.NewID(), hash, nil, providerAttemptID)
	approvalID, actionID := domain.NewID(), domain.NewID()
	if _, err := pool.Exec(ctx, insertExact, approvalID, domain.NewID(), taskID, actionID, hash, hash, providerAttemptID); err != nil {
		t.Fatal(err)
	}
	assertRejected("bound exact approval delete before companion", `DELETE FROM approvals WHERE id=$1`, approvalID)
	assertRejected("bound exact approval ID change", `UPDATE approvals SET id=$2 WHERE id=$1`, approvalID, domain.NewID())
	assertRejected("bound X change", `UPDATE approvals SET bound_provider_attempt_id=$2 WHERE id=$1`, approvalID, anotherAttemptID)
	assertRejected("action hash change", `UPDATE approvals SET action_sha256=$2 WHERE id=$1`, approvalID, strings.Repeat("b", 64))
	assertRejected("action identity change", `UPDATE approvals SET action_request_id=$2 WHERE id=$1`, approvalID, domain.NewID())
	assertRejected("approval kind change", `UPDATE approvals SET approval_kind='workflow_step' WHERE id=$1`, approvalID)
	if err := pool.QueryRow(ctx, `SELECT bound_provider_attempt_id FROM approvals WHERE id=$1`, approvalID).Scan(&anotherAttemptID); err != nil || anotherAttemptID != providerAttemptID {
		t.Fatalf("exact P binding changed=%s err=%v", anotherAttemptID, err)
	}
	legacyID := domain.NewID()
	if _, err := pool.Exec(ctx, `INSERT INTO approvals(id,request_id,task_id,action_request_id,requested_risk_level,reason,decision)
		VALUES($1,$2,$3,$4,'low','legacy','pending')`, legacyID, domain.NewID(), taskID, domain.NewID()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM approvals WHERE id=$1`, legacyID); err != nil {
		t.Fatalf("legacy approval delete changed: %v", err)
	}
}
