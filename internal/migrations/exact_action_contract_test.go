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

func TestExactActionPopulatedV22Upgrade(t *testing.T) {
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
	schema := "exact_23_upgrade_" + strconv.FormatInt(time.Now().UnixNano(), 10)
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
	applyEmbeddedMigrationsThrough(t, ctx, pool, 22)
	programID, scopeID, policyID, definitionID, taskID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	for _, item := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES($1,$2,'test','scope','policy')`, []any{programID, "v22-program-" + string(programID)}},
		{`INSERT INTO program_launch_authority(program_id) VALUES($1)`, []any{programID}},
		{`INSERT INTO scopes(id,program_id,version,definition) VALUES($1,$2,1,'{}')`, []any{scopeID, programID}},
		{`INSERT INTO policies(id,program_id,version,definition) VALUES($1,$2,1,'{}')`, []any{policyID, programID}},
		{`INSERT INTO workflow_definitions(id,name,version,definition) VALUES($1,$2,'1','{}')`, []any{definitionID, "v22-definition-" + string(definitionID)}},
		{`INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES($1,$2,'legacy',$3,'pending','tester')`, []any{taskID, programID, definitionID}},
		{`INSERT INTO approvals(id,request_id,task_id,action_request_id,requested_risk_level,reason,decision) VALUES($1,$2,$3,$4,'low','legacy','approved')`, []any{domain.NewID(), domain.NewID(), taskID, domain.NewID()}},
	} {
		if _, err := pool.Exec(ctx, item.sql, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	providerAttemptID, approvalID, actionID := domain.NewID(), domain.NewID(), domain.NewID()
	if _, err := pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,safe_message) VALUES($1,'historical_exact','test','migration',$2,'existing X')`, providerAttemptID, programID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO approvals(id,request_id,task_id,action_request_id,requested_risk_level,reason,decision,approval_kind,action_sha256,review_context_sha256,bound_provider_attempt_id)
		VALUES($1,$2,$3,$2,'low','existing exact','pending','exact_action',$4,$5,$6)`, approvalID, actionID, taskID, strings.Repeat("a", 64), strings.Repeat("b", 64), providerAttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO exact_dispatch_attempts(provider_attempt_id,approval_id,program_id,action_request_id,action_sha256)
		VALUES($1,$2,$3,$4,$5)`, providerAttemptID, approvalID, programID, actionID, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := RequireCurrent(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var kind, status string
	var epoch int64
	if err := pool.QueryRow(ctx, `SELECT approval_kind FROM approvals WHERE task_id=$1 AND approval_kind='workflow_step'`, taskID).Scan(&kind); err != nil || kind != "workflow_step" {
		t.Fatalf("legacy kind=%q err=%v", kind, err)
	}
	if err := pool.QueryRow(ctx, `SELECT status,authority_epoch FROM program_launch_authority WHERE program_id=$1`, programID).Scan(&status, &epoch); err != nil || status != "BLOCKED" || epoch != 0 {
		t.Fatalf("authority status=%q epoch=%d err=%v", status, epoch, err)
	}
	var exactDecision, dispatchState string
	if err := pool.QueryRow(ctx, `SELECT a.decision,d.state FROM approvals a JOIN exact_dispatch_attempts d ON d.approval_id=a.id WHERE a.id=$1 AND d.provider_attempt_id=$2`, approvalID, providerAttemptID).Scan(&exactDecision, &dispatchState); err != nil || exactDecision != "pending" || dispatchState != "UNDISPATCHED" {
		t.Fatalf("historical exact P/X state=%q/%q err=%v", exactDecision, dispatchState, err)
	}
}
