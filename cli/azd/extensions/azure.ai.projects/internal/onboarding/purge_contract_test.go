// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const regionalDeletedFixtureID = "/subscriptions/foundry-sub/providers/Microsoft.CognitiveServices/locations/eastus/" +
	"resourceGroups/new-foundry-rg/deletedAccounts/cog-official"

func newDeletedAccountPurgeFixture(t *testing.T) *cleanupARM {
	t.Helper()
	f := newCleanupARM(t, false, false)
	f.deploy(t)
	require.NoError(t, f.lifecycle.Cleanup(t.Context(), f.base.plan, false, nil))
	require.True(t, f.softDeleted)
	return f
}

func TestRegionalPurgeUsesActualWireIdentityAndIndependentCreationClocks(t *testing.T) {
	f := newDeletedAccountPurgeFixture(t)
	state, err := f.base.journal.Load(t.Context())
	require.NoError(t, err)
	source := state.Sources[strings.ToLower(f.spec.AccountID)]
	require.True(t, source.AccountSystemCreatedAt.IsZero(), "old journal has only the ARM inventory clock")
	transport := f.options.Transport
	gets, deletes := 0, 0
	f.options.Transport = contractARMOptions(func(request *http.Request) (*http.Response, error) {
		if strings.Contains(strings.ToLower(request.URL.Path), "/deletedaccounts/") {
			require.Equal(t, regionalDeletedFixtureID, request.URL.Path)
			require.Equal(t, "2025-06-01", request.URL.Query().Get("api-version"))
			if request.Method == http.MethodDelete {
				deletes++
				current, err := f.base.journal.Load(t.Context())
				require.NoError(t, err)
				saved := current.Sources[strings.ToLower(f.spec.AccountID)]
				require.Equal(t, source.CreatedTime, saved.CreatedTime, "the ARM birth timestamp is not rewritten")
				require.Equal(t, "2026-10-26T00:50:00.0413256Z", saved.AccountSystemCreatedAt.Format(time.RFC3339Nano))
				require.Equal(t, "2026-10-26T00:50:01.8662485Z", saved.AccountDateCreated.Format(time.RFC3339Nano))
			} else {
				require.Equal(t, http.MethodGet, request.Method)
				gets++
			}
		}
		return transport.Do(request)
	}).Transport
	f.lifecycle = NewLifecycle(contractCredential{}, f.options, f.base.journal)
	require.NoError(t, f.lifecycle.Cleanup(t.Context(), f.base.plan, true, nil))
	require.Equal(t, 1, deletes)
	require.Equal(t, 2, gets, "one regional GET before purge and one authoritative absence GET afterward")
	state, err = f.base.journal.Load(t.Context())
	require.NoError(t, err)
	assert.True(t, state.Foundry.AccountDeleted)
	assert.True(t, state.Foundry.Purged)
	assert.True(t, state.CleanupComplete)
	for id, record := range state.Assignments {
		assert.True(t, record.Deleted, id)
	}
	require.NoError(t, f.lifecycle.Cleanup(t.Context(), f.base.plan, true, nil))
	assert.Equal(t, 1, deletes, "persisted Purged prevents a second purge")
	assert.Equal(t, 2, gets, "persisted Purged does not requery the regional deletion cache")
}

func TestPurgePersistsExactRPBirthBeforeActiveAccountDeletion(t *testing.T) {
	f := newCleanupARM(t, false, false)
	f.deploy(t)
	transport := f.options.Transport
	accountDeletes := 0
	f.options.Transport = contractARMOptions(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodDelete && strings.EqualFold(request.URL.Path, f.spec.AccountID) {
			accountDeletes++
			state, err := f.base.journal.Load(t.Context())
			require.NoError(t, err)
			source := state.Sources[strings.ToLower(f.spec.AccountID)]
			require.False(t, source.AccountSystemCreatedAt.IsZero())
			require.False(t, source.AccountDateCreated.IsZero())
			require.NotEqual(t, source.CreatedTime, source.AccountSystemCreatedAt)
			require.NotEqual(t, source.CreatedTime, source.AccountDateCreated)
		}
		return transport.Do(request)
	}).Transport
	f.lifecycle = NewLifecycle(contractCredential{}, f.options, f.base.journal)
	require.NoError(t, f.lifecycle.Cleanup(t.Context(), f.base.plan, true, nil))
	assert.Equal(t, 1, accountDeletes)
	assert.True(t, f.purged)
}

func TestRegionalPurgeRejectsForeignIdentityAndUnprovenBirth(t *testing.T) {
	for _, scenario := range []string{
		"active resource ID", "wrong subscription", "wrong resource group", "wrong account",
		"wrong path region", "wrong location", "wrong name", "wrong type", "nonterminal deleted account",
		"missing RP birth", "missing dateCreated", "malformed dateCreated", "different creation operation",
		"missing deletion date", "deletion before creation", "missing source", "wrong source ID",
		"not initially absent", "missing ARM birth", "source outside creation operation",
		"partial recorded RP identity", "changed recorded RP birth", "changed recorded RP dateCreated",
	} {
		t.Run(scenario, func(t *testing.T) {
			f := newDeletedAccountPurgeFixture(t)
			state, err := f.base.journal.Load(t.Context())
			require.NoError(t, err)
			key := strings.ToLower(f.spec.AccountID)
			source := state.Sources[key]
			switch scenario {
			case "missing source":
				delete(state.Sources, key)
			case "wrong source ID":
				source.ID += "-foreign"
			case "not initially absent":
				source.InitiallyAbsent = false
			case "missing ARM birth":
				source.CreatedTime = time.Time{}
			case "source outside creation operation":
				source.CreatedTime = time.Date(2026, 10, 26, 0, 55, 0, 0, time.UTC)
			case "partial recorded RP identity":
				source.AccountSystemCreatedAt = source.CreatedTime
			case "changed recorded RP birth", "changed recorded RP dateCreated":
				source.AccountSystemCreatedAt, err = time.Parse(time.RFC3339Nano, "2026-10-26T00:50:00.0413256Z")
				require.NoError(t, err)
				source.AccountDateCreated, err = time.Parse(time.RFC3339Nano, "2026-10-26T00:50:01.8662485Z")
				require.NoError(t, err)
				if scenario == "changed recorded RP birth" {
					source.AccountSystemCreatedAt = source.AccountSystemCreatedAt.Add(time.Millisecond)
				} else {
					source.AccountDateCreated = source.AccountDateCreated.Add(time.Millisecond)
				}

			}
			if scenario != "missing source" {
				state.Sources[key] = source
			}
			require.NoError(t, f.base.journal.Save(t.Context(), state))
			transport := f.options.Transport
			purgeCalls := 0
			f.options.Transport = contractARMOptions(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodDelete && strings.Contains(request.URL.Path, "/deletedAccounts/") {
					purgeCalls++
				}
				response, err := transport.Do(request)
				if err != nil || request.Method != http.MethodGet || request.URL.Path != regionalDeletedFixtureID ||
					response.StatusCode != http.StatusOK {
					return response, err
				}
				var account map[string]any
				require.NoError(t, json.NewDecoder(response.Body).Decode(&account))
				require.NoError(t, response.Body.Close())
				properties := cleanupObject(t, account["properties"])
				switch scenario {
				case "active resource ID":
					account["id"] = f.spec.AccountID
				case "wrong subscription":
					account["id"] = strings.Replace(regionalDeletedFixtureID, "/foundry-sub/", "/foreign-sub/", 1)
				case "wrong resource group":
					account["id"] = strings.Replace(regionalDeletedFixtureID, "/new-foundry-rg/", "/foreign-rg/", 1)
				case "wrong account":
					account["id"] = regionalDeletedFixtureID + "-foreign"
				case "wrong path region":
					account["id"] = strings.Replace(regionalDeletedFixtureID, "/eastus/", "/westus/", 1)
				case "wrong location":
					account["location"] = "westus"
				case "wrong name":
					account["name"] = "foreign-account"
				case "wrong type":
					account["type"] = "Microsoft.CognitiveServices/accounts"
				case "nonterminal deleted account":
					properties["provisioningState"] = "Deleting"
				case "missing RP birth":
					delete(account, "systemData")
				case "missing dateCreated":
					delete(properties, "dateCreated")
				case "malformed dateCreated":
					properties["dateCreated"] = "not-a-timestamp"
				case "different creation operation":
					cleanupObject(t, account["systemData"])["createdAt"] = "2026-10-26T00:55:00Z"
					properties["dateCreated"] = "2026-10-26T00:55:01Z"
				case "missing deletion date":
					delete(properties, "deletionDate")
				case "deletion before creation":
					properties["deletionDate"] = "2025-01-01T00:00:00Z"
				}
				raw, err := json.Marshal(account)
				require.NoError(t, err)
				return contractARMResponse(request, 200, string(raw)), nil
			}).Transport
			f.lifecycle = NewLifecycle(contractCredential{}, f.options, f.base.journal)
			require.Error(t, f.lifecycle.Cleanup(t.Context(), f.base.plan, true, nil))
			assert.Zero(t, purgeCalls, "unverified regional response cannot authorize irreversible DELETE")
			assert.False(t, f.purged)
			state, err = f.base.journal.Load(t.Context())
			require.NoError(t, err)
			assert.False(t, state.Foundry.Purged)
			assert.False(t, state.CleanupComplete)
			assert.True(t, f.softDeleted, "retain the regional recovery record on failure")
		})
	}
}

func TestRegionalPurgeRequiresExactSuccessfulCreationEvidence(t *testing.T) {
	for _, scenario := range []string{
		"missing attempt", "missing evidence", "changed snapshot digest", "changed template digest",
		"changed correlation", "missing account Create", "failed account Create", "read account operation",
		"foreign operation ID", "foreign account target", "missing operation time", "missing operation duration",
		"operation outside root interval", "replacement in a later attempt", "cleanup not started", "account not deleted",
	} {
		t.Run(scenario, func(t *testing.T) {
			f := newDeletedAccountPurgeFixture(t)
			state, err := f.base.journal.Load(t.Context())
			require.NoError(t, err)
			client, err := armcognitiveservices.NewDeletedAccountsClient(f.base.plan.SubscriptionID,
				contractCredential{}, f.options)
			require.NoError(t, err)
			account, err := client.Get(t.Context(), f.spec.Location,
				f.base.plan.ResourceGroup, f.base.plan.Account.Name, nil)
			require.NoError(t, err)
			attempt := &state.Foundry.Attempts[0]
			switch scenario {
			case "missing attempt":
				state.Foundry.Attempts = nil
			case "missing evidence":
				attempt.Evidence = nil
			case "changed snapshot digest":
				attempt.Evidence.Digest += "changed"
			case "changed template digest":
				attempt.TemplateDigest += "changed"
			case "changed correlation":
				attempt.CorrelationID += "-foreign"
			case "cleanup not started":
				state.CleanupStarted = false
			case "account not deleted":
				state.Foundry.AccountDeleted = false
			default:
				if scenario == "replacement in a later attempt" {
					raw, err := json.Marshal(attempt)
					require.NoError(t, err)
					var later FoundryAttempt
					require.NoError(t, json.Unmarshal(raw, &later))
					later.CorrelationID += "-later"
					later.Evidence.Properties.CorrelationID = new(later.CorrelationID)
					for _, properties := range later.Evidence.Deployments {
						if properties != nil {
							properties.CorrelationID = new(later.CorrelationID)
						}
					}
					state.Foundry.Attempts = append(state.Foundry.Attempts, later)
					attempt = &state.Foundry.Attempts[1]
					account.SystemData.CreatedAt = new(time.Date(2026, 10, 26, 0, 55, 0, 0, time.UTC))
					account.Properties.DateCreated = new("2026-10-26T00:55:01Z")
				}
				matched := false
				for deploymentID, operations := range attempt.Evidence.Operations {
					for index, operation := range operations {
						if operation == nil || operation.Properties == nil || operation.Properties.TargetResource == nil ||
							!strings.EqualFold(authString(operation.Properties.TargetResource.ID), f.spec.AccountID) {
							continue
						}
						matched = true
						switch scenario {
						case "missing account Create":
							attempt.Evidence.Operations[deploymentID] = append(operations[:index], operations[index+1:]...)
						case "failed account Create":
							operation.Properties.ProvisioningState = new("Failed")
						case "read account operation":
							operation.Properties.ProvisioningOperation = new(armresources.ProvisioningOperationRead)
						case "foreign operation ID":
							operation.ID = new(deploymentID + "-foreign/operations/account")
						case "foreign account target":
							operation.Properties.TargetResource.ID = new(f.spec.AccountID + "-foreign")
						case "missing operation time":
							operation.Properties.Timestamp = nil
						case "missing operation duration":
							operation.Properties.Duration = nil
						case "operation outside root interval":
							operation.Properties.Duration = new("PT2H")
						case "replacement in a later attempt":
							operation.Properties.Timestamp = new(time.Date(2026, 10, 26, 0, 54, 0, 0, time.UTC))
						}
					}
				}
				require.True(t, matched)
				attempt.Evidence.Digest, err = evidenceDigest(*attempt.Evidence)
				require.NoError(t, err)
			}
			_, err = f.lifecycle.(*ownedLifecycle).verifyDeletedAccount(t.Context(), f.base.plan, &state, account.Account)
			require.Error(t, err)
			assert.False(t, f.purged)
			assert.True(t, f.softDeleted)
		})
	}
}

func TestRegionalPurgeStopsWhenBirthEvidenceCannotBePersisted(t *testing.T) {
	f := newDeletedAccountPurgeFixture(t)
	transport := f.options.Transport
	purges := 0
	f.options.Transport = contractARMOptions(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == regionalDeletedFixtureID {
			if request.Method == http.MethodGet {
				f.base.journal.fail = true
			} else if request.Method == http.MethodDelete {
				purges++
			}
		}
		return transport.Do(request)
	}).Transport
	f.lifecycle = NewLifecycle(contractCredential{}, f.options, f.base.journal)
	require.ErrorContains(t, f.lifecycle.Cleanup(t.Context(), f.base.plan, true, nil), "journal unavailable")
	require.Zero(t, purges)
	f.base.journal.fail = false
	state, err := f.base.journal.Load(t.Context())
	require.NoError(t, err)
	assert.True(t, state.Foundry.AccountDeleted)
	assert.False(t, state.Foundry.Purged)
	assert.True(t, state.Sources[strings.ToLower(f.spec.AccountID)].AccountSystemCreatedAt.IsZero())
}
