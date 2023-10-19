/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	. "github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/resources"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/jwangsadinata/go-multimap/slicemultimap"
)

const (
	POLICY_ALLOW        = "allow"
	POLICY_DENY         = "deny"
	POLICY_NEEDS_REVIEW = "needs-review"
	POLICY_UNDEFINED    = "UNDEFINED"
	POLICY_CONFLICT     = "CONFLICT"
)

var VALID_USAGE_POLICIES = []string{POLICY_ALLOW, POLICY_DENY, POLICY_NEEDS_REVIEW}
var ALL_USAGE_POLICIES = []string{POLICY_ALLOW, POLICY_DENY, POLICY_NEEDS_REVIEW, POLICY_UNDEFINED, POLICY_CONFLICT}

// Note: the SPDX spec. does not provide regex for an SPDX ID, but provides the following in ABNF:
//
//	string = 1*(ALPHA / DIGIT / "-" / "." )
//
// Currently, the regex below tests composition of of only
// alphanum, "-", and "." characters and disallows empty strings
// TODO:
//   - First and last chars are not "-" or "."
//   - Enforce reasonable min/max lengths
//     In theory, we can check overall length with positive lookahead
//     (e.g., min 3 max 128):  (?=.{3,128}$)
//     However, this does not appear to be supported in `regexp` package
//     or perhaps it must be a compiled expression TBD
const (
	REGEX_VALID_SPDX_ID = "^[a-zA-Z0-9.-]+$"
)

// compiled regexp. to save time
var spdxIdRegexp *regexp.Regexp

type LicensePolicy struct {
	Id             string   `json:"id"`
	Reference      string   `json:"reference"`
	IsOsiApproved  bool     `json:"osi"`
	IsFsfLibre     bool     `json:"fsf"`
	IsDeprecated   bool     `json:"deprecated"`
	Family         string   `json:"family"`
	Name           string   `json:"name"`
	UsagePolicy    string   `json:"usagePolicy"`
	Aliases        []string `json:"aliases"`
	Children       []string `json:"children"`
	Notes          []string `json:"notes"`
	Urls           []string `json:"urls"`
	AnnotationRefs []string `json:"annotationRefs"`

	// Alternative field names for --where searches
	AltUsagePolicy    string `json:"usage-policy"`
	AltAnnotationRefs string `json:"annotations"`
	AltSPDXId         string `json:"spdx-id"`
}

type LicenseComplianceConfig struct {
	PolicyList            []LicensePolicy   `json:"policies"`
	Annotations           map[string]string `json:"annotations"`
	policyConfigFile      string
	loadOnce              sync.Once
	hashOnce              sync.Once
	licenseFamilyNameMap  *slicemultimap.MultiMap
	licenseIdMap          *slicemultimap.MultiMap
	filteredFamilyNameMap *slicemultimap.MultiMap
}

func (config *LicenseComplianceConfig) Reset() {
	config.policyConfigFile = DEFAULT_LICENSE_POLICY_CONFIG
	config.PolicyList = nil
	config.Annotations = nil
	if config.licenseFamilyNameMap != nil {
		config.licenseFamilyNameMap.Clear()
	}
	if config.licenseIdMap != nil {
		config.licenseIdMap.Clear()
	}
}

func (config *LicenseComplianceConfig) GetFamilyNameMap() (hashmap *slicemultimap.MultiMap, err error) {
	if config.licenseFamilyNameMap == nil {
		err = config.HashLicensePolicies()
	}
	return config.licenseFamilyNameMap, err
}

func (config *LicenseComplianceConfig) GetLicenseIdMap() (hashmap *slicemultimap.MultiMap, err error) {
	if config.licenseIdMap == nil {
		err = config.HashLicensePolicies()
	}
	return config.licenseIdMap, err
}

func (config *LicenseComplianceConfig) GetFilteredFamilyNameMap(whereFilters []WhereFilter) (hashmap *slicemultimap.MultiMap, err error) {
	// NOTE: This call is necessary as this will cause all `licensePolicyConfig.PolicyList`
	// entries to have alternative field names to be mapped (e.g., `usagePolicy` -> `usage-policy`)
	config.filteredFamilyNameMap, err = config.GetFamilyNameMap()

	if err != nil {
		return
	}

	if len(whereFilters) > 0 {
		// Always use a new filtered hashmap for each filtered list request
		licensePolicyConfig.filteredFamilyNameMap = slicemultimap.New()
		err = licensePolicyConfig.filteredHashLicensePolicies(whereFilters)
	}
	return config.filteredFamilyNameMap, err
}

func (config *LicenseComplianceConfig) LoadLicensePolicies(filename string, defaultFilename string) (err error) {
	getLogger().Enter(filename)
	defer getLogger().Exit()

	// Only load the policy config. once
	config.loadOnce.Do(func() {
		err = config.innerLoadLicensePolicies(filename, defaultFilename)
	})

	return
}

func (config *LicenseComplianceConfig) innerLoadLicensePolicies(filename string, defaultFilename string) (err error) {
	getLogger().Enter(filename)
	defer getLogger().Exit()

	var buffer []byte

	// Always reset the config if a new policy file is loaded
	config.Reset()

	if filename != "" {

		// locate the license policy file
		config.policyConfigFile, err = utils.FindVerifyConfigFileAbsPath(getLogger(), filename)

		if err != nil {
			return fmt.Errorf("unable to find license policy file: `%s`", filename)
		}

		// attempt to read in contents of the policy config.
		getLogger().Infof("Loading license policy file: `%s`...", config.policyConfigFile)
		buffer, err = os.ReadFile(config.policyConfigFile)
		if err != nil {
			return fmt.Errorf("unable to `ReadFile`: `%s`", config.policyConfigFile)
		}
	} else {
		// Attempt to load the default config file from embedded file resources
		getLogger().Infof("Loading (embedded) default license policy file: `%s`...", defaultFilename)
		buffer, err = resources.LoadConfigFile(defaultFilename)
		if err != nil {
			return fmt.Errorf("unable to read schema config file: `%s` from embedded resources: `%s`",
				defaultFilename, resources.RESOURCES_CONFIG_DIR)
		}
	}

	// NOTE: this cleverly unmarshals into the current config instance this function is associated with
	errUnmarshal := json.Unmarshal(buffer, config)
	if errUnmarshal != nil {
		err = fmt.Errorf("cannot `Unmarshal`: `%s`", config.policyConfigFile)
		return
	}

	return
}

func (config *LicenseComplianceConfig) HashLicensePolicies() (hashError error) {
	getLogger().Enter()
	defer getLogger().Exit()

	config.hashOnce.Do(func() {
		hashError = config.innerHashLicensePolicies()
	})
	return
}

func (config *LicenseComplianceConfig) innerHashLicensePolicies() (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Note: we only need test to see if one of the maps has not been allocated
	// and populated to infer neither has
	config.licenseFamilyNameMap = slicemultimap.New()
	config.licenseIdMap = slicemultimap.New()

	for i, policy := range config.PolicyList {

		// Map old JSON key names to new key names (as they appear as titles in report columns)

		// Update the original entries in the []PolicyList stored in the global LicenseComplianceConfig
		getLogger().Debugf("Mapping: `Id`: `%s` to `spdx-id`: `%s`\n", policy.Id, policy.AltSPDXId)
		config.PolicyList[i].AltSPDXId = policy.Id
		getLogger().Debugf("Mapping: `UsagePolicy`: `%s` to `usage-policy`: `%s`\n", policy.Id, policy.AltSPDXId)
		config.PolicyList[i].AltUsagePolicy = policy.UsagePolicy
		getLogger().Debugf("Mapping: `AnnotationRefs`: `%s` to `annotations`: `%s`\n", policy.Id, policy.AltSPDXId)
		config.PolicyList[i].AltAnnotationRefs = strings.Join(policy.AnnotationRefs, ",")

		// Actually hash the policy
		err = config.hashPolicy(config.PolicyList[i])
		if err != nil {
			err = fmt.Errorf("unable to hash policy: %v", config.PolicyList[i])
			return
		}
	}
	return
}

// We will take the raw license policy and make it accessible for fast hash lookup
// Multiple hash maps are created understanding that license data in SBOMs can be
// based upon SPDX IDs <or> license names <or> license family names
// NOTE: we allow for both discrete policies based upon SPDX ID as well as
// "family" based policies.  This means given hash (lookup) might map to one or more
// family policies as well as a discrete one for specific SPDX ID.  In such cases,
// the policy MUST align (i.e., must not have both "allow" and "deny". Therefore,
// when we hash we assure that such a conflict does NOT exist at time of creation.
func (config *LicenseComplianceConfig) hashPolicy(policy LicensePolicy) (err error) {
	// ONLY hash valid policy records.
	if !IsValidPolicyEntry(policy) {
		// Do not add it to any hash table
		getLogger().Tracef("WARNING: invalid policy entry (id: `%s`, name: `%s`). Skipping...", policy.Id, policy.Name)
		return
	}

	// Only add to "id" hashmap if "Id" value is valid
	// NOTE: do NOT hash entries with "" (empty) Id values; however, they may represent a "family" entry
	if policy.Id != "" {
		getLogger().Debugf("ID Hashmap: Adding policy Id=`%s`, Name=`%s`, Family=`%s`", policy.Id, policy.Name, policy.Family)
		config.licenseIdMap.Put(policy.Id, policy)
	} else {
		getLogger().Debugf("WARNING: Skipping policy with no SPDX ID (empty)...")
	}

	// Assure we are not adding policy (value) to an existing hash
	// that represents a policy conflict.
	values, match := config.licenseFamilyNameMap.Get(policy.Family)

	// If a hashmap entry exists, see if current policy matches those
	// already added for that key
	if match {
		getLogger().Debugf("Family Hashmap: Entries exist for policy Id=`%s`, Name=`%s`, Family=`%s`", policy.Id, policy.Name, policy.Family)
		consistent := VerifyPoliciesMatch(policy, values)

		if !consistent {
			err = getLogger().Errorf("Multiple (possibly conflicting) policies declared for ID `%s`,family: `%s`, policy: `%s`",
				policy.Id,
				policy.Family,
				policy.UsagePolicy)
			return
		}
	}

	// NOTE: validation of policy struct (including "family" value) is done above
	getLogger().Debugf("Family Hashmap: Adding policy Id=`%s`, Name=`%s`, Family=`%s`", policy.Id, policy.Name, policy.Family)

	// Do NOT hash entries with and empty "Family" (name) value
	if policy.Family != "" {
		getLogger().Debugf("ID Hashmap: Adding policy Id=`%s`, Name=`%s`, Family=`%s`", policy.Id, policy.Name, policy.Family)
		config.licenseFamilyNameMap.Put(policy.Family, policy)
	} else {
		err = getLogger().Errorf("invalid policy: Family: \"\" (empty)")
		return
	}

	if len(policy.Children) > 0 {
		err = config.hashChildPolicies(policy)
		if err != nil {
			return
		}
	}

	return
}

func (config *LicenseComplianceConfig) hashChildPolicies(policy LicensePolicy) (err error) {

	for _, childId := range policy.Children {
		// Copy of the parent policy and overwrite its "id" with the child's
		childPolicy := policy
		childPolicy.Id = childId
		// Do NOT copy children as this will break recursion
		childPolicy.Children = nil
		// No need to copy Notes and Urls which carry "family" information and links
		childPolicy.Notes = nil
		childPolicy.Urls = nil

		err = config.hashPolicy(childPolicy)
		if err != nil {
			return
		}
	}

	return
}

func (config *LicenseComplianceConfig) filteredHashLicensePolicies(whereFilters []WhereFilter) (err error) {
	getLogger().Enter()
	defer getLogger().Exit(err)

	// NOTE: original []PolicyList includes values for both deprecated and current fields
	// So that filtered "queries" will work regardless (for backwards compatibility)
	for _, policy := range config.PolicyList {
		err = config.filteredHashLicensePolicy(policy, whereFilters)
		if err != nil {
			return
		}
	}
	return
}

// Hash a CDX Component and recursively those of any "nested" components
// TODO we should WARN if version is not a valid semver (e.g., examples/cyclonedx/BOM/laravel-7.12.0/bom.1.3.json)
func (config *LicenseComplianceConfig) filteredHashLicensePolicy(policy LicensePolicy, whereFilters []WhereFilter) (err error) {
	var match bool = true
	var mapPolicy map[string]interface{}

	// See if the policy matches where filters criteria
	if len(whereFilters) > 0 {
		mapPolicy, err = utils.ConvertStructToMap(policy)
		if err != nil {
			return
		}

		match, err = whereFilterMatch(mapPolicy, whereFilters)
		if err != nil {
			return
		}
	}

	// Hash policy if it matched where filters
	if match {
		getLogger().Debugf("Matched: Hashing Policy: id: %s, family: %s", policy.Id, policy.Family)
		config.filteredFamilyNameMap.Put(policy.Family, policy)
	}

	return
}

//------------------------------------------------
// CDX LicenseChoice "helper" functions
//------------------------------------------------

// "getter" for compiled regex expression
func getRegexForValidSpdxId() *regexp.Regexp {
	if spdxIdRegexp == nil {
		regex, err := regexp.Compile(REGEX_VALID_SPDX_ID)
		if err != nil {
			os.Exit(ERROR_APPLICATION)
		}
		spdxIdRegexp = regex
	}
	return spdxIdRegexp
}

func IsValidSpdxId(id string) bool {
	return getRegexForValidSpdxId().MatchString(id)
}

func IsValidFamilyKey(key string) bool {
	var BAD_KEYWORDS = []string{"CONFLICT", "UNKNOWN"}

	// For now, valid family keys are subsets of SPDX IDs
	// Therefore, pass result from that SPDX ID validation function
	valid := IsValidSpdxId(key)

	// Test for keywords that we have seen set that clearly are not valid family names
	// TODO: make keywords configurable
	for _, keyword := range BAD_KEYWORDS {
		if strings.Contains(strings.ToLower(key), strings.ToLower(keyword)) {
			return false
		}
	}

	return valid
}

//------------------------------------------------
// License Policy "helper" functions
//------------------------------------------------

func IsValidUsagePolicy(usagePolicy string) bool {
	for _, entry := range VALID_USAGE_POLICIES {
		if usagePolicy == entry {
			return true
		}
	}
	return false
}

// NOTE: policy.Id == "" we allow as "valid" as this indicates a potential "family" entry (i.e., group of SPDX IDs)
func IsValidPolicyEntry(policy LicensePolicy) bool {

	if policy.Id != "" && !IsValidSpdxId(policy.Id) {
		getLogger().Warningf("invalid SPDX ID: `%s` (Name=`%s`). Skipping...", policy.Id, policy.Name)
		return false
	}

	if strings.TrimSpace(policy.Name) == "" {
		getLogger().Warningf("invalid Name: `%s` (Id=`%s`).", policy.Name, policy.Id)
	}

	if !IsValidUsagePolicy(policy.UsagePolicy) {
		getLogger().Warningf("invalid Usage Policy: `%s` (Id=`%s`, Name=`%s`). Skipping...", policy.UsagePolicy, policy.Id, policy.Name)
		return false
	}

	if !IsValidFamilyKey(policy.Family) {
		getLogger().Warningf("invalid Family: `%s` (Id=`%s`, Name=`%s`). Skipping...", policy.Family, policy.Id, policy.Name)
		return false
	}

	if policy.Id == "" {
		if len(policy.Children) < 1 {
			getLogger().Debugf("Family (policy): `%s`. Has no children (SPDX IDs) listed.", policy.Family)
		}
		// Test to make sure "family" entries (i.e. policy.Id == "") have valid "children" (SPDX IDs)
		for _, childId := range policy.Children {
			if !IsValidSpdxId(childId) {
				getLogger().Warningf("invalid Id: `%s` for Family: `%s`. Skipping...", childId, policy.Family)
			}
		}
	}

	// TODO - make sure policies with valid "Id" do NOT have children as these are
	// intended to be discrete (non-family-grouped) entries
	return true
}

// given an array of policies verify their "usage" policy does not represent a conflict
func VerifyPoliciesMatch(testPolicy LicensePolicy, policies []interface{}) bool {

	var currentPolicy LicensePolicy
	testUsagePolicy := testPolicy.UsagePolicy

	for _, current := range policies {
		currentPolicy = current.(LicensePolicy)
		getLogger().Debugf("Usage Policy=%s", currentPolicy.UsagePolicy)

		if currentPolicy.UsagePolicy != testUsagePolicy {
			getLogger().Warningf("Policy (Id: %s, Family: %s, Policy: %s) is in conflict with policies (%s) declared in the same family.",
				currentPolicy.Id,
				currentPolicy.Family,
				currentPolicy.UsagePolicy,
				testUsagePolicy)
		}
	}

	return true
}
