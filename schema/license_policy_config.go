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

package schema

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/CycloneDX/sbom-utility/common"
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

// Note: the "License" property is used as hashmap key
// NOTE: CDXRefType is a named `string` type as of v1.5
type LicenseInfo struct {
	UsagePolicy            string           `json:"usage-policy"`
	LicenseChoiceTypeValue int              `json:"license-type-value"`
	LicenseChoiceType      string           `json:"license-type"`
	License                string           `json:"license"`
	ResourceName           string           `json:"resource-name"`
	BOMRef                 CDXRefType       `json:"bom-ref"`
	BOMLocationValue       int              `json:"bom-location-value"`
	BOMLocation            string           `json:"bom-location"`
	LicenseChoice          CDXLicenseChoice // Do not marshal
	Policy                 LicensePolicy    // Do not marshal
	Component              CDXComponent     // Do not marshal
	Service                CDXService       // Do not marshal
}

// LicenseChoice - Choice type
const (
	LC_TYPE_INVALID = iota
	LC_TYPE_ID
	LC_TYPE_NAME
	LC_TYPE_EXPRESSION
)

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

type LicensePolicyConfig struct {
	PolicyList              []LicensePolicy   `json:"policies"`
	Annotations             map[string]string `json:"annotations"`
	defaultPolicyConfigFile string
	policyConfigFile        string
	loadOnce                sync.Once
	hashOnce                sync.Once
	licenseFamilyNameMap    *slicemultimap.MultiMap
	licenseIdMap            *slicemultimap.MultiMap
	filteredFamilyNameMap   *slicemultimap.MultiMap
}

func NewLicensePolicyConfig(configFile string) *LicensePolicyConfig {
	temp := LicensePolicyConfig{
		defaultPolicyConfigFile: configFile,
		policyConfigFile:        configFile,
	}
	return &temp
}

func (config *LicensePolicyConfig) Reset() {
	config.policyConfigFile = config.defaultPolicyConfigFile
	config.PolicyList = nil
	config.Annotations = nil
	if config.licenseFamilyNameMap != nil {
		config.licenseFamilyNameMap.Clear()
	}
	if config.licenseIdMap != nil {
		config.licenseIdMap.Clear()
	}
	if config.filteredFamilyNameMap != nil {
		config.filteredFamilyNameMap.Clear()
	}
}

func (config *LicensePolicyConfig) GetFamilyNameMap() (hashmap *slicemultimap.MultiMap, err error) {
	if config.licenseFamilyNameMap == nil {
		err = config.hashLicensePolicies()
		fmt.Printf("!!!!!!!!!Not hashed!!!!!!!!!!")
	}
	return config.licenseFamilyNameMap, err
}

func (config *LicensePolicyConfig) GetLicenseIdMap() (hashmap *slicemultimap.MultiMap, err error) {
	if config.licenseIdMap == nil {
		err = config.hashLicensePolicies()
	}
	return config.licenseIdMap, err
}

func (config *LicensePolicyConfig) GetFilteredFamilyNameMap(whereFilters []common.WhereFilter) (hashmap *slicemultimap.MultiMap, err error) {
	// NOTE: This call is necessary as this will cause all `licensePolicyConfig.PolicyList`
	// entries to have alternative field names to be mapped (e.g., `usagePolicy` -> `usage-policy`)
	config.filteredFamilyNameMap, err = config.GetFamilyNameMap()

	if err != nil {
		return
	}

	if len(whereFilters) > 0 {
		// Always use a new filtered hashmap for each filtered list request
		config.filteredFamilyNameMap = slicemultimap.New()
		err = config.filteredHashLicensePolicies(whereFilters)
	}
	return config.filteredFamilyNameMap, err
}

func (config *LicensePolicyConfig) LoadHashPolicyConfigurationFile(policyFile string, defaultPolicyFile string) (err error) {
	// Do not pass a default file, it should fail if custom policy cannot be loaded
	// Only load the policy config. once
	config.loadOnce.Do(func() {
		err = config.innerLoadLicensePolicies(policyFile, defaultPolicyFile)
		if err != nil {
			return
		}

		// Note: the HashLicensePolicies function creates new id and name hashmaps
		// therefore there is no need to clear them
		err = config.hashLicensePolicies()
	})

	return
}

func (config *LicensePolicyConfig) innerLoadLicensePolicies(policyFile string, defaultPolicyFile string) (err error) {
	getLogger().Enter(policyFile)
	defer getLogger().Exit()

	var buffer []byte

	// Always reset the config if a new policy file is loaded
	config.Reset()

	if policyFile != "" {
		// locate the license policy file
		config.policyConfigFile, err = utils.FindVerifyConfigFileAbsPath(getLogger(), policyFile)

		if err != nil {
			return fmt.Errorf("unable to find license policy file: `%s`", policyFile)
		}

		// attempt to read in contents of the policy config.
		getLogger().Infof("Loading license policy file: `%s`...", config.policyConfigFile)
		buffer, err = os.ReadFile(config.policyConfigFile)
		if err != nil {
			return fmt.Errorf("unable to `ReadFile`: `%s`", config.policyConfigFile)
		}
	} else {
		// Attempt to load the default config file from embedded file resources
		getLogger().Infof("Loading (embedded) default license policy file: `%s`...", defaultPolicyFile)
		buffer, err = resources.LoadConfigFile(defaultPolicyFile)
		if err != nil {
			return fmt.Errorf("unable to read schema config file: `%s` from embedded resources: `%s`",
				defaultPolicyFile, resources.RESOURCES_CONFIG_DIR)
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

func (config *LicensePolicyConfig) hashLicensePolicies() (hashError error) {
	getLogger().Enter()
	defer getLogger().Exit()

	config.hashOnce.Do(func() {
		hashError = config.innerHashLicensePolicies()
	})
	return
}

func (config *LicensePolicyConfig) innerHashLicensePolicies() (err error) {
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
func (config *LicensePolicyConfig) hashPolicy(policy LicensePolicy) (err error) {
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

func (config *LicensePolicyConfig) hashChildPolicies(policy LicensePolicy) (err error) {

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

func (config *LicensePolicyConfig) filteredHashLicensePolicies(whereFilters []common.WhereFilter) (err error) {
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
func (config *LicensePolicyConfig) filteredHashLicensePolicy(policy LicensePolicy, whereFilters []common.WhereFilter) (err error) {
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

func (config *LicensePolicyConfig) FindPolicy(licenseInfo LicenseInfo) (matchedPolicy LicensePolicy, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Initialize to empty
	matchedPolicy = LicensePolicy{}

	switch licenseInfo.LicenseChoiceTypeValue {
	case LC_TYPE_ID:
		matchedPolicy.UsagePolicy, matchedPolicy, err = config.FindPolicyBySpdxId(licenseInfo.LicenseChoice.License.Id)
		if err != nil {
			return
		}
	case LC_TYPE_NAME:
		matchedPolicy.UsagePolicy, matchedPolicy, err = config.FindPolicyByFamilyName(licenseInfo.LicenseChoice.License.Name)
		if err != nil {
			return
		}
	case LC_TYPE_EXPRESSION:
		// Parse expression according to SPDX spec.
		var expressionTree *CompoundExpression
		expressionTree, err = ParseExpression(config, licenseInfo.LicenseChoice.Expression)
		if err != nil {
			return
		}
		getLogger().Debugf("Parsed expression:\n%v", expressionTree)
		matchedPolicy.UsagePolicy = expressionTree.CompoundUsagePolicy
	}

	if matchedPolicy.UsagePolicy == "" {
		matchedPolicy.UsagePolicy = POLICY_UNDEFINED
	}
	//return matchedPolicy, err
	return
}

func (config *LicensePolicyConfig) FindPolicyBySpdxId(id string) (policyValue string, matchedPolicy LicensePolicy, err error) {
	getLogger().Enter("id:", id)
	defer getLogger().Exit()

	var matched bool
	var arrPolicies []interface{}

	// Note: this will cause all policy hashmaps to be initialized (created), if it has not bee
	licensePolicyIdMap, err := config.GetLicenseIdMap()
	if err != nil {
		err = getLogger().Errorf("license policy map error: `%w`", err)
		return
	}

	arrPolicies, matched = licensePolicyIdMap.Get(id)
	getLogger().Tracef("licensePolicyMapById.Get(%s): (%v) matches", id, len(arrPolicies))

	// There MUST be ONLY one policy per (discrete) license ID
	if len(arrPolicies) > 1 {
		err = getLogger().Errorf("Multiple (possibly conflicting) policies declared for SPDX ID=`%s`", id)
		return
	}

	if matched {
		// retrieve the usage policy from the single (first) entry
		matchedPolicy = arrPolicies[0].(LicensePolicy)
		policyValue = matchedPolicy.UsagePolicy
	} else {
		getLogger().Tracef("No policy match found for SPDX ID=`%s` ", id)
		policyValue = POLICY_UNDEFINED
	}

	return
}

// NOTE: for now, we will look for the "family" name encoded in the License.Name field
// (until) we can get additional fields/properties added to the CDX LicenseChoice schema
func (config *LicensePolicyConfig) FindPolicyByFamilyName(name string) (policyValue string, matchedPolicy LicensePolicy, err error) {
	getLogger().Enter("name:", name)
	defer getLogger().Exit()

	var matched bool
	var key string
	var arrPolicies []interface{}

	// NOTE: we have found some SBOM authors have placed license expressions
	// within the "name" field.  This prevents us from assigning policy
	// return
	if hasLogicalConjunctionOrPreposition(name) {
		getLogger().Warningf("policy name contains logical conjunctions or preposition: `%s`", name)
		policyValue = POLICY_UNDEFINED
		return
	}

	// Note: this will cause all policy hashmaps to be initialized (created), if it has not been
	familyNameMap, _ := config.GetFamilyNameMap()

	// See if any of the policy family keys contain the family name
	matched, key, err = config.searchForLicenseFamilyName(name)
	if err != nil {
		return
	}

	if matched {
		arrPolicies, _ = familyNameMap.Get(key)

		if len(arrPolicies) == 0 {
			err = getLogger().Errorf("No policy match found in hashmap for family name key: `%s`", key)
			return
		}

		// NOTE: We can use the first policy (of a family) as they are
		// verified to be consistent when loaded from the policy config. file
		matchedPolicy = arrPolicies[0].(LicensePolicy)
		policyValue = matchedPolicy.UsagePolicy

		// If we have more than one license in the same family (name), then
		// check if there are any "usage policy" conflicts to display in report
		if len(arrPolicies) > 1 {
			conflict := policyConflictExists(arrPolicies)
			if conflict {
				getLogger().Tracef("Usage policy conflict for license family name=`%s` ", name)
				policyValue = POLICY_CONFLICT
			}
		}
	} else {
		getLogger().Tracef("No policy match found for license family name=`%s` ", name)
		policyValue = POLICY_UNDEFINED
	}

	return
}

// Loop through all known license family names (in hashMap) to see if any
// appear in the CDX License "Name" field
func (config *LicensePolicyConfig) searchForLicenseFamilyName(licenseName string) (found bool, familyName string, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	familyNameMap, err := config.GetFamilyNameMap()
	if err != nil {
		getLogger().Error(err)
		return
	}

	keys := familyNameMap.Keys()

	for _, key := range keys {
		familyName = key.(string)
		getLogger().Debugf("Searching for familyName: '%s' in License Name: %s", familyName, licenseName)
		found = containsFamilyName(licenseName, familyName)

		if found {
			getLogger().Debugf("Match found: familyName: '%s' in License Name: %s", familyName, licenseName)
			return
		}
	}

	return
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

// NOTE: caller assumes resp. for checking for empty input array
func policyConflictExists(arrPolicies []interface{}) bool {
	var currentUsagePolicy string
	var policy LicensePolicy

	// Init. usage policy to first entry in array
	policy = arrPolicies[0].(LicensePolicy)
	currentUsagePolicy = policy.UsagePolicy

	// Check every subsequent usage policy in array to identify mismatch (i.e., a conflict)
	for i := 1; i < len(arrPolicies); i++ {
		policy = arrPolicies[i].(LicensePolicy)
		if policy.UsagePolicy != currentUsagePolicy {
			return true
		}
	}
	return false
}

// Looks for an SPDX family (name) somewhere in the CDX License object "Name" field
func containsFamilyName(name string, familyName string) bool {
	// NOTE: we do not currently normalize as we assume family names
	// are proper substring of SPDX IDs which are mixed case and
	// should match exactly as encoded.
	return strings.Contains(name, familyName)
}

// Supported conjunctions and prepositions
const (
	AND                   string = "AND"
	OR                    string = "OR"
	WITH                  string = "WITH"
	CONJUNCTION_UNDEFINED string = ""
)

func hasLogicalConjunctionOrPreposition(value string) bool {

	if strings.Contains(value, AND) ||
		strings.Contains(value, OR) ||
		strings.Contains(value, WITH) {
		return true
	}
	return false
}

//------------------------------------------------
// CDX LicenseChoice "helper" functions
//------------------------------------------------

// "getter" for compiled regex expression
func getRegexForValidSpdxId() (regex *regexp.Regexp, err error) {
	if spdxIdRegexp == nil {
		regex, err = regexp.Compile(REGEX_VALID_SPDX_ID)
	}
	return
}

func IsValidSpdxId(id string) bool {
	regex, err := getRegexForValidSpdxId()
	if err != nil {
		getLogger().Error(fmt.Errorf("unable to invoke regex. %v", err))
		return false
	}
	return regex.MatchString(id)
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
