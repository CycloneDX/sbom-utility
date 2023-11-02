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

type BOMComponentStats struct {
	Total          int
	MapIdentifiers map[string]int
	MapTypes       map[string]int
	MapMimeTypes   map[string]int
	// Number w/o licenses
	// Number not in dependency graph
}

type BOMServiceStats struct {
	Total        int
	MapEndpoints map[string]int // map["name"] len(endpoints)
	// Number Unauthenticated
	// Number w/o licenses
}

type BOMVulnerabilityStats struct {
	Total int
	// Number w/o mitigation or workaround or rejected
	MapSeverities map[string]int
}

type StatisticsInfo struct {
	ComponentStats     *BOMComponentStats
	ServiceStats       *BOMServiceStats
	VulnerabilityStats *BOMVulnerabilityStats
}
