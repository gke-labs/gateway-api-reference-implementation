// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package state

import (
	"cmp"
	"fmt"
	"net/http"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// ConditionError is an error that makes a status condition false, with the reason and message to report.
type ConditionError struct {
	// Type is the condition type that becomes false.
	Type string

	// Reason is the machine-readable reason to report in the condition.
	Reason string

	// Message is the human-readable message to report in the condition.
	Message string
}

// Error returns the error message.
func (e *ConditionError) Error() string {
	return e.Message
}

// toErrorState builds an ErrorState from the condition error for proxy responses.
func (e *ConditionError) toErrorState() *ErrorState {
	return &ErrorState{
		HTTPStatusCode: http.StatusInternalServerError,
		HTTPMessage:    e.Message,
	}
}

// ConditionWarning is a warning that leaves a status condition true, with the reason and message to report.
type ConditionWarning struct {
	// Type is the condition type that receives the warning.
	Type string

	// Reason is the machine-readable reason to report in the condition.
	Reason string

	// Message is the human-readable message to report in the condition.
	Message string
}

// newValidationError builds a ConditionError for an unsupported or invalid route value.
func newValidationError(message string) *ConditionError {
	return &ConditionError{
		Type:    string(gatewayv1.RouteConditionAccepted),
		Reason:  string(gatewayv1.RouteReasonUnsupportedValue),
		Message: message,
	}
}

// buildCondition constructs a condition of the specified type from collected errors and warnings.
// If the error list contains an error of that type, it returns a False condition whose reason comes from the
// first error of that type and whose message joins up to five distinct error messages of that type in list order.
// Otherwise, if the warning list contains a warning of that type, it returns a True condition whose reason comes
// from the first warning of that type and whose message joins up to five distinct warning messages of that type.
// Otherwise, it returns a True condition with trueReason and trueMessage.
// List order decides which item is first, so callers append in a fixed order.
func buildCondition(errs []*ConditionError, warnings []*ConditionWarning, conditionType, trueReason, trueMessage string, generation int64) metav1.Condition {
	var reason string
	var messages []string
	for _, err := range errs {
		if err.Type == conditionType {
			if len(messages) == 0 {
				reason = err.Reason
			}
			if !slices.Contains(messages, err.Message) {
				messages = append(messages, err.Message)
			}
		}
	}
	if len(messages) > 0 {
		return NewCondition(conditionType, metav1.ConditionFalse, reason, joinMessages(messages), generation)
	}

	for _, warning := range warnings {
		if warning.Type == conditionType {
			if len(messages) == 0 {
				reason = warning.Reason
			}
			if !slices.Contains(messages, warning.Message) {
				messages = append(messages, warning.Message)
			}
		}
	}
	if len(messages) > 0 {
		return NewCondition(conditionType, metav1.ConditionTrue, reason, joinMessages(messages), generation)
	}

	return NewCondition(conditionType, metav1.ConditionTrue, trueReason, trueMessage, generation)
}

// joinMessages joins distinct messages with semicolons up to maxJoinedMessages.
// If more messages are present, it summarizes the remaining count.
func joinMessages(messages []string) string {
	const maxJoinedMessages = 5
	if len(messages) <= maxJoinedMessages {
		return strings.Join(messages, "; ")
	}
	return fmt.Sprintf("%s; and %d more", strings.Join(messages[:maxJoinedMessages], "; "), len(messages)-maxJoinedMessages)
}

// buildAcceptedCondition constructs a RouteConditionAccepted condition from collected errors.
func buildAcceptedCondition(errs []*ConditionError, generation int64) metav1.Condition {
	return buildCondition(
		errs,
		nil,
		string(gatewayv1.RouteConditionAccepted),
		string(gatewayv1.RouteReasonAccepted),
		"Route validation succeeded",
		generation,
	)
}

// buildResolvedRefsCondition constructs a RouteConditionResolvedRefs condition from collected errors.
func buildResolvedRefsCondition(errs []*ConditionError, generation int64) metav1.Condition {
	return buildCondition(
		errs,
		nil,
		string(gatewayv1.RouteConditionResolvedRefs),
		string(gatewayv1.RouteReasonResolvedRefs),
		"All references resolved",
		generation,
	)
}

// NewCondition constructs a metav1.Condition with the current transition time.
func NewCondition(condType string, status metav1.ConditionStatus, reason, message string, observedGeneration int64) metav1.Condition {
	return metav1.Condition{
		Type:               condType,
		Status:             status,
		ObservedGeneration: observedGeneration,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	}
}

// SetCondition updates or adds a condition in a slice of conditions.
// It preserves LastTransitionTime if the Status has not changed.
// It returns true if the condition was added or modified.
func SetCondition(conditions *[]metav1.Condition, newCond metav1.Condition) bool {
	if conditions == nil {
		return false
	}
	for i, existing := range *conditions {
		if existing.Type == newCond.Type {
			if existing.Status == newCond.Status {
				newCond.LastTransitionTime = existing.LastTransitionTime
			} else if newCond.LastTransitionTime.IsZero() {
				newCond.LastTransitionTime = metav1.Now()
			}
			if existing.Status == newCond.Status &&
				existing.Reason == newCond.Reason &&
				existing.Message == newCond.Message &&
				existing.ObservedGeneration == newCond.ObservedGeneration {
				return false
			}
			(*conditions)[i] = newCond
			return true
		}
	}
	if newCond.LastTransitionTime.IsZero() {
		newCond.LastTransitionTime = metav1.Now()
	}
	*conditions = append(*conditions, newCond)
	return true
}

// SetConditions updates existing conditions slice with new conditions,
// preserving LastTransitionTime when Status has not changed.
// It returns true if any condition was added, modified, or removed.
func SetConditions(conditions *[]metav1.Condition, newConditions []metav1.Condition) bool {
	if conditions == nil {
		return false
	}
	changed := false
	for _, newCond := range newConditions {
		if SetCondition(conditions, newCond) {
			changed = true
		}
	}
	if len(*conditions) != len(newConditions) {
		filtered := make([]metav1.Condition, 0, len(newConditions))
		for _, nc := range newConditions {
			for _, ec := range *conditions {
				if ec.Type == nc.Type {
					filtered = append(filtered, ec)
					break
				}
			}
		}
		if len(filtered) != len(*conditions) {
			*conditions = filtered
			changed = true
		}
	}
	return changed
}

// GatewayOwnedConditionTypes contains every Gateway condition type that this controller sets.
// When reconciling status, the controller modifies or removes conditions in this set.
// The controller leaves all other condition types intact so that conditions written by other controllers survive.
// Every Gateway condition type produced by the controller must appear in this map.
var GatewayOwnedConditionTypes = map[string]bool{
	string(gatewayv1.GatewayConditionAccepted):                       true,
	string(gatewayv1.GatewayConditionProgrammed):                     true,
	string(gatewayv1.GatewayConditionResolvedRefs):                   true,
	string(gatewayv1.GatewayConditionInsecureFrontendValidationMode): true,
}

// ListenerOwnedConditionTypes contains every Listener condition type that this controller sets.
// When reconciling status, the controller modifies or removes conditions in this set.
// The controller leaves all other condition types intact so that conditions written by other controllers survive.
// Every Listener condition type produced by the controller must appear in this map.
var ListenerOwnedConditionTypes = map[string]bool{
	string(gatewayv1.ListenerConditionAccepted):             true,
	string(gatewayv1.ListenerConditionProgrammed):           true,
	string(gatewayv1.ListenerConditionResolvedRefs):         true,
	string(gatewayv1.ListenerConditionConflicted):           true,
	string(gatewayv1.ListenerConditionOverlappingTLSConfig): true,
}

// MergeConditions updates existing conditions slice with desired conditions,
// preserving LastTransitionTime when Status has not changed.
// It only updates or removes conditions of types that are owned (present in ownedTypes or desired).
// Any conditions of unowned (foreign) types already present in existing are preserved unmodified.
// It returns true if any condition was added, modified, or removed.
func MergeConditions(conditions *[]metav1.Condition, desired []metav1.Condition, ownedTypes map[string]bool) bool {
	if conditions == nil {
		return false
	}

	isOwned := func(condType string) bool {
		if ownedTypes != nil && ownedTypes[condType] {
			return true
		}
		for _, d := range desired {
			if d.Type == condType {
				return true
			}
		}
		return false
	}

	changed := false
	desiredMatched := make([]bool, len(desired))

	newConditions := make([]metav1.Condition, 0, len(*conditions)+len(desired))
	for _, ec := range *conditions {
		desiredIdx := -1
		for j, dc := range desired {
			if !desiredMatched[j] && dc.Type == ec.Type {
				desiredIdx = j
				break
			}
		}

		if desiredIdx >= 0 {
			desiredMatched[desiredIdx] = true
			dc := desired[desiredIdx]
			if ec.Status == dc.Status {
				dc.LastTransitionTime = ec.LastTransitionTime
			} else if dc.LastTransitionTime.IsZero() {
				dc.LastTransitionTime = metav1.Now()
			}
			if ec.Status != dc.Status ||
				ec.Reason != dc.Reason ||
				ec.Message != dc.Message ||
				ec.ObservedGeneration != dc.ObservedGeneration {
				changed = true
			}
			newConditions = append(newConditions, dc)
		} else {
			if isOwned(ec.Type) {
				changed = true
			} else {
				newConditions = append(newConditions, ec)
			}
		}
	}

	for j, dc := range desired {
		if !desiredMatched[j] {
			if dc.LastTransitionTime.IsZero() {
				dc.LastTransitionTime = metav1.Now()
			}
			newConditions = append(newConditions, dc)
			changed = true
		}
	}

	if changed {
		*conditions = newConditions
	}
	return changed
}

// FindCondition searches a slice of conditions for a condition with the specified type.
func FindCondition(conditions []metav1.Condition, condType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}

// ConditionsEqual compares two condition slices for equality (ignoring LastTransitionTime).
func ConditionsEqual(a, b []metav1.Condition) bool {
	if len(a) != len(b) {
		return false
	}
	for _, cA := range a {
		found := false
		for _, cB := range b {
			if cA.Type == cB.Type {
				if cA.Status == cB.Status &&
					cA.ObservedGeneration == cB.ObservedGeneration &&
					cA.Reason == cB.Reason &&
					cA.Message == cB.Message {
					found = true
					break
				}
				return false
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func normalizeGroup(g *gatewayv1.Group) string {
	val := ValueOf(g)
	if val == "" || val == gatewayv1.GroupName {
		return gatewayv1.GroupName
	}
	return string(val)
}

func normalizeKind(k *gatewayv1.Kind) string {
	val := ValueOf(k)
	if val == "" || val == "Gateway" {
		return "Gateway"
	}
	return string(val)
}

// CompareParentReference compares two ParentReferences for deterministic sorting.
// It normalizes group and kind (defaulting nil/empty to the Gateway API standard group and Gateway kind),
// and defaults unset namespace to defaultNamespace (typically the route's namespace).
// The comparison order is: Group, Kind, Namespace, Name, SectionName, Port.
func CompareParentReference(a, b gatewayv1.ParentReference, defaultNamespace string) int {
	if c := cmp.Compare(normalizeGroup(a.Group), normalizeGroup(b.Group)); c != 0 {
		return c
	}
	if c := cmp.Compare(normalizeKind(a.Kind), normalizeKind(b.Kind)); c != 0 {
		return c
	}
	nsA := defaultNamespace
	if a.Namespace != nil && *a.Namespace != "" {
		nsA = string(*a.Namespace)
	}
	nsB := defaultNamespace
	if b.Namespace != nil && *b.Namespace != "" {
		nsB = string(*b.Namespace)
	}
	if c := cmp.Compare(nsA, nsB); c != 0 {
		return c
	}
	if c := cmp.Compare(string(a.Name), string(b.Name)); c != 0 {
		return c
	}
	secA := string(ValueOf(a.SectionName))
	secB := string(ValueOf(b.SectionName))
	if c := cmp.Compare(secA, secB); c != 0 {
		return c
	}
	portA := int32(ValueOf(a.Port))
	portB := int32(ValueOf(b.Port))
	return cmp.Compare(portA, portB)
}

// CompareRouteParentStatus compares two RouteParentStatus entries for deterministic sorting.
// It compares ControllerName first, then normalized ParentReference.
func CompareRouteParentStatus(a, b gatewayv1.RouteParentStatus, defaultNamespace string) int {
	if c := cmp.Compare(string(a.ControllerName), string(b.ControllerName)); c != 0 {
		return c
	}
	return CompareParentReference(a.ParentRef, b.ParentRef, defaultNamespace)
}

// SortRouteParentStatuses sorts a slice of RouteParentStatus entries deterministically.
func SortRouteParentStatuses(parents []gatewayv1.RouteParentStatus, defaultNamespace string) {
	slices.SortStableFunc(parents, func(a, b gatewayv1.RouteParentStatus) int {
		return CompareRouteParentStatus(a, b, defaultNamespace)
	})
}

func reflectParentReferenceEqual(a, b gatewayv1.ParentReference, defaultNamespace ...string) bool {
	ns := ""
	if len(defaultNamespace) > 0 {
		ns = defaultNamespace[0]
	}
	return CompareParentReference(a, b, ns) == 0
}

// UpdateRouteParentStatuses updates an existing slice of RouteParentStatus with desired statuses,
// preserving LastTransitionTime for conditions whose Status has not changed.
// Entries belonging to our managed controller are sorted deterministically by normalized ParentRef.
// Entries belonging to other controllers are preserved in their existing relative order, after our entries.
// If the only difference between existing and desired statuses is order, updated returns false.
// It returns the updated slice and a boolean indicating whether any semantic changes occurred.
func UpdateRouteParentStatuses(
	existing []gatewayv1.RouteParentStatus,
	desired []gatewayv1.RouteParentStatus,
	routeNamespace string,
	controllerName gatewayv1.GatewayController,
) ([]gatewayv1.RouteParentStatus, bool) {
	updated := false

	var ourEntries []gatewayv1.RouteParentStatus

	for _, d := range desired {
		entry := gatewayv1.RouteParentStatus{
			ParentRef:      d.ParentRef,
			ControllerName: d.ControllerName,
			Conditions:     make([]metav1.Condition, len(d.Conditions)),
		}
		if entry.ControllerName == "" && controllerName != "" {
			entry.ControllerName = controllerName
		}
		copy(entry.Conditions, d.Conditions)

		// Find matching existing parent status
		var matchingExisting *gatewayv1.RouteParentStatus
		for j := range existing {
			if existing[j].ControllerName == entry.ControllerName && reflectParentReferenceEqual(existing[j].ParentRef, entry.ParentRef, routeNamespace) {
				matchingExisting = &existing[j]
				break
			}
		}

		if matchingExisting == nil {
			updated = true
			for k := range entry.Conditions {
				if entry.Conditions[k].LastTransitionTime.IsZero() {
					entry.Conditions[k].LastTransitionTime = metav1.Now()
				}
			}
		} else {
			if len(matchingExisting.Conditions) != len(entry.Conditions) {
				updated = true
			}
			for k, dc := range entry.Conditions {
				found := false
				for _, ec := range matchingExisting.Conditions {
					if ec.Type == dc.Type {
						found = true
						if ec.Status == dc.Status {
							entry.Conditions[k].LastTransitionTime = ec.LastTransitionTime
						} else {
							updated = true
							if entry.Conditions[k].LastTransitionTime.IsZero() {
								entry.Conditions[k].LastTransitionTime = metav1.Now()
							}
						}
						if ec.Status != dc.Status || ec.Reason != dc.Reason || ec.Message != dc.Message || ec.ObservedGeneration != dc.ObservedGeneration {
							updated = true
						}
						break
					}
				}
				if !found {
					updated = true
					if entry.Conditions[k].LastTransitionTime.IsZero() {
						entry.Conditions[k].LastTransitionTime = metav1.Now()
					}
				}
			}
		}

		ourEntries = append(ourEntries, entry)
	}

	// Sort our own entries deterministically
	SortRouteParentStatuses(ourEntries, routeNamespace)

	// Check for existing entries: preserve entries from unmanaged controllers in their relative order,
	// and detect removals of entries from managed controller(s).
	var otherEntries []gatewayv1.RouteParentStatus
	for _, e := range existing {
		if controllerName != "" && e.ControllerName == controllerName {
			found := false
			for _, d := range desired {
				dCtrl := d.ControllerName
				if dCtrl == "" {
					dCtrl = controllerName
				}
				if dCtrl == e.ControllerName && reflectParentReferenceEqual(d.ParentRef, e.ParentRef, routeNamespace) {
					found = true
					break
				}
			}
			if !found {
				updated = true
			}
		} else if controllerName == "" {
			isManaged := false
			for _, d := range desired {
				if d.ControllerName == e.ControllerName {
					isManaged = true
					break
				}
			}
			if isManaged {
				found := false
				for _, d := range desired {
					if d.ControllerName == e.ControllerName && reflectParentReferenceEqual(d.ParentRef, e.ParentRef, routeNamespace) {
						found = true
						break
					}
				}
				if !found {
					updated = true
				}
			} else {
				otherEntries = append(otherEntries, e)
			}
		} else {
			otherEntries = append(otherEntries, e)
		}
	}

	if len(existing) != len(ourEntries)+len(otherEntries) {
		updated = true
	}

	result := append(ourEntries, otherEntries...)
	return result, updated
}

// UpdatePolicyAncestors updates an existing slice of PolicyAncestorStatus with desired statuses,
// preserving LastTransitionTime for conditions whose Status has not changed.
// Entries belonging to other controllers are preserved.
func UpdatePolicyAncestors(
	existing []gatewayv1.PolicyAncestorStatus,
	desired []gatewayv1.PolicyAncestorStatus,
	controllerName gatewayv1.GatewayController,
) ([]gatewayv1.PolicyAncestorStatus, bool) {
	updated := false
	var result []gatewayv1.PolicyAncestorStatus

	for _, d := range desired {
		entry := gatewayv1.PolicyAncestorStatus{
			AncestorRef:    d.AncestorRef,
			ControllerName: d.ControllerName,
			Conditions:     make([]metav1.Condition, len(d.Conditions)),
		}
		if entry.ControllerName == "" && controllerName != "" {
			entry.ControllerName = controllerName
		}
		copy(entry.Conditions, d.Conditions)

		var matchingExisting *gatewayv1.PolicyAncestorStatus
		for j := range existing {
			if existing[j].ControllerName == d.ControllerName && reflectParentReferenceEqual(existing[j].AncestorRef, d.AncestorRef) {
				matchingExisting = &existing[j]
				break
			}
		}

		if matchingExisting == nil {
			updated = true
			for k := range entry.Conditions {
				if entry.Conditions[k].LastTransitionTime.IsZero() {
					entry.Conditions[k].LastTransitionTime = metav1.Now()
				}
			}
		} else {
			if len(matchingExisting.Conditions) != len(d.Conditions) {
				updated = true
			}
			for k, dc := range d.Conditions {
				found := false
				for _, ec := range matchingExisting.Conditions {
					if ec.Type == dc.Type {
						found = true
						if ec.Status == dc.Status {
							entry.Conditions[k].LastTransitionTime = ec.LastTransitionTime
						} else {
							updated = true
							if entry.Conditions[k].LastTransitionTime.IsZero() {
								entry.Conditions[k].LastTransitionTime = metav1.Now()
							}
						}
						if ec.Status != dc.Status || ec.Reason != dc.Reason || ec.Message != dc.Message || ec.ObservedGeneration != dc.ObservedGeneration {
							updated = true
						}
						break
					}
				}
				if !found {
					updated = true
					if entry.Conditions[k].LastTransitionTime.IsZero() {
						entry.Conditions[k].LastTransitionTime = metav1.Now()
					}
				}
			}
		}
		result = append(result, entry)
	}

	for _, e := range existing {
		if controllerName != "" && e.ControllerName == controllerName {
			found := false
			for _, d := range desired {
				if d.ControllerName == e.ControllerName && reflectParentReferenceEqual(d.AncestorRef, e.AncestorRef) {
					found = true
					break
				}
			}
			if !found {
				updated = true
			}
		} else if controllerName == "" {
			isManaged := false
			for _, d := range desired {
				if d.ControllerName == e.ControllerName {
					isManaged = true
					break
				}
			}
			if isManaged {
				found := false
				for _, d := range desired {
					if d.ControllerName == e.ControllerName && reflectParentReferenceEqual(d.AncestorRef, e.AncestorRef) {
						found = true
						break
					}
				}
				if !found {
					updated = true
				}
			} else {
				result = append(result, e)
			}
		} else {
			result = append(result, e)
		}
	}

	if len(existing) != len(result) {
		updated = true
	}

	return result, updated
}
