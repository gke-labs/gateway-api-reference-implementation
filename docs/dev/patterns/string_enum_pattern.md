# String Enum Pattern

In this project, we follow the "string enum" pattern, which is widely used in Kubernetes and other Go projects. This pattern provides type safety for a set of predefined string values while remaining compatible with standard Go strings.

## Pattern definition

To define a string enum, create a new type based on `string` and define constants for the valid values:

```go
type PathMatchType string

const (
	PathMatchTypeExact      PathMatchType = "Exact"
	PathMatchTypePathPrefix PathMatchType = "PathPrefix"
	PathMatchTypeNone       PathMatchType = "None"
)
```

## Advantages

1.  **Type Safety**: Functions can accept the specific type (e.g., `PathMatchType`) instead of a generic `string`, preventing invalid values from being passed.
2.  **Readability**: Constants make the code easier to read and maintain.
3.  **Extensibility**: You can define methods on the enum type.

## Example with Methods

You can add behavior to the enum by defining methods:

```go
func (t PathMatchType) Weight() int {
	switch t {
	case PathMatchTypeExact:
		return 3
	case PathMatchTypePathPrefix:
		return 2
	case PathMatchTypeNone:
		return 1
	default:
		return 0
	}
}
```

This is particularly useful for implementing logic like match precedence.
