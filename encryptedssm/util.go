package encryptedssm

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/hashicorp/aws-sdk-go-base/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const (
	AwsTagKeyPrefix = `aws:`
)

// IgnoreAws returns non-AWS tag keys.
func (tags KeyValueTags) IgnoreAws() KeyValueTags {
	result := make(KeyValueTags)

	for k, v := range tags {
		if !strings.HasPrefix(k, AwsTagKeyPrefix) {
			result[k] = v
		}
	}

	return result
}

// IgnoreConfig returns any tags not removed by a given configuration.
func (tags KeyValueTags) IgnoreConfig(config *IgnoreConfig) KeyValueTags {
	if config == nil {
		return tags
	}

	result := tags.IgnorePrefixes(config.KeyPrefixes)
	result = result.Ignore(config.Keys)

	return result
}

// IgnorePrefixes returns non-matching tag key prefixes.
func (tags KeyValueTags) IgnorePrefixes(ignoreTagPrefixes KeyValueTags) KeyValueTags {
	result := make(KeyValueTags)

	for k, v := range tags {
		var ignore bool

		for ignoreTagPrefix := range ignoreTagPrefixes {
			if strings.HasPrefix(k, ignoreTagPrefix) {
				ignore = true
				break
			}
		}

		if ignore {
			continue
		}

		result[k] = v
	}

	return result
}

// Map returns tag keys mapped to their values.
func (tags KeyValueTags) Map() map[string]string {
	result := make(map[string]string, len(tags))

	for k, v := range tags {
		if v == nil || v.Value == nil {
			result[k] = ""
			continue
		}

		result[k] = *v.Value
	}

	return result
}

// Ignore returns non-matching tag keys.
func (tags KeyValueTags) Ignore(ignoreTags KeyValueTags) KeyValueTags {
	result := make(KeyValueTags)

	for k, v := range tags {
		if _, ok := ignoreTags[k]; ok {
			continue
		}

		result[k] = v
	}

	return result
}

// SsmListTags lists ssm service tags.
// The identifier is typically the Amazon Resource Name (ARN), although
// it may also be a different identifier depending on the service.
func SsmListTags(conn *ssm.SSM, identifier string, resourceType string) (KeyValueTags, error) {
	input := &ssm.ListTagsForResourceInput{
		ResourceId:   aws.String(identifier),
		ResourceType: aws.String(resourceType),
	}

	output, err := conn.ListTagsForResource(input)

	if err != nil {
		return New(nil), err
	}

	return SsmKeyValueTags(output.TagList), nil
}

// SsmKeyValueTags creates KeyValueTags from ssm service tags.
func SsmKeyValueTags(tags []*ssm.Tag) KeyValueTags {
	m := make(map[string]*string, len(tags))

	for _, tag := range tags {
		m[aws.StringValue(tag.Key)] = tag.Value
	}

	return New(m)
}

// New creates KeyValueTags from common Terraform Provider SDK types.
// Supports map[string]string, map[string]*string, map[string]interface{}, and []interface{}.
// When passed []interface{}, all elements are treated as keys and assigned nil values.
func New(i interface{}) KeyValueTags {
	switch value := i.(type) {
	case map[string]*TagData:
		kvtm := make(KeyValueTags, len(value))

		for k, v := range value {
			tagData := v
			kvtm[k] = tagData
		}

		return kvtm
	case map[string]string:
		kvtm := make(KeyValueTags, len(value))

		for k, v := range value {
			str := v // Prevent referencing issues
			kvtm[k] = &TagData{Value: &str}
		}

		return kvtm
	case map[string]*string:
		kvtm := make(KeyValueTags, len(value))

		for k, v := range value {
			strPtr := v

			if strPtr == nil {
				kvtm[k] = nil
				continue
			}

			kvtm[k] = &TagData{Value: strPtr}
		}

		return kvtm
	case map[string]interface{}:
		kvtm := make(KeyValueTags, len(value))

		for k, v := range value {
			str := v.(string)
			kvtm[k] = &TagData{Value: &str}
		}

		return kvtm
	case []string:
		kvtm := make(KeyValueTags, len(value))

		for _, v := range value {
			kvtm[v] = nil
		}

		return kvtm
	case []interface{}:
		kvtm := make(KeyValueTags, len(value))

		for _, v := range value {
			kvtm[v.(string)] = nil
		}

		return kvtm
	default:
		return make(KeyValueTags)
	}
}

// SsmUpdateTags updates ssm service tags.
// The identifier is typically the Amazon Resource Name (ARN), although
// it may also be a different identifier depending on the service.
func SsmUpdateTags(conn *ssm.SSM, identifier string, resourceType string, oldTagsMap interface{}, newTagsMap interface{}) error {
	oldTags := New(oldTagsMap)
	newTags := New(newTagsMap)

	if removedTags := oldTags.Removed(newTags); len(removedTags) > 0 {
		input := &ssm.RemoveTagsFromResourceInput{
			ResourceId:   aws.String(identifier),
			ResourceType: aws.String(resourceType),
			TagKeys:      aws.StringSlice(removedTags.IgnoreAws().Keys()),
		}

		_, err := conn.RemoveTagsFromResource(input)

		if err != nil {
			return fmt.Errorf("error untagging resource (%s): %w", identifier, err)
		}
	}

	if updatedTags := oldTags.Updated(newTags); len(updatedTags) > 0 {
		input := &ssm.AddTagsToResourceInput{
			ResourceId:   aws.String(identifier),
			ResourceType: aws.String(resourceType),
			Tags:         updatedTags.IgnoreAws().SsmTags(),
		}

		_, err := conn.AddTagsToResource(input)

		if err != nil {
			return fmt.Errorf("error tagging resource (%s): %w", identifier, err)
		}
	}

	return nil
}

// Keys returns tag keys.
func (tags KeyValueTags) Keys() []string {
	result := make([]string, 0, len(tags))

	for k := range tags {
		result = append(result, k)
	}

	return result
}

// SsmTags returns ssm service tags.
func (tags KeyValueTags) SsmTags() []*ssm.Tag {
	result := make([]*ssm.Tag, 0, len(tags))

	for k, v := range tags.Map() {
		tag := &ssm.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		}

		result = append(result, tag)
	}

	return result
}

// Removed returns tags removed.
func (tags KeyValueTags) Removed(newTags KeyValueTags) KeyValueTags {
	result := make(KeyValueTags)

	for k, v := range tags {
		if _, ok := newTags[k]; !ok {
			result[k] = v
		}
	}

	return result
}

// Updated returns tags added and updated.
func (tags KeyValueTags) Updated(newTags KeyValueTags) KeyValueTags {
	result := make(KeyValueTags)

	for k, newV := range newTags {
		if oldV, ok := tags[k]; !ok || !oldV.Equal(newV) {
			result[k] = newV
		}
	}

	return result
}

func (td *TagData) Equal(other *TagData) bool {
	if td == nil && other == nil {
		return true
	}

	if td == nil || other == nil {
		return false
	}

	if !reflect.DeepEqual(td.AdditionalBoolFields, other.AdditionalBoolFields) {
		return false
	}

	if !reflect.DeepEqual(td.AdditionalStringFields, other.AdditionalStringFields) {
		return false
	}

	if !reflect.DeepEqual(td.Value, other.Value) {
		return false
	}

	return true
}

func shouldUpdateSsmParameter(d *schema.ResourceData) bool {
	// If the user has specified a preference, return their preference
	if value, ok := d.GetOkExists("overwrite"); ok {
		return value.(bool)
	}

	// Since the user has not specified a preference, obey lifecycle rules
	// if it is not a new resource, otherwise overwrite should be set to false.
	return !d.IsNewResource()
}

// Returns true if the error matches all these conditions:
//  * err is of type awserr.Error
//  * Error.Code() matches code
//  * Error.Message() contains message
func isAWSErr(err error, code string, message string) bool {
	return tfawserr.ErrMessageContains(err, code, message)
}

func isResourceTimeoutError(err error) bool {
	timeoutErr, ok := err.(*resource.TimeoutError)
	return ok && timeoutErr.LastError == nil
}

// tagsSchema returns the schema to use for tags.
//
func tagsSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeMap,
		Optional: true,
		Elem:     &schema.Schema{Type: schema.TypeString},
	}
}
