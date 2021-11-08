package encryptedssm

import (
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/ssm"
	awsbase "github.com/hashicorp/aws-sdk-go-base"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/logging"
	"github.com/terraform-providers/terraform-provider-aws/version"
)

type Config struct {
	AccessKey     string
	SecretKey     string
	CredsFilename string
	Profile       string
	Token         string
	Region        string
	MaxRetries    int

	AssumeRoleARN               string
	AssumeRoleDurationSeconds   int
	AssumeRoleExternalID        string
	AssumeRolePolicy            string
	AssumeRolePolicyARNs        []string
	AssumeRoleSessionName       string
	AssumeRoleTags              map[string]string
	AssumeRoleTransitiveTagKeys []string

	AllowedAccountIds   []string
	ForbiddenAccountIds []string

	Endpoints map[string]string
	Insecure  bool

	SkipCredsValidation  bool
	SkipRegionValidation bool

	terraformVersion string
}

type AWSClient struct {
	ssmconn          *ssm.SSM
	kmsconn          *kms.KMS
	IgnoreTagsConfig *IgnoreConfig
}

// TagData represents the data associated with a resource tag key.
// Almost exclusively for AWS services, this is just a tag value,
// however there are services that attach additional data to tags.
// An example is autoscaling with the PropagateAtLaunch field.
type TagData struct {
	// Additional boolean field names and values associated with this tag.
	// Each service is responsible for properly handling this data.
	AdditionalBoolFields map[string]*bool

	// Additional string field names and values associated with this tag.
	// Each service is responsible for properly handling this data.
	AdditionalStringFields map[string]*string

	// Tag value.
	Value *string
}

type KeyValueTags map[string]*TagData

// IgnoreConfig contains various options for removing resource tags.
type IgnoreConfig struct {
	Keys        KeyValueTags
	KeyPrefixes KeyValueTags
}

// Client configures and returns a fully initialized AWSClient
func (c *Config) Client() (interface{}, error) {
	// Get the auth and region. This can fail if keys/regions were not
	// specified and we're attempting to use the environment.
	if !c.SkipRegionValidation {
		if err := awsbase.ValidateRegion(c.Region); err != nil {
			return nil, err
		}
	}

	awsbaseConfig := &awsbase.Config{
		AccessKey:                   c.AccessKey,
		AssumeRoleARN:               c.AssumeRoleARN,
		AssumeRoleDurationSeconds:   c.AssumeRoleDurationSeconds,
		AssumeRoleExternalID:        c.AssumeRoleExternalID,
		AssumeRolePolicy:            c.AssumeRolePolicy,
		AssumeRolePolicyARNs:        c.AssumeRolePolicyARNs,
		AssumeRoleSessionName:       c.AssumeRoleSessionName,
		AssumeRoleTags:              c.AssumeRoleTags,
		AssumeRoleTransitiveTagKeys: c.AssumeRoleTransitiveTagKeys,
		CallerDocumentationURL:      "https://registry.terraform.io/providers/hashicorp/aws",
		CallerName:                  "Terraform encryptedssm Provider",
		CredsFilename:               c.CredsFilename,
		DebugLogging:                logging.IsDebugOrHigher(),
		MaxRetries:                  c.MaxRetries,
		Profile:                     c.Profile,
		Region:                      c.Region,
		SecretKey:                   c.SecretKey,
		Token:                       c.Token,
		UserAgentProducts: []*awsbase.UserAgentProduct{
			{Name: "APN", Version: "1.0"},
			{Name: "HashiCorp", Version: "1.0"},
			{Name: "Terraform", Version: c.terraformVersion, Extra: []string{"+https://www.terraform.io"}},
			// TODO: change this
			{Name: "terraform-provider-encryptedssm", Version: version.ProviderVersion, Extra: []string{"+https://registry.terraform.io/providers/hashicorp/aws"}},
		},
	}

	sess, accountID, _, err := awsbase.GetSessionWithAccountIDAndPartition(awsbaseConfig)
	if err != nil {
		return nil, fmt.Errorf("error configuring Terraform AWS Provider: %w", err)
	}

	if accountID == "" {
		log.Printf("[WARN] AWS account ID not found for provider. See https://www.terraform.io/docs/providers/aws/index.html#skip_requesting_account_id for implications.")
	}

	if err := awsbase.ValidateAccountID(accountID, c.AllowedAccountIds, c.ForbiddenAccountIds); err != nil {
		return nil, err
	}

	client := &AWSClient{
		ssmconn: ssm.New(sess.Copy(&aws.Config{Endpoint: aws.String(c.Endpoints["ssm"])})),
		kmsconn: kms.New(sess.Copy(&aws.Config{Endpoint: aws.String(c.Endpoints["kms"])})),
	}

	return client, nil
}
