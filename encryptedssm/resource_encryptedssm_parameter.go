package encryptedssm

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/customdiff"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

const (
	// Maximum amount of time to wait for asynchronous validation on SSM Parameter creation.
	ssmParameterCreationValidationTimeout = 2 * time.Minute
)

func resourceAwsSsmParameter() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsSsmParameterPut,
		Read:   resourceAwsSsmParameterRead,
		Update: resourceAwsSsmParameterPut,
		Delete: resourceAwsSsmParameterDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"tier": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  ssm.ParameterTierStandard,
				ValidateFunc: validation.StringInSlice([]string{
					ssm.ParameterTierStandard,
					ssm.ParameterTierAdvanced,
				}, false),
			},
			"type": {
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: validation.StringInSlice([]string{
					ssm.ParameterTypeSecureString,
				}, false),
			},
			"encrypted_value": {
				Type:      schema.TypeString,
				Required:  true,
				Sensitive: false,
			},
			"encryption_key": {
				Type:      schema.TypeString,
				Required:  true,
				Sensitive: false,
			},
			"arn": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"data_type": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				ValidateFunc: validation.StringInSlice([]string{
					"aws:ec2:image",
					"text",
				}, false),
			},
			"overwrite": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"allowed_pattern": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"version": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"tags": tagsSchema(),
		},

		CustomizeDiff: customdiff.All(
			// Prevent the following error during tier update from Advanced to Standard:
			// ValidationException: This parameter uses the advanced-parameter tier. You can't downgrade a parameter from the advanced-parameter tier to the standard-parameter tier. If necessary, you can delete the advanced parameter and recreate it as a standard parameter.
			customdiff.ForceNewIfChange("tier", func(_ context.Context, old, new, meta interface{}) bool {
				return old.(string) == ssm.ParameterTierAdvanced && new.(string) == ssm.ParameterTierStandard
			}),
		),
	}
}

func resourceAwsSsmParameterRead(d *schema.ResourceData, meta interface{}) error {
	ssmconn := meta.(*AWSClient).ssmconn
	ignoreTagsConfig := meta.(*AWSClient).IgnoreTagsConfig

	log.Printf("[DEBUG] Reading SSM Parameter: %s", d.Id())

	input := &ssm.GetParameterInput{
		Name:           aws.String(d.Id()),
		WithDecryption: aws.Bool(true),
	}

	var resp *ssm.GetParameterOutput
	err := resource.Retry(ssmParameterCreationValidationTimeout, func() *resource.RetryError {
		var err error
		resp, err = ssmconn.GetParameter(input)

		if isAWSErr(err, ssm.ErrCodeParameterNotFound, "") && d.IsNewResource() && d.Get("data_type").(string) == "aws:ec2:image" {
			return resource.RetryableError(fmt.Errorf("error reading SSM Parameter (%s) after creation: this can indicate that the provided parameter value could not be validated by SSM", d.Id()))
		}

		if err != nil {
			return resource.NonRetryableError(err)
		}

		return nil
	})

	if isResourceTimeoutError(err) {
		resp, err = ssmconn.GetParameter(input)
	}

	if isAWSErr(err, ssm.ErrCodeParameterNotFound, "") && !d.IsNewResource() {
		log.Printf("[WARN] SSM Parameter (%s) not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	if err != nil {
		return fmt.Errorf("error reading SSM Parameter (%s): %w", d.Id(), err)
	}

	param := resp.Parameter
	name := *param.Name
	encValue := *param.Value

	base64Blob, err := base64.StdEncoding.DecodeString(d.Get("encrypted_value").(string))
	if err != nil {
		return err
	}

	decryptinput := &kms.DecryptInput{
		KeyId:          aws.String(d.Get("encryption_key").(string)),
		CiphertextBlob: base64Blob,
	}

	result, err := kmsDecrypt(decryptinput, meta)
	if err != nil {
		return fmt.Errorf("Error decrypting with KMS: %s", err)
	}

	var encrypted_value string
	if string(result.Plaintext) == string(encValue) {
		encrypted_value = d.Get("encrypted_value").(string)
	} else {
		encrypted_value = "Outdated sensitive value"
	}

	d.Set("name", name)
	d.Set("type", param.Type)
	d.Set("encrypted_value", encrypted_value)
	d.Set("version", param.Version)

	describeParamsInput := &ssm.DescribeParametersInput{
		ParameterFilters: []*ssm.ParameterStringFilter{
			{
				Key:    aws.String("Name"),
				Option: aws.String("Equals"),
				Values: []*string{aws.String(name)},
			},
		},
	}
	describeResp, err := ssmconn.DescribeParameters(describeParamsInput)
	if err != nil {
		return fmt.Errorf("error describing SSM parameter: %s", err)
	}

	if describeResp == nil || len(describeResp.Parameters) == 0 || describeResp.Parameters[0] == nil {
		log.Printf("[WARN] SSM Parameter %q not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	detail := describeResp.Parameters[0]
	d.Set("key_id", detail.KeyId)
	d.Set("description", detail.Description)
	d.Set("tier", ssm.ParameterTierStandard)
	if detail.Tier != nil {
		d.Set("tier", detail.Tier)
	}
	d.Set("allowed_pattern", detail.AllowedPattern)
	d.Set("data_type", detail.DataType)

	tags, err := SsmListTags(ssmconn, name, ssm.ResourceTypeForTaggingParameter)

	if err != nil {
		return fmt.Errorf("error listing tags for SSM Parameter (%s): %s", name, err)
	}

	if err := d.Set("tags", tags.IgnoreAws().IgnoreConfig(ignoreTagsConfig).Map()); err != nil {
		return fmt.Errorf("error setting tags: %s", err)
	}

	d.Set("arn", param.ARN)

	return nil
}

func resourceAwsSsmParameterDelete(d *schema.ResourceData, meta interface{}) error {
	ssmconn := meta.(*AWSClient).ssmconn

	log.Printf("[INFO] Deleting SSM Parameter: %s", d.Id())

	_, err := ssmconn.DeleteParameter(&ssm.DeleteParameterInput{
		Name: aws.String(d.Get("name").(string)),
	})
	if err != nil {
		return fmt.Errorf("error deleting SSM Parameter (%s): %s", d.Id(), err)
	}

	return nil
}

func resourceAwsSsmParameterPut(d *schema.ResourceData, meta interface{}) error {
	ssmconn := meta.(*AWSClient).ssmconn

	log.Printf("[INFO] Creating SSM Parameter: %s", d.Get("name").(string))

	base64Blob, err := base64.StdEncoding.DecodeString(d.Get("encrypted_value").(string))
	if err != nil {
		return err
	}

	input := &kms.DecryptInput{
		KeyId:          aws.String(d.Get("encryption_key").(string)),
		CiphertextBlob: base64Blob,
	}

	result, err := kmsDecrypt(input, meta)
	if err != nil {
		return fmt.Errorf("Error decrypting with KMS: %s", err)
	}

	paramInput := &ssm.PutParameterInput{
		Name:           aws.String(d.Get("name").(string)),
		Type:           aws.String(d.Get("type").(string)),
		Tier:           aws.String(d.Get("tier").(string)),
		Value:          aws.String(string(result.Plaintext)),
		Overwrite:      aws.Bool(shouldUpdateSsmParameter(d)),
		AllowedPattern: aws.String(d.Get("allowed_pattern").(string)),
	}

	if v, ok := d.GetOk("data_type"); ok {
		paramInput.DataType = aws.String(v.(string))
	}

	if d.HasChange("description") {
		_, n := d.GetChange("description")
		paramInput.Description = aws.String(n.(string))
	}

	paramInput.SetKeyId(d.Get("encryption_key").(string))

	log.Printf("[DEBUG] Waiting for SSM Parameter %v to be updated", d.Get("name"))
	_, err = ssmconn.PutParameter(paramInput)

	if isAWSErr(err, "ValidationException", "Tier is not supported") {
		paramInput.Tier = nil
		_, err = ssmconn.PutParameter(paramInput)
	}

	if err != nil {
		return fmt.Errorf("error creating SSM parameter: %s", err)
	}

	name := d.Get("name").(string)
	if d.HasChange("tags") {
		o, n := d.GetChange("tags")

		if err := SsmUpdateTags(ssmconn, name, ssm.ResourceTypeForTaggingParameter, o, n); err != nil {
			return fmt.Errorf("error updating SSM Parameter (%s) tags: %s", name, err)
		}
	}

	d.SetId(d.Get("name").(string))

	return resourceAwsSsmParameterRead(d, meta)
}

func kmsDecrypt(decryptInput *kms.DecryptInput, meta interface{}) (*kms.DecryptOutput, error) {
	kmsconn := meta.(*AWSClient).kmsconn
	result, err := kmsconn.Decrypt(decryptInput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return result, errors.New(aerr.Error())
		} else {
			return result, errors.New(err.Error())
		}

	}
	return result, nil
}
