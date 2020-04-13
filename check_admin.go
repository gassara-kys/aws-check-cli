package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"reflect"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/urfave/cli"
)

const (
	managedAdminArn   = "arn:aws:iam::aws:policy/AdministratorAccess"
	managedIAMFullArn = "arn:aws:iam::aws:policy/IAMFullAccess"
	iamAllAction      = "iam:*"
	allAction         = "*"
	allResouce        = "*"
)

func init() {
	cmdList = append(cmdList, cli.Command{
		Name:  "check-admin",
		Usage: "check for IAM-USER that may have administrator access",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:   "assume-role-arn",
				Usage:  "if set this option, try assume role and check IAM",
				EnvVar: "ASSUME_ROLE_ARN",
			},
			cli.BoolFlag{
				Name:   "admin-only",
				Usage:  "if set this option true, show admin only users.",
				EnvVar: "ADMIN_ONLY",
			},
		},
		Action: func(c *cli.Context) error {
			return action(c, &iamCheck{Out: os.Stdout})
		},
	})
}

type iamCheck struct {
	Out  io.Writer
	Sess *session.Session
	Svc  *iam.IAM
}

type adminUser struct {
	UserArn                  string `json:"user_arn"`
	HasUserAdmin             bool   `json:"has_user_admin"`
	HasGroupAdmin            bool   `json:"has_grorup_admin"`
	EnablePermissionBoundory bool   `json:"enable_permission_boundory"`
}

func (i *iamCheck) Run(c *cli.Context, region string) error {
	return i.Main(region, c.String("assume-role-arn"), c.Bool("admin-only"))
}

func (i *iamCheck) Main(region, assumeRole string, adminOnly bool) error {
	if err := i.newAWSSession(region, assumeRole); err != nil {
		return err
	}
	result, err := i.Svc.ListUsers(&iam.ListUsersInput{
		MaxItems: aws.Int64(10),
	})
	if err != nil {
		return err
	}

	var adminUsers []adminUser
	for _, user := range result.Users {
		if user == nil {
			continue
		}
		admin := adminUser{
			UserArn: *user.Arn,
		}

		// Permission Boundory
		if enabled, err := i.enablePermissionBoundory(*user.UserName); err != nil {
			return err
		} else {
			admin.EnablePermissionBoundory = enabled
		}
		// User attached policy
		if has, err := i.hasUserAdmin(*user.UserName); err != nil {
			return err
		} else if has {
			admin.HasUserAdmin = true
		}
		// Group attached policy
		if has, err := i.hasGroupAdmin(*user.UserName); err != nil {
			return err
		} else if has {
			admin.HasGroupAdmin = true
		}
		if !adminOnly {
			adminUsers = append(adminUsers, admin)
		} else if admin.HasUserAdmin || admin.HasGroupAdmin {
			adminUsers = append(adminUsers, admin) // --admin-only option
		}
	}

	if len(adminUsers) == 0 {
		return nil
	}
	if output, err := json.MarshalIndent(adminUsers, "", "  "); err != nil {
		return err
	} else {
		fmt.Fprintf(i.Out, "%s", string(output))
	}
	return nil
}

func (i *iamCheck) newAWSSession(region, assumeRole string) error {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region)},
	)
	if err != nil {
		return err
	}
	if assumeRole != "" {
		sess = session.New(&aws.Config{
			Region:      sess.Config.Region,
			Credentials: stscreds.NewCredentials(sess, assumeRole),
		})
	}
	i.Sess = sess
	i.Svc = iam.New(i.Sess)
	return nil
}

func (i *iamCheck) enablePermissionBoundory(userName string) (bool, error) {
	result, err := i.Svc.GetUser(&iam.GetUserInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		return false, err
	}
	return result.User.PermissionsBoundary != nil, nil
}

func (i *iamCheck) hasUserAdmin(userName string) (bool, error) {
	result, err := i.Svc.ListAttachedUserPolicies(&iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		return false, err
	}
	for _, policy := range result.AttachedPolicies {

		if isAdmin, err := i.isAdminPolicy(*policy.PolicyArn); err != nil {
			return false, err
		} else if isAdmin {
			return isAdmin, nil
		}
	}
	return false, nil
}

func (i *iamCheck) hasGroupAdmin(userName string) (bool, error) {
	result, err := i.Svc.ListGroupsForUser(&iam.ListGroupsForUserInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		return false, err
	}
	for _, g := range result.Groups {
		policies, err := i.Svc.ListAttachedGroupPolicies(&iam.ListAttachedGroupPoliciesInput{
			GroupName: aws.String(*g.GroupName),
		})
		if err != nil {
			return false, err
		}
		for _, p := range policies.AttachedPolicies {
			if isAdmin, err := i.isAdminPolicy(*p.PolicyArn); err != nil {
				return false, err
			} else if isAdmin {
				return isAdmin, nil
			}

		}
	}
	return false, nil
}

type policyDocument struct {
	Version   string
	Statement []statementEntry
}

type statementEntry struct {
	Effect   string
	Action   interface{}
	Resource interface{}
}

// AdministartorAccessかIAMFullAccessがあればtrue、インラインポリシーで←相当のものがあってもtrueを返します
// ※ただし、インラインポリシーは現状Denyがあっても無視します（Allowルールしか見ない）
func (i *iamCheck) isAdminPolicy(policyArn string) (bool, error) {
	// check admin managed policy
	if policyArn == managedAdminArn {
		return true, nil
	} else if policyArn == managedIAMFullArn {
		return true, nil
	}

	// check policyDocument
	p, err := i.Svc.GetPolicy(&iam.GetPolicyInput{
		PolicyArn: aws.String(policyArn),
	})
	if err != nil {
		return false, err
	}

	pv, err := i.Svc.GetPolicyVersion(&iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyArn),
		VersionId: aws.String(*p.Policy.DefaultVersionId),
	})
	if err != nil {
		return false, err
	}
	decodedDoc, err := url.QueryUnescape(aws.StringValue(pv.PolicyVersion.Document))
	if err != nil {
		return false, err
	}
	// TODO Debug
	// fmt.Fprintf(i.Out, "doc: %s\n", decodedDoc)

	var doc policyDocument
	if err := json.Unmarshal([]byte(decodedDoc), &doc); err != nil {
		return false, err
	}
	for _, statement := range doc.Statement {
		if statement.Effect == "" || statement.Action == nil || statement.Resource == nil {
			continue
		}

		if statement.Effect != "Allow" {
			// Denyルールの方が強いが無視
			continue
		}

		dangerAction := false
		if reflect.TypeOf(statement.Action).Name() == "string" {
			if statement.Action.(string) == iamAllAction ||
				statement.Action.(string) == allAction {
				dangerAction = true
			}
		} else {
			x := statement.Action.([]interface{})
			for i := 0; i < len(x); i++ {
				if x[i].(string) == iamAllAction ||
					x[i].(string) == allAction {
					dangerAction = true
				}
			}
		}

		dangerResource := false
		if reflect.TypeOf(statement.Resource).Name() == "string" {
			if statement.Resource.(string) == allResouce {
				dangerResource = true
			}
		} else {
			x := statement.Resource.([]interface{})
			for i := 0; i < len(x); i++ {
				if x[i].(string) == allResouce {
					dangerResource = true
				}
			}
		}
		if dangerAction && dangerResource {
			return true, nil
		}
	}
	return false, nil
}
