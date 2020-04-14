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
	// Managed policies
	mngPolicies, err := i.Svc.ListAttachedUserPolicies(
		&iam.ListAttachedUserPoliciesInput{
			UserName: aws.String(userName),
		})
	if err != nil {
		return false, err
	}
	// TODO Debug
	fmt.Fprintf(i.Out, "user: %s ---------------------------------------\n managed policy: %+v\n", userName, mngPolicies.AttachedPolicies)

	for _, p := range mngPolicies.AttachedPolicies {
		if i.isAdminManagedPolicy(*p.PolicyArn) {
			return true, nil
		}
	}

	// Inline policies
	inlinePolicies, err := i.Svc.ListUserPolicies(
		&iam.ListUserPoliciesInput{
			UserName: aws.String(userName),
		})
	if err != nil {
		return false, err
	}
	for _, pNm := range inlinePolicies.PolicyNames {
		p, err := i.Svc.GetUserPolicy(&iam.GetUserPolicyInput{
			UserName:   aws.String(userName),
			PolicyName: pNm,
		})
		if err != nil {
			return false, err
		}
		pd, err := i.convertPolicyDocument(p.PolicyDocument)
		if err != nil {
			return false, err
		}
		if i.isAdminInlinePolicy(pd) {
			return true, nil
		}
	}
	return false, nil
}

func (i *iamCheck) hasGroupAdmin(userName string) (bool, error) {
	gs, err := i.Svc.ListGroupsForUser(
		&iam.ListGroupsForUserInput{
			UserName: aws.String(userName),
		})
	if err != nil {
		return false, err
	}
	for _, g := range gs.Groups {
		// Managed Policy
		mngPolicies, err := i.Svc.ListAttachedGroupPolicies(
			&iam.ListAttachedGroupPoliciesInput{
				GroupName: aws.String(*g.GroupName),
			})
		if err != nil {
			return false, err
		}
		for _, p := range mngPolicies.AttachedPolicies {
			if i.isAdminManagedPolicy(*p.PolicyArn) {
				return true, nil
			}
		}

		// Inline Policy
		inlinePolicies, err := i.Svc.ListGroupPolicies(
			&iam.ListGroupPoliciesInput{
				GroupName: aws.String(*g.GroupName),
			})
		if err != nil {
			return false, err
		}
		for _, pNm := range inlinePolicies.PolicyNames {
			p, err := i.Svc.GetGroupPolicy(
				&iam.GetGroupPolicyInput{
					GroupName:  aws.String(*g.GroupName),
					PolicyName: pNm,
				})
			if err != nil {
				return false, err
			}
			pd, err := i.convertPolicyDocument(p.PolicyDocument)
			if err != nil {
				return false, err
			}
			if i.isAdminInlinePolicy(pd) {
				return true, nil
			}
		}
	}
	return false, nil
}

type policyDocumentRaw struct {
	Version   string
	Statement []statementEntryRaw
}

type statementEntryRaw struct {
	Effect   string
	Action   interface{}
	Resource interface{}
}

type policyDocument struct {
	Version   string
	Statement []statementEntry
}

type statementEntry struct {
	Effect   string
	Action   []string
	Resource []string
}

func (i *iamCheck) convertPolicyDocument(doc *string) (policyDocument, error) {
	var pd policyDocument
	decodedDoc, err := url.QueryUnescape(*doc)
	if err != nil {
		return pd, err
	}
	var pdRaw policyDocumentRaw
	if err := json.Unmarshal([]byte(decodedDoc), &pdRaw); err != nil {
		return pd, err
	}
	pd.Version = pdRaw.Version
	for _, stmtRaw := range pdRaw.Statement {
		if stmtRaw.Effect == "" || stmtRaw.Action == nil || stmtRaw.Resource == nil {
			continue
		}
		var stmt statementEntry
		stmt.Effect = stmtRaw.Effect

		// convert action interface{} -> []string
		var actions []string
		if reflect.TypeOf(stmtRaw.Action).Name() == "string" {
			actions = append(actions, stmtRaw.Action.(string))
		} else {
			actions = append(actions, stmtRaw.Action.([]string)...)
		}
		stmt.Action = actions

		// convert resource interface{} -> []string
		var resources []string
		if reflect.TypeOf(stmtRaw.Resource).Name() == "string" {
			resources = append(resources, stmtRaw.Resource.(string))
		} else {
			resources = append(resources, stmtRaw.Resource.([]string)...)
		}
		stmt.Resource = resources
		pd.Statement = append(pd.Statement, stmt)
	}

	return pd, nil
}

// Inline PolicyのAdmin判定
// ※ただし、現状Denyがあっても無視します（Allowルールしか見ない）
func (i *iamCheck) isAdminInlinePolicy(doc policyDocument) bool {
	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			// Denyルールの方が強いが無視
			continue
		}

		dangerAction := false
		for _, a := range stmt.Action {
			if a == allAction || a == iamAllAction {
				dangerAction = true
				break
			}
		}
		dangerResource := false
		for _, a := range stmt.Resource {
			if a == allResouce {
				dangerResource = true
				break
			}
		}
		if dangerAction && dangerResource {
			return true
		}
	}
	return false
}

// ManagedPolicyのAdmin判定
// ※ただし、現状Denyがあっても無視します
func (i *iamCheck) isAdminManagedPolicy(policyArn string) bool {
	if policyArn == managedAdminArn || policyArn == managedIAMFullArn {
		return true
	}
	return false
}
