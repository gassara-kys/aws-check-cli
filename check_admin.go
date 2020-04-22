package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

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
	allAction1        = "*:*"
	allAction2        = "*"
	allResouce        = "*"
)

func init() {
	cmdList = append(cmdList, cli.Command{
		Name:  "admin-check",
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
			return action(c, &adminChecker{Out: os.Stdout})
		},
	})
}

type adminChecker struct {
	Out  io.Writer
	Sess *session.Session
	Svc  *iam.IAM
}

type adminUser struct {
	UserArn                  string   `json:"user_arn"`
	UserName                 string   `json:"user_name"`
	AccessKeyID              []string `json:"access_key_id"`
	HasUserAdmin             bool     `json:"has_user_admin"`
	HasGroupAdmin            bool     `json:"has_grorup_admin"`
	EnablePermissionBoundory bool     `json:"enable_permission_boundory"`
}

func (a *adminChecker) Run(c *cli.Context, region string) error {
	return a.Main(region, c.String("assume-role-arn"), c.Bool("admin-only"))
}

func (a *adminChecker) Main(region, assumeRole string, adminOnly bool) error {
	if err := a.newAWSSession(region, assumeRole); err != nil {
		return err
	}
	result, err := a.Svc.ListUsers(&iam.ListUsersInput{})
	if err != nil {
		return err
	}

	var adminUsers []adminUser
	for _, user := range result.Users {
		if user == nil {
			continue
		}
		admin := adminUser{
			UserArn:  *user.Arn,
			UserName: *user.UserName,
		}
		if err := a.setAccessKeyIDs(&admin); err != nil {
			return err
		}
		if admin.AccessKeyID == nil {
			continue // there are no active access keys.
		}

		// Permission Boundory
		if enabled, err := a.enablePermissionBoundory(*user.UserName); err != nil {
			return err
		} else {
			admin.EnablePermissionBoundory = enabled
		}
		// User attached policy
		if has, err := a.hasUserAdmin(admin.UserName); err != nil {
			return err
		} else if has {
			admin.HasUserAdmin = true
		}
		// Group attached policy
		if has, err := a.hasGroupAdmin(admin.UserName); err != nil {
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
		fmt.Fprintf(a.Out, "%s", string(output))
	}
	return nil
}

func (a *adminChecker) newAWSSession(region, assumeRole string) error {
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
	a.Sess = sess
	a.Svc = iam.New(a.Sess)
	return nil
}

func (a *adminChecker) setAccessKeyIDs(user *adminUser) error {
	result, err := a.Svc.ListAccessKeys(&iam.ListAccessKeysInput{
		UserName: &user.UserName,
	})
	if err != nil {
		return err
	}
	for _, key := range result.AccessKeyMetadata {
		if *key.Status == "Active" {
			user.AccessKeyID = append(user.AccessKeyID, *key.AccessKeyId)
		}
	}
	return nil
}

func (a *adminChecker) enablePermissionBoundory(userName string) (bool, error) {
	result, err := a.Svc.GetUser(&iam.GetUserInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		return false, err
	}
	return result.User.PermissionsBoundary != nil, nil
}

func (a *adminChecker) hasUserAdmin(userName string) (bool, error) {
	// Managed policies
	mngPolicies, err := a.Svc.ListAttachedUserPolicies(
		&iam.ListAttachedUserPoliciesInput{
			UserName: aws.String(userName),
		})
	if err != nil {
		return false, err
	}
	for _, p := range mngPolicies.AttachedPolicies {
		if isAdmin, err := a.isAdminManagedPolicy(*p.PolicyArn); err != nil {
			return false, err
		} else if isAdmin {
			return true, nil
		}
	}

	// Inline policies
	inlinePolicies, err := a.Svc.ListUserPolicies(
		&iam.ListUserPoliciesInput{
			UserName: aws.String(userName),
		})
	if err != nil {
		return false, err
	}
	for _, policyNm := range inlinePolicies.PolicyNames {
		if isAdmin, err := a.isAdminUserInlinePolicy(&userName, policyNm); err != nil {
			return false, err

		} else if isAdmin {
			return true, nil
		}
	}
	return false, nil
}

func (a *adminChecker) hasGroupAdmin(userName string) (bool, error) {
	gs, err := a.Svc.ListGroupsForUser(
		&iam.ListGroupsForUserInput{
			UserName: aws.String(userName),
		})
	if err != nil {
		return false, err
	}
	for _, g := range gs.Groups {
		// Managed Policy
		mngPolicies, err := a.Svc.ListAttachedGroupPolicies(
			&iam.ListAttachedGroupPoliciesInput{
				GroupName: aws.String(*g.GroupName),
			})
		if err != nil {
			return false, err
		}
		for _, p := range mngPolicies.AttachedPolicies {
			if isAdmin, err := a.isAdminManagedPolicy(*p.PolicyArn); err != nil {
				return false, err
			} else if isAdmin {
				return true, nil
			}
		}

		// Inline Policy
		inlinePolicies, err := a.Svc.ListGroupPolicies(
			&iam.ListGroupPoliciesInput{
				GroupName: aws.String(*g.GroupName),
			})
		if err != nil {
			return false, err
		}
		for _, policyNm := range inlinePolicies.PolicyNames {
			if isAdmin, err := a.isAdminGroupInlinePolicy(g.GroupName, policyNm); err != nil {
				return false, err

			} else if isAdmin {
				return true, nil
			}
		}
	}
	return false, nil
}

// Policy Documentの内容がAdministrator or IAMFullAccess相当かチェックします
// ※ただし、現状Denyがあっても無視します（Allowルールしか見ない）
func (a *adminChecker) isAdminPolicyDoc(doc policyDocument) bool {
	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			// Denyルールの方が強いが無視
			continue
		}

		dangerAction := false
		for _, a := range stmt.Action {
			if a == allAction1 || a == allAction2 || a == iamAllAction {
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

// isAdminManagedPolicy AWS Managed Policy / Customer Managed PolicyのAdmin判定
func (a *adminChecker) isAdminManagedPolicy(policyArn string) (bool, error) {
	// Check for AWS Managed policy
	if policyArn == managedAdminArn || policyArn == managedIAMFullArn {
		return true, nil
	}

	// Check for Customer Managed policy
	p, err := a.Svc.GetPolicy(&iam.GetPolicyInput{
		PolicyArn: aws.String(policyArn),
	})
	if err != nil {
		return false, err
	}
	pv, err := a.Svc.GetPolicyVersion(&iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyArn),
		VersionId: p.Policy.DefaultVersionId,
	})
	if err != nil {
		return false, err
	}
	doc, err := convertPolicyDocument(pv.PolicyVersion.Document)
	if err != nil {
		return false, err
	}
	return a.isAdminPolicyDoc(doc), nil
}

// isAdminUserInlinePolicy Inline PolicyのAdmin判定
func (a *adminChecker) isAdminUserInlinePolicy(userNm, policyNm *string) (bool, error) {
	p, err := a.Svc.GetUserPolicy(&iam.GetUserPolicyInput{
		UserName:   userNm,
		PolicyName: policyNm,
	})
	if err != nil {
		return false, err
	}
	doc, err := convertPolicyDocument(p.PolicyDocument)
	if err != nil {
		return false, err
	}
	return a.isAdminPolicyDoc(doc), nil
}

// isAdminGroupInlinePolicy Inline PolicyのAdmin判定
func (a *adminChecker) isAdminGroupInlinePolicy(group, policy *string) (bool, error) {
	p, err := a.Svc.GetGroupPolicy(&iam.GetGroupPolicyInput{
		GroupName:  group,
		PolicyName: policy,
	})
	if err != nil {
		return false, err
	}
	doc, err := convertPolicyDocument(p.PolicyDocument)
	if err != nil {
		return false, err
	}
	return a.isAdminPolicyDoc(doc), nil
}
