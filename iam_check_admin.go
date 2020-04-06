package main

import (
	"fmt"
	"io"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/urfave/cli"
)

const managedAdminArn = "arn:aws:iam::aws:policy/AdministratorAccess"

func init() {
	cmdList = append(cmdList, cli.Command{
		Name:  "iam-admin-check",
		Usage: "check iam-user who has administrator access",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:   "assume-role-arn",
				Usage:  "if set this option, try assume role and check IAM",
				EnvVar: "ASSUME_ROLE_ARN",
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
	UserName                 string `json:"user_name"`
	HasUserAdmin             bool   `json:"has_user_admin`
	HasGroupAdmin            bool   `json:"has_grorup_admin`
	EnablePermissionBoundory bool   `json:"enable_permission_boundory`
}

func (i *iamCheck) Run(c *cli.Context, region string) error {
	return i.Main(region, c.String("assume-role-arn"))
}

func (i *iamCheck) Main(region, assumeRole string) error {
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
			UserName: *user.UserName,
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
			adminUsers = append(adminUsers, admin)
			continue
		}

		// Group Policy TODO

	}

	fmt.Fprintf(i.Out, "%+v", adminUsers)
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
		// Check Managed-Policy
		if *policy.PolicyArn == managedAdminArn {
			return true, nil
		}

		// Check Inline-Policy TODO
	}
	return false, nil
}
