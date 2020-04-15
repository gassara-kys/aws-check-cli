package main

import (
	"encoding/json"
	"net/url"
	"reflect"
)

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

func convertPolicyDocument(doc *string) (policyDocument, error) {
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
			if v, ok := stmtRaw.Action.([]string); ok {
				actions = append(actions, v...)
			}
		}
		stmt.Action = actions

		// convert resource interface{} -> []string
		var resources []string
		if reflect.TypeOf(stmtRaw.Resource).Name() == "string" {
			resources = append(resources, stmtRaw.Resource.(string))
		} else {
			if v, ok := stmtRaw.Resource.([]string); ok {
				resources = append(actions, v...)
			}
		}
		stmt.Resource = resources
		pd.Statement = append(pd.Statement, stmt)
	}
	return pd, nil
}
