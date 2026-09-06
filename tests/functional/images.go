//go:build functional

package functional

type CrowdsecImage struct {
	Tag                  string
	SupportsBotChallenge bool
}

var CrowdsecImages = []CrowdsecImage{
	{Tag: "crowdsecurity/crowdsec:v1.7.0"},
	{Tag: "crowdsecurity/crowdsec:v1.7.2"},
	{Tag: "crowdsecurity/crowdsec:v1.7.3"},
	{Tag: "crowdsecurity/crowdsec:v1.7.4"},
	{Tag: "crowdsecurity/crowdsec:v1.7.6"},
	{Tag: "crowdsecurity/crowdsec:v1.7.7"},
	{Tag: "crowdsecurity/crowdsec:v1.7.8"},
	{Tag: "crowdsecurity/crowdsec:v1.8.0", SupportsBotChallenge: true},
	{Tag: "crowdsecurity/crowdsec:v1.8.1", SupportsBotChallenge: true},
}
