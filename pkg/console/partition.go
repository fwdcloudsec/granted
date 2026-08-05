package console

import "strings"

type PartitionHost int

const (
	Default PartitionHost = iota
	Gov
	Cn
	ISO
	ISOB
	Eusc
)

func (p PartitionHost) String() string {
	switch p {
	case Default:
		return "aws"
	case Gov:
		return "aws-us-gov"
	case Cn:
		return "aws-cn"
	case Eusc:
		return "aws-eusc"
	case ISO:
		return "aws-iso"
	case ISOB:
		return "aws-iso-b"
	}
	return "aws"
}

func (p PartitionHost) HostString() string {
	return p.RegionalHostString("")
}

func (p PartitionHost) RegionalHostString(region string) string {
	regionPrefix := GetRegionPrefixFromRegion(region)
	switch p {
	case Default:
		return regionPrefix + "signin.aws.amazon.com"
	case Gov:
		return regionPrefix + "signin.amazonaws-us-gov.com"
	case Cn:
		return regionPrefix + "signin.amazonaws.cn"
	case Eusc:
		return regionPrefix + "signin.amazonaws-eusc.eu"
	}

	// Note: we're not handling the ISO and ISOB cases, I don't think they are supported by a public AWS console
	return regionPrefix + "signin.aws.amazon.com"
}

func (p PartitionHost) ConsoleHostString() string {
	return p.RegionalConsoleHostString("")
}

func (p PartitionHost) RegionalConsoleHostString(region string) string {
	regionPrefix := GetRegionPrefixFromRegion(region)
	switch p {
	case Default:
		return "https://" + regionPrefix + "console.aws.amazon.com/"
	case Gov:
		return "https://" + regionPrefix + "console.amazonaws-us-gov.com/"
	case Cn:
		return "https://" + regionPrefix + "console.amazonaws.cn/"
	case Eusc:
		return "https://" + regionPrefix + "console.amazonaws-eusc.eu/"
	}
	// Note: we're not handling the ISO and ISOB cases, I don't think they are supported by a public AWS console
	return "https://" + regionPrefix + "console.aws.amazon.com/"
}

func GetPartitionFromRegion(region string) PartitionHost {
	partition := strings.Split(region, "-")
	if partition[0] == "cn" {
		return PartitionHost(Cn)
	}
	if partition[0] == "eusc" {
		return PartitionHost(Eusc)
	}
	if len(partition) > 1 {
		if partition[1] == "iso" {
			return PartitionHost(ISO)
		}
		if partition[1] == "isob" {
			return PartitionHost(ISOB)
		}
		if partition[1] == "gov" {
			return PartitionHost(Gov)
		}
	}
	return PartitionHost(Default)
}

func GetRegionPrefixFromRegion(region string) string {
	if region == "us-east-1" || region == "" || region == "cn-north-1" || region == "us-gov-west-1" {
		return ""
	} else {
		return region + "."
	}
}
