from typing import List, Dict, Any

from waf.constants import CATALOG_API_DEMO_WAF_PREFIX


def add_prefix_to_visibility_config_metric_config(rule: Dict[str, Any], prefix: str) -> Dict[str, Any]:
    if rule.get('VisibilityConfig', {}).get('MetricName') is not None:
        rule['VisibilityConfig']['MetricName'] = f"{prefix}-{rule['VisibilityConfig']['MetricName']}"
    return rule


def reset_priority(rule: Dict[str, Any], idx: int) -> Dict[str, Any]:
    rule['Priority'] = idx * 100
    return rule


RULES = {
    CATALOG_API_DEMO_WAF_PREFIX: [
        {
            "Name": "AWS-AWSManagedRulesAmazonIpReputationList",
            "Priority": 0,
            "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": "AWS",
                        "Name": "AWSManagedRulesAmazonIpReputationList"
                    }
            },
            "OverrideAction": {
                "None": {}
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": "AWS-AWSManagedRulesAmazonIpReputationList"
            }
        },
        {
            "Name": "AWS-AWSManagedRulesAnonymousIpList",
            "Priority": 1,
            "Statement": {
                "ManagedRuleGroupStatement": {
                    "VendorName": "AWS",
                    "Name": "AWSManagedRulesAnonymousIpList",
                    "RuleActionOverrides": [
                        {
                            "Name": "HostingProviderIPList",
                            "ActionToUse": {
                                "Count": {}
                            }
                        }
                    ]
                }
            },
            "OverrideAction": {
                "None": {}
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": "AWS-AWSManagedRulesAnonymousIpList"
            }
        },
        {
            "Name": "AWS-AWSManagedRulesKnownBadInputsRuleSet",
            "Priority": 2,
            "Statement": {
                "ManagedRuleGroupStatement": {
                    "VendorName": "AWS",
                    "Name": "AWSManagedRulesKnownBadInputsRuleSet"
                }
            },
            "OverrideAction": {
                "None": {}
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": "AWS-AWSManagedRulesKnownBadInputsRuleSet"
            }
        },
        {
            "Name": "AWS-AWSManagedRulesLinuxRuleSet",
            "Priority": 3,
            "Statement": {
                "ManagedRuleGroupStatement": {
                    "VendorName": "AWS",
                    "Name": "AWSManagedRulesLinuxRuleSet"
                }
            },
            "OverrideAction": {
                "None": {}
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": "AWS-AWSManagedRulesLinuxRuleSet"
            }
        },
        {
            "Name": "AWS-AWSManagedRulesPHPRuleSet",
            "Priority": 4,
            "Statement": {
                "ManagedRuleGroupStatement": {
                    "VendorName": "AWS",
                    "Name": "AWSManagedRulesPHPRuleSet"
                }
            },
            "OverrideAction": {
                "None": {}
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": "AWS-AWSManagedRulesPHPRuleSet"
            }
        }
    ],
}


def get_rules(prefix: str) -> List[Dict[str, Any]]:
    rules = RULES[prefix]
    return [
        reset_priority(
            add_prefix_to_visibility_config_metric_config(
                rule,
                prefix
            ),
            idx + 1
        )
        for idx, rule in enumerate(rules)
    ]
