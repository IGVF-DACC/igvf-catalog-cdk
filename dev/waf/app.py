from aws_cdk import App
from aws_cdk import Environment

from waf.config import config

from waf.constants import CATALOG_API_DEMO_WAF_PREFIX

from waf.acl import WAF
from waf.acl import WAFProps

from waf.rules import get_rules


ENVIRONMENT = Environment(
    account=config['account'],
    region=config['region'],
)

app = App()

demo_waf_catalog_api = WAF(
    app,
    IGVF_API_DEMO_WAF_PREFIX,
    props=WAFProps(
        rules=get_rules(IGVF_API_DEMO_WAF_PREFIX),
        prefix=IGVF_API_DEMO_WAF_PREFIX,
        ips_to_allow=[
            # e.g. '98.35.33.121/32',
        ],
        ips_to_block=[
            # e.g. '192.0.2.0/24',
        ]
    ),
    env=ENVIRONMENT,
    termination_protection=True,
)

app.synth()
