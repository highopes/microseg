#!/usr/bin/env python
###################################################################################
#                           Written by Wei, Hang                                  #
#                             hangwe@cisco.com                                    #
###################################################################################
"""This application helps to build a zero-trust environment that micro-segments
an existing EPG of an ACI. The segmentation is based on analytics from  AppDynamics
(First phase the analytics results are manually pre-configed)
"""
import argparse
import requests
import cobra.mit.access
import cobra.mit.session
import cobra.mit.request
import cobra.model.pol
import cobra.model.fv
import cobra.model.vmm
from credentials import *

# use argparse to provide optional arguments and a help menu
cli_args = argparse.ArgumentParser("Micro-segmentation", "Micro-segment existing EPG into uEPGs based on AppD.",
                                   "Required: Tenant, Application Profile")
cli_args.add_argument('-t', '--tenant', required=True,
                      help="The Existing Tenant's Name.")
cli_args.add_argument('-a', '--application', required=True,
                      help="The Existing Application Profile's Name.")

# use argparse to parse arguments into variables
args = cli_args.parse_args()

TENANT = vars(args)['tenant']
APNAME = vars(args)['application']


def test_err(tenant_name, ap_name, apic_session):
    """
    This function tests if the args are exsiting.

    :param tenant_name: The Tenant's name
    :param app_name: The Application Profile's name
    :param apic_session: An established session with the APIC
    """
    # build query for existing tenants
    tenant_query = cobra.mit.request.ClassQuery('fvTenant')
    tenant_query.propFilter = 'eq(fvTenant.name, "{}")'.format(tenant_name)

    # test for truthiness
    if not apic_session.query(tenant_query):
        print("\nTenant {} doesn't exist!\n".format(tenant_name))
        exit(1)

    ap_query = cobra.mit.request.ClassQuery('fvAp')
    ap_query.propFilter = 'eq(fvAp.name, "{}")'.format(ap_name)
    # test for truthiness, but doesn't work if you have duplicate name in other tenant
    if not apic_session.query(ap_query):
        print("\nApplication Profile {} doesn't exist!\n".format(ap_name))
        exit(1)


def get_BDname(tenant_name, ap_name, apic_session):
    """
    This function is to return bdname
    """
    ## TODO: call query ##
    bdname = "hangwe-outside-bd"
    return bdname


def get_baseEPG(tenant_name, ap_name, apic_session):
    """
    This function is to return base EPG
    """
    ## TODO: call query ##
    baseEPG = "cback-epg"
    return baseEPG


def get_VMM(tenant_name, ap_name, apic_session):
    """
    This function is to return the current VMM Domain's DN
    """
    ## TODO: call query ##
    vmm_dn = "uni/vmmp-VMware/dom-POV-UCS-HX"
    return vmm_dn


def get_AppD(tenant_name, ap_name):
    """
    This function is to return the tier flow context of the application analyzed by AppDynamics 
    """
    ## TODO: call AppD ##
    appdict = {"Web": ["172.16.1.14", "172.16.1.15", "172.16.1.16"], "App": ["172.16.1.24"], "DB": ["172.16.1.34"]}
    return appdict


def get_Relationships(tenant_name, ap_name):
    """
    This function is to return the relationships between uEPGs
    """
    ## TODO: call AppD ##
    rs = {"Web": {"app2web": ["consume"]}, "App": {"db2app": ["consume"], "app2web": ["provide"]},
          "DB": {"db2app": ["provide"]}}
    return rs


def main():
    """
    This main function micro-segments existing EPG into uEPGs based on AppDynamics analysis.
    """
    # create a session
    requests.packages.urllib3.disable_warnings()

    ls = cobra.mit.session.LoginSession(URL, LOGIN, PASSWORD)
    md = cobra.mit.access.MoDirectory(ls)
    md.login()

    # test if tenant/ap exists
    test_err(TENANT, APNAME, md)

    # get variables we need
    BDNAME = get_BDname(TENANT, APNAME, md)
    EPGNAME = get_baseEPG(TENANT, APNAME, md)
    VMMDN = get_VMM(TENANT, APNAME, md)
    APPD = get_AppD(TENANT, APNAME)
    RELATIONSHIPS = get_Relationships(TENANT, APNAME)

    # the top level object on which operations will be made
    polUni = cobra.model.pol.Uni('')
    fvTenant = cobra.model.fv.Tenant(polUni, TENANT)

    # Re-config existing Application Profile
    fvAp = cobra.model.fv.Ap(fvTenant, descr='This application has been micro-segmented by AppD', name=APNAME,
                             nameAlias='')

    # Re-config existing Base EPG
    fvAEPg_Base = cobra.model.fv.AEPg(fvAp, descr='The base EPG has been micro-segmented by AppD', name=EPGNAME,
                                      pcEnfPref='unenforced', prefGrMemb='exclude', shutdown='no')
    fvRsDomAtt_Base = cobra.model.fv.RsDomAtt(fvAEPg_Base, annotation='', bindingType='none', classPref='useg',
                                              customEpgName='',
                                              delimiter='', encap='unknown', encapMode='auto', epgCos='Cos0',
                                              epgCosPref='disabled', instrImedcy='immediate', lagPolicyName='',
                                              netflowDir='both', netflowPref='disabled', numPorts='0',
                                              portAllocation='none',
                                              primaryEncap='unknown', primaryEncapInner='unknown',
                                              resImedcy='immediate',
                                              secondaryEncapInner='unknown', switchingMode='native',
                                              tDn=VMMDN, untagged='no')
    vmmSecP_Base = cobra.model.vmm.SecP(fvRsDomAtt_Base, allowPromiscuous='reject', annotation='', descr='',
                                        forgedTransmits='reject', macChanges='reject', name='', nameAlias='',
                                        ownerKey='',
                                        ownerTag='')
    fvRsBd_Base = cobra.model.fv.RsBd(fvAEPg_Base, annotation='', tnFvBDName=BDNAME)

    # Create micro-segment for each app tier
    for tier, ips in APPD.items():
        # create uEPG
        fvAEPg = cobra.model.fv.AEPg(fvAp, descr='This is a Micro-segmented EPG created by AppDynamics',
                                     exceptionTag='', floodOnEncap='disabled', fwdCtrl='',
                                     hasMcastSource='no', isAttrBasedEPg='yes', matchT='AtleastOne', name=tier,
                                     nameAlias='', pcEnfPref='unenforced', prefGrMemb='exclude', prio='unspecified',
                                     shutdown='no')
        fvRsDomAtt = cobra.model.fv.RsDomAtt(fvAEPg, annotation='', bindingType='none', classPref='encap',
                                             customEpgName='',
                                             delimiter='', encap='unknown', encapMode='auto', epgCos='Cos0',
                                             epgCosPref='disabled', instrImedcy='immediate', lagPolicyName='',
                                             netflowDir='both', netflowPref='disabled', numPorts='0',
                                             portAllocation='none',
                                             primaryEncap='unknown', primaryEncapInner='unknown', resImedcy='immediate',
                                             secondaryEncapInner='unknown', switchingMode='native',
                                             tDn=VMMDN, untagged='no')
        fvRsCustQosPol = cobra.model.fv.RsCustQosPol(fvAEPg, annotation='', tnQosCustomPolName='')
        fvRsBd = cobra.model.fv.RsBd(fvAEPg, annotation='', tnFvBDName=BDNAME)
        fvCrtrn = cobra.model.fv.Crtrn(fvAEPg, annotation='', descr='', match='any', name='default', nameAlias='',
                                       ownerKey='',
                                       ownerTag='', prec='0')

        # attribute
        nameid = 0
        for ip in ips:
            fvIpAttr = cobra.model.fv.IpAttr(fvCrtrn, annotation='', descr='', ip=ip, name=str(nameid), nameAlias='',
                                             ownerKey='', ownerTag='', usefvSubnet='no')
            nameid += 1

        # build the relationships between uEPGs
        for ctr in RELATIONSHIPS[fvAEPg.name].items():
            if "consume" in ctr[1]:
                fvRsCons = cobra.model.fv.RsCons(fvAEPg, annotation='', intent='install', prio='unspecified',
                                                 tnVzBrCPName=ctr[0])
            if "provide" in ctr[1]:
                fvRsProv = cobra.model.fv.RsProv(fvAEPg, annotation='', intent='install', matchT='AtleastOne',
                                                 prio='unspecified', tnVzBrCPName=ctr[0])

    # commit the generated code to APIC
    c = cobra.mit.request.ConfigRequest()
    c.addMo(fvTenant)
    md.commit(c)

    print("\nApplication {} in Tenant {}, has been micro-segmented!\n".format(APNAME, TENANT))


if __name__ == '__main__':
    main()
