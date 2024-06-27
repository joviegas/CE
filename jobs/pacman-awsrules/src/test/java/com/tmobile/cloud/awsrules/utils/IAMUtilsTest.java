/*******************************************************************************
 * Copyright 2018 T Mobile, Inc. or its affiliates. All Rights Reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 ******************************************************************************/
package com.tmobile.cloud.awsrules.utils;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import software.amazon.awssdk.services.identitymanagement.IdentityManagementClient;
import software.amazon.awssdk.services.identitymanagement.model.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest({URLDecoder.class, PacmanUtils.class})
public class IAMUtilsTest {

    @InjectMocks
    IAMUtils iamUtils;
    
    @Mock
    IdentityManagementClient iamClient;
    
    @Before
    public void setUp() throws Exception{
        iamClient = PowerMockito.mock(IdentityManagementClient.class); 
    }
 
    @SuppressWarnings("static-access")
    @Test
    public void getAccessKeyInformationForUserTest() throws Exception {
        
        ListAccessKeysResponse keysResult = ListAccessKeysResponse.builder().build();
        keysResult.isTruncated(false);
        
        when(iamClient.listAccessKeys(anyObject())).thenReturn(keysResult);
        assertThat(iamUtils.getAccessKeyInformationForUser("user",iamClient),is(notNullValue()));
        
    }
    
    @SuppressWarnings("static-access")
    @Test
    public void getAttachedPolicyOfIAMUserTest() throws Exception {
        
    	ListAttachedUserPoliciesResponse policiesResult = ListAttachedUserPoliciesResponse.builder().build();
        
        when(iamClient.listAttachedUserPolicies(anyObject())).thenReturn(policiesResult);
        assertThat(iamUtils.getAttachedPolicyOfIAMUser("user",iamClient),is(notNullValue()));
        
    }
    
    @SuppressWarnings("static-access")
    @Test
    public void getActionListByPolicyTest() throws Exception {
    	 AttachedPolicy attachedPolicies = AttachedPolicy.builder().build();
         attachedPolicies.policyName("IAMFullAccess");
         List<AttachedPolicy> policies = new ArrayList<>();
         policies.add(attachedPolicies);
         
         PolicyVersion versions = PolicyVersion.builder().build();
         versions.isDefaultVersion(true);
         versions.versionId("123");
         versions.document("{\"ag\":\"aws-all\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"iam:*\"],\"Resource\":[\"iam:*\"]}],\"from\":0,\"searchtext\":\"\",\"size\":25}");
        ListPolicyVersionsResponse policyVersions = ListPolicyVersionsResponse.builder().build();
        policyVersions.versions(Arrays.asList(versions));
        
        
        ListAttachedUserPoliciesResponse attachedUserPoliciesResult = ListAttachedUserPoliciesResponse.builder().build();
        attachedUserPoliciesResult.attachedPolicies(policies);
        attachedUserPoliciesResult.isTruncated(false);
        
        ListUserPoliciesResponse listUserPoliciesResult = ListUserPoliciesResponse.builder().build();
        listUserPoliciesResult.policyNames(Arrays.asList("123"));
        listUserPoliciesResult.isTruncated(false);
        
        GetUserPolicyResponse policyResult = GetUserPolicyResponse.builder().build();
        
        policyResult.policyName("123");
        policyResult.policyDocument("{\"ag\":\"aws-all\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"iam:*\"],\"Resource\":[\"iam:*\"]}],\"from\":0,\"searchtext\":\"\",\"size\":25}");
        policyResult.userName("123");
         
        GetPolicyVersionResponse versionResult = GetPolicyVersionResponse.builder().build();
        versionResult.policyVersion(versions);
        when(iamClient.listAttachedUserPolicies(anyObject())).thenReturn(attachedUserPoliciesResult);
        when(iamClient.listUserPolicies(anyObject())).thenReturn(listUserPoliciesResult);
        when(iamClient.getUserPolicy(anyObject())).thenReturn(policyResult);
        when(iamClient.listPolicyVersions(anyObject())).thenReturn(policyVersions);
        when(iamClient.getPolicyVersion(anyObject())).thenReturn(versionResult);
        mockStatic(URLDecoder.class);
        when(URLDecoder.decode(anyString(),anyString())).thenReturn("qeqwehgj");
        assertThat(iamUtils.getAllowedActionsByUserPolicy(iamClient,"133"),is(notNullValue()));
        
    }
    
    @SuppressWarnings("static-access")
    @Test
    public void getActionsByRolePolicyTest() throws Exception {
    	 AttachedPolicy attachedPolicies = AttachedPolicy.builder().build();
         attachedPolicies.policyName("IAMFullAccess");
         List<AttachedPolicy> policies = new ArrayList<>();
         policies.add(attachedPolicies);
         
         PolicyVersion versions = PolicyVersion.builder().build();
         versions.isDefaultVersion(true);
         versions.versionId("123");
         versions.document("{\"ag\":\"aws-all\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"iam:*\"],\"Resource\":[\"iam:*\"]}],\"from\":0,\"searchtext\":\"\",\"size\":25}");
        ListPolicyVersionsResponse policyVersions = ListPolicyVersionsResponse.builder().build();
        policyVersions.versions(Arrays.asList(versions));
        
        
        ListAttachedRolePoliciesResponse attachedRolePoliciesResult = ListAttachedRolePoliciesResponse.builder().build();
        attachedRolePoliciesResult.attachedPolicies(policies);
        attachedRolePoliciesResult.isTruncated(false);
        
        ListRolePoliciesResponse rolePoliciesResult = ListRolePoliciesResponse.builder().build();
        rolePoliciesResult.policyNames(Arrays.asList("123"));
        rolePoliciesResult.isTruncated(false);
        
        GetRolePolicyResponse policyResult = GetRolePolicyResponse.builder().build();
        
        policyResult.policyName("123");
        policyResult.policyDocument("{\"ag\":\"aws-all\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"iam:*\"],\"Resource\":[\"iam:*\"]}],\"from\":0,\"searchtext\":\"\",\"size\":25}");
        policyResult.roleName("123");
         
        GetPolicyVersionResponse versionResult = GetPolicyVersionResponse.builder().build();
        versionResult.policyVersion(versions);
        when(iamClient.listAttachedRolePolicies(anyObject())).thenReturn(attachedRolePoliciesResult);
        when(iamClient.listRolePolicies(anyObject())).thenReturn(rolePoliciesResult);
        when(iamClient.getRolePolicy(anyObject())).thenReturn(policyResult);
        when(iamClient.listPolicyVersions(anyObject())).thenReturn(policyVersions);
        when(iamClient.getPolicyVersion(anyObject())).thenReturn(versionResult);
        mockStatic(URLDecoder.class);
        when(URLDecoder.decode(anyString(),anyString())).thenReturn("qeqwehgj");
        assertThat(iamUtils.getAllowedActionsByRolePolicy(iamClient,"133"),is(notNullValue()));
        
    }
    
}
