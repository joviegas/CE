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
package com.tmobile.cloud.awsrules.iam;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.tmobile.pacman.commons.PacmanSdkConstants;
import com.tmobile.pacman.commons.policy.Annotation;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import software.amazon.awssdk.services.identitymanagement.IdentityManagementClient;
import software.amazon.awssdk.services.identitymanagement.model.AttachedPolicy;
import software.amazon.awssdk.services.identitymanagement.model.GetPolicyResponse;
import software.amazon.awssdk.services.identitymanagement.model.GetPolicyVersionResponse;
import software.amazon.awssdk.services.identitymanagement.model.ListAttachedRolePoliciesResponse;
import software.amazon.awssdk.services.identitymanagement.model.Policy;
import software.amazon.awssdk.services.identitymanagement.model.PolicyVersion;
import com.tmobile.cloud.awsrules.utils.CommonTestUtils;
import com.tmobile.cloud.awsrules.utils.IAMUtils;
import com.tmobile.cloud.awsrules.utils.PacmanUtils;
import com.tmobile.pacman.commons.exception.InvalidInputException;
import com.tmobile.pacman.commons.policy.BasePolicy;

@PowerMockIgnore({"javax.net.ssl.*","javax.management.*"})
@RunWith(PowerMockRunner.class)
@PrepareForTest({URLDecoder.class, PacmanUtils.class,IAMUtils.class, Annotation.class})
public class IAMAccessGrantForNonAdminAccountRuleTest {

    @InjectMocks
    IAMAccessGrantForNonAdminAccountRule iamAccessGrantForNonAdminAccountRule;
    
    
    @Mock
    IdentityManagementClient identityManagementClient;

    @Before
    public void setUp() throws Exception{
        identityManagementClient = PowerMockito.mock(IdentityManagementClient.class); 
    }
    @Test
    public void test()throws Exception{
        AttachedPolicy attachedPolicies = AttachedPolicy.builder().build();
        attachedPolicies.policyName("IAMFullAccess");
        List<AttachedPolicy> policies = new ArrayList<>();
        policies.add(attachedPolicies);
        ListAttachedRolePoliciesResponse result  = ListAttachedRolePoliciesResponse.builder().build();
        result.attachedPolicies(policies);
        result.isTruncated(false);
        
        
        AttachedPolicy attachedPolicies1 = AttachedPolicy.builder().build();
        attachedPolicies1.policyName("AdministratorAccess");
        List<AttachedPolicy> policies1 = new ArrayList<>();
        policies1.add(attachedPolicies1);
        ListAttachedRolePoliciesResponse result1  = ListAttachedRolePoliciesResponse.builder().build();
        result1.attachedPolicies(policies1);
        result1.isTruncated(false);
        
        AttachedPolicy attachedPolicies2 = AttachedPolicy.builder().build();
        attachedPolicies2.policyArn("123");
        List<AttachedPolicy> policies2 = new ArrayList<>();
        policies2.add(attachedPolicies2);
        ListAttachedRolePoliciesResponse result2  = ListAttachedRolePoliciesResponse.builder().build();
        result2.attachedPolicies(policies2);
        result2.isTruncated(false);
        
        
        List<AttachedPolicy> policies3 = new ArrayList<>();
        ListAttachedRolePoliciesResponse result3  = ListAttachedRolePoliciesResponse.builder().build();
        result3.attachedPolicies(policies3);
        result3.isTruncated(false);
        
        Policy policy = Policy.builder().build();
        policy.policyId("policyId");
        
        
        
        GetPolicyResponse policyResult = GetPolicyResponse.builder().build();
        policyResult.policy(policy);
        
        
        PolicyVersion policyVersion = PolicyVersion.builder().build();
        policyVersion.versionId("versionId");
        policyVersion.isDefaultVersion(true);
        policyVersion.document("{\"ag\":\"aws-all\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"iam:*\"]}],\"from\":0,\"searchtext\":\"\",\"size\":25}");
        
        GetPolicyVersionResponse versionResult = GetPolicyVersionResponse.builder().build();
        versionResult.policyVersion(policyVersion);
        
        
        GetPolicyResponse policyResult1 = GetPolicyResponse.builder().build();
        policyResult1.policy(policy);
        
        
        PolicyVersion policyVersion1 = PolicyVersion.builder().build();
        policyVersion1.versionId("versionId");
        policyVersion1.isDefaultVersion(true);
        policyVersion1.document("{\"ag\":\"aws-all\",\"Statement\":{\"Effect\":\"Allow\",\"Action\":[\"iam:*\"]},\"from\":0,\"searchtext\":\"\",\"size\":25}");
        
        GetPolicyVersionResponse versionResult1 = GetPolicyVersionResponse.builder().build();
        versionResult1.policyVersion(policyVersion1);
        
        mockStatic(PacmanUtils.class);
        when(PacmanUtils.doesAllHaveValue(anyString(),anyString(),anyString())).thenReturn(
                true);
        
        
        when(PacmanUtils.splitStringToAList(anyString(),anyString())).thenReturn(CommonTestUtils.getListString());
        
        Map<String,Object>map=new HashMap<String, Object>();
        map.put("client", identityManagementClient);
        IAMAccessGrantForNonAdminAccountRule spy = Mockito.spy(new IAMAccessGrantForNonAdminAccountRule());
        
        Mockito.doReturn(map).when((BasePolicy)spy).getClientFor(anyObject(), anyString(), anyObject());
        
        when(identityManagementClient.getPolicy(anyObject())).thenReturn(policyResult);
        when(identityManagementClient.listAttachedRolePolicies(anyObject())).thenReturn(result);
        when(identityManagementClient.getPolicyVersion(anyObject())).thenReturn(versionResult1);
        mockStatic(Annotation.class);
        when(Annotation.buildAnnotation(anyObject(),anyObject())).thenReturn(getMockAnnotation());
        spy.execute(CommonTestUtils.getMapString("r_123 "),CommonTestUtils.getMapString("r_123 "));
        
        when(identityManagementClient.getPolicy(anyObject())).thenReturn(policyResult);
        when(identityManagementClient.listAttachedRolePolicies(anyObject())).thenReturn(result);
        when(identityManagementClient.getPolicyVersion(anyObject())).thenReturn(versionResult);
        spy.execute(CommonTestUtils.getMapString("r_123 "),CommonTestUtils.getMapString("r_123 "));
        
        when(identityManagementClient.listAttachedRolePolicies(anyObject())).thenReturn(result1);
        spy.execute(CommonTestUtils.getMapString("r_123 "),CommonTestUtils.getMapString("r_123 "));
        
        when(identityManagementClient.listAttachedRolePolicies(anyObject())).thenReturn(result2);
        spy.execute(CommonTestUtils.getMapString("r_123 "),CommonTestUtils.getMapString("r_123 "));
        
        when(identityManagementClient.listAttachedRolePolicies(anyObject())).thenReturn(result3);
        spy.execute(CommonTestUtils.getMapString("r_123 "),CommonTestUtils.getMapString("r_123 "));
        
        spy.execute(CommonTestUtils.getMapString("r_123 "),CommonTestUtils.getAnotherMapString("r_123 "));
        
        mockStatic(URLDecoder.class);
        when(URLDecoder.decode(anyString(),anyString())).thenThrow(new UnsupportedEncodingException());
        assertThatThrownBy( 
                () -> iamAccessGrantForNonAdminAccountRule.execute(CommonTestUtils.getMapString("r_123 "),CommonTestUtils.getMapString("r_123 "))).isInstanceOf(InvalidInputException.class);
        
        
        when(PacmanUtils.doesAllHaveValue(anyString(),anyString(),anyString())).thenReturn(
                false);
        assertThatThrownBy(
                () -> iamAccessGrantForNonAdminAccountRule.execute(CommonTestUtils.getMapString("r_123 "),CommonTestUtils.getMapString("r_123 "))).isInstanceOf(InvalidInputException.class);
    }
    private Annotation getMockAnnotation() {
        Annotation annotation=new Annotation();
        annotation.put(PacmanSdkConstants.POLICY_NAME,"Mock policy name");
        annotation.put(PacmanSdkConstants.POLICY_ID, "Mock policy id");
        annotation.put(PacmanSdkConstants.POLICY_VERSION, "Mock policy version");
        annotation.put(PacmanSdkConstants.RESOURCE_ID, "Mock resource id");
        annotation.put(PacmanSdkConstants.TYPE, "Mock type");
        return annotation;
    }
    
    @Test
    public void getHelpTextTest(){
        assertThat(iamAccessGrantForNonAdminAccountRule.getHelpText(), is(notNullValue()));
    }

}
