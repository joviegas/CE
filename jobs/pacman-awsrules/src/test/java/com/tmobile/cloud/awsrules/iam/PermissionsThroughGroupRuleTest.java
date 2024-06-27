package com.tmobile.cloud.awsrules.iam;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

import java.util.HashMap;
import java.util.Map;

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

import com.tmobile.cloud.awsrules.utils.IAMUtils;
import com.tmobile.cloud.awsrules.utils.PacmanUtils;
import com.tmobile.cloud.constants.PacmanRuleConstants;
import com.tmobile.pacman.commons.PacmanSdkConstants;
import com.tmobile.pacman.commons.exception.InvalidInputException;
import com.tmobile.pacman.commons.exception.RuleExecutionFailedExeption;
import com.tmobile.pacman.commons.policy.BasePolicy;
import com.tmobile.pacman.commons.policy.PolicyResult;

@PowerMockIgnore({ "javax.net.ssl.*", "javax.management.*" })
@RunWith(PowerMockRunner.class)
@PrepareForTest({ PacmanUtils.class, BasePolicy.class, IAMUtils.class, Annotation.class })
public class PermissionsThroughGroupRuleTest {

	@InjectMocks
	PermissionsThroughGroupRule permissionsThroughGroupRule;

	@Mock
	IdentityManagementClient amazonIdentityManagementClient;

	@Before
	public void setUp() throws Exception {
		amazonIdentityManagementClient = PowerMockito.mock(IdentityManagementClient.class);
	}

	@Test
	public void iamUserWithInvalidPermission() throws Exception {

		mockStatic(PacmanUtils.class);
		mockStatic(IAMUtils.class);
		when(PacmanUtils.doesAllHaveValue(anyString(), anyString(), anyString())).thenReturn(true);

		Map<String, String> ruleParam = getInputParamMap();
		ruleParam.put(PacmanRuleConstants.RESOURCE_ID, "arn:aws:iam::123456789:user/user1");
		
		Map<String, String> resourceAttribute = getResourceData("arn:aws:iam::123456789:user/user1");

		Map<String, Object> map = new HashMap<String, Object>();
		map.put("client", amazonIdentityManagementClient);
		PermissionsThroughGroupRule spy = Mockito.spy(new PermissionsThroughGroupRule());
		Mockito.doReturn(map).when((BasePolicy) spy).getClientFor(anyObject(), anyString(), anyObject());
		
		when(IAMUtils.isUserHasInvalidPermission(anyString(),anyObject())).thenReturn(true);
		mockStatic(Annotation.class);
		when(Annotation.buildAnnotation(anyObject(),anyObject())).thenReturn(getMockAnnotation());
		PolicyResult ruleResult = spy.execute(ruleParam, resourceAttribute);

		assertEquals(PacmanSdkConstants.STATUS_FAILURE, ruleResult.getStatus());
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
	public void iamUserWithValidPermission() throws Exception {

		mockStatic(PacmanUtils.class);
		mockStatic(IAMUtils.class);
		when(PacmanUtils.doesAllHaveValue(anyString(), anyString(), anyString())).thenReturn(true);

		Map<String, String> ruleParam = getInputParamMap();
		ruleParam.put(PacmanRuleConstants.RESOURCE_ID, "arn:aws:iam::123456789:user/user1");
		
		Map<String, String> resourceAttribute = getResourceData("arn:aws:iam::123456789:user/user1");

		Map<String, Object> map = new HashMap<String, Object>();
		map.put("client", amazonIdentityManagementClient);
		PermissionsThroughGroupRule spy = Mockito.spy(new PermissionsThroughGroupRule());
		Mockito.doReturn(map).when((BasePolicy) spy).getClientFor(anyObject(), anyString(), anyObject());
		
		when(IAMUtils.isUserHasInvalidPermission(anyString(),anyObject())).thenReturn(false);

		PolicyResult ruleResult = spy.execute(ruleParam, resourceAttribute);

		assertEquals(PacmanSdkConstants.STATUS_SUCCESS, ruleResult.getStatus());
	}

	@Test
	public void mandatoryDataTest() throws Exception {

		mockStatic(PacmanUtils.class);
		mockStatic(IAMUtils.class);

		Map<String, String> ruleParam = getInputParamMap();
		ruleParam.put(PacmanRuleConstants.RESOURCE_ID, "arn:aws:iam::123456789:user/user1");

		Map<String, String> resourceAttribute = getResourceData("arn:aws:iam::123456789:user/user1");

		when(PacmanUtils.doesAllHaveValue(anyString(), anyString(), anyString())).thenReturn(false);
		assertThatThrownBy(() -> permissionsThroughGroupRule.execute(ruleParam, resourceAttribute)).isInstanceOf(InvalidInputException.class);

	}

	@Test
	public void exceptionTest() throws Exception {

		mockStatic(PacmanUtils.class);
		mockStatic(IAMUtils.class);

		when(PacmanUtils.doesAllHaveValue(anyString(), anyString(), anyString())).thenReturn(true);

		Map<String, String> ruleParam = getInputParamMap();
		ruleParam.put(PacmanRuleConstants.RESOURCE_ID, "arn:aws:iam::123456789:user/user1");

		Map<String, String> resourceAttribute = getResourceData("arn:aws:iam::123456789:user/user1");

		Map<String, Object> map = new HashMap<String, Object>();
		map.put("client", amazonIdentityManagementClient);
		PermissionsThroughGroupRule spy = Mockito.spy(new PermissionsThroughGroupRule());

		Mockito.doReturn(map).when((BasePolicy) spy).getClientFor(anyObject(), anyString(), anyObject());

		when(IAMUtils.isUserHasInvalidPermission(anyString(),anyObject())).thenThrow(new RuleExecutionFailedExeption());
		assertThatThrownBy(() -> spy.execute(ruleParam, resourceAttribute)).isInstanceOf(RuleExecutionFailedExeption.class);

	}
	
	@Test
	public void getHelpTextTest() {
		assertThat(permissionsThroughGroupRule.getHelpText(), is(notNullValue()));
	}

	private Map<String, String> getInputParamMap() {
		Map<String, String> ruleParam = new HashMap<>();
		ruleParam.put(PacmanSdkConstants.EXECUTION_ID, "exectionid");
		ruleParam.put(PacmanSdkConstants.POLICY_ID, "AWS_user_permissions_via_group_version-1_user_policy_via_group_iamuser");
		ruleParam.put(PacmanRuleConstants.CATEGORY, PacmanSdkConstants.SECURITY);
		ruleParam.put(PacmanRuleConstants.SEVERITY, PacmanSdkConstants.SEV_MEDIUM);
		ruleParam.put(PacmanRuleConstants.ACCOUNTID, "123456789");
		ruleParam.put(PacmanSdkConstants.Role_IDENTIFYING_STRING, "test/ro");
		return ruleParam;
	}

	private Map<String, String> getResourceData(String id) {
		Map<String, String> resObj = new HashMap<>();
		resObj.put("_resourceid", id);
		return resObj;
	}
	
}
