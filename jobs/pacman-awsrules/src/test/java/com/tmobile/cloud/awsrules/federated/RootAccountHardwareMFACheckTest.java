package com.tmobile.cloud.awsrules.federated;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

import java.util.Arrays;
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
import software.amazon.awssdk.services.identitymanagement.model.AssignmentStatusType;
import software.amazon.awssdk.services.identitymanagement.model.GetAccountSummaryResponse;
import software.amazon.awssdk.services.identitymanagement.model.ListVirtualMfaDevicesRequest;
import software.amazon.awssdk.services.identitymanagement.model.ListVirtualMFADevicesResponse;
import software.amazon.awssdk.services.identitymanagement.model.VirtualMfaDevice;
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
public class RootAccountHardwareMFACheckTest {

	@InjectMocks
	RootAccountHardwareMFACheck rootAccountHardwareMFACheck;

	@Mock
	IdentityManagementClient amazonIdentityManagementClient;

	@Before
	public void setUp() throws Exception {
		amazonIdentityManagementClient = PowerMockito.mock(IdentityManagementClient.class);
	}

	@Test
	public void invalidMFA() throws Exception {

		mockStatic(PacmanUtils.class);
		when(PacmanUtils.doesAllHaveValue(anyString(), anyString(), anyString())).thenReturn(true);

		Map<String, String> ruleParam = getInputParamMap();
		ruleParam.put(PacmanRuleConstants.RESOURCE_ID, "123456789");
		
		Map<String, String> resourceAttribute = getResourceData("123456789");

		Map<String, Object> map = new HashMap<String, Object>();
		map.put("client", amazonIdentityManagementClient);
		RootAccountHardwareMFACheck spy = Mockito.spy(new RootAccountHardwareMFACheck());
		Mockito.doReturn(map).when((BasePolicy) spy).getClientFor(anyObject(), anyString(), anyObject());
		
		when(amazonIdentityManagementClient.getAccountSummary(anyObject())).thenReturn(mockSummary());
		
		ListVirtualMfaDevicesRequest listMfaRequest = ListVirtualMfaDevicesRequest.builder().build();
		when(amazonIdentityManagementClient.listVirtualMFADevices(listMfaRequest.assignmentStatus(AssignmentStatusType.Assigned))).thenReturn(mockMFAList());
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
	public void validMFA() throws Exception {

		mockStatic(PacmanUtils.class);
		when(PacmanUtils.doesAllHaveValue(anyString(), anyString(), anyString())).thenReturn(true);

		Map<String, String> ruleParam = getInputParamMap();
		ruleParam.put(PacmanRuleConstants.RESOURCE_ID, "123456789");
		
		Map<String, String> resourceAttribute = getResourceData("123456789");

		Map<String, Object> map = new HashMap<String, Object>();
		map.put("client", amazonIdentityManagementClient);
		RootAccountHardwareMFACheck spy = Mockito.spy(new RootAccountHardwareMFACheck());
		Mockito.doReturn(map).when((BasePolicy) spy).getClientFor(anyObject(), anyString(), anyObject());
		
		when(amazonIdentityManagementClient.getAccountSummary(anyObject())).thenReturn(mockSummary());
		
		ListVirtualMfaDevicesRequest listMfaRequest = ListVirtualMfaDevicesRequest.builder().build();
		when(amazonIdentityManagementClient.listVirtualMFADevices(listMfaRequest.assignmentStatus(AssignmentStatusType.Assigned))).thenReturn(null);
		
		PolicyResult ruleResult = spy.execute(ruleParam, resourceAttribute);

		assertEquals(PacmanSdkConstants.STATUS_SUCCESS, ruleResult.getStatus());
	}

	@Test
	public void mandatoryDataTest() throws Exception {

		mockStatic(PacmanUtils.class);

		Map<String, String> ruleParam = getInputParamMap();
		ruleParam.put(PacmanRuleConstants.RESOURCE_ID, "123456789");

		Map<String, String> resourceAttribute = getResourceData("123456789");

		when(PacmanUtils.doesAllHaveValue(anyString(), anyString(), anyString())).thenReturn(false);
		assertThatThrownBy(() -> rootAccountHardwareMFACheck.execute(ruleParam, resourceAttribute)).isInstanceOf(InvalidInputException.class);

	}

	@Test
	public void exceptionTest() throws Exception {

		mockStatic(PacmanUtils.class);

		when(PacmanUtils.doesAllHaveValue(anyString(), anyString(), anyString())).thenReturn(true);

		Map<String, String> ruleParam = getInputParamMap();
		ruleParam.put(PacmanRuleConstants.RESOURCE_ID, "123456789");
		
		Map<String, String> resourceAttribute = getResourceData("123456789");

		Map<String, Object> map = new HashMap<String, Object>();
		map.put("client", amazonIdentityManagementClient);
		RootAccountHardwareMFACheck spy = Mockito.spy(new RootAccountHardwareMFACheck());
		Mockito.doReturn(map).when((BasePolicy) spy).getClientFor(anyObject(), anyString(), anyObject());
		
		when(amazonIdentityManagementClient.getAccountSummary(anyObject())).thenThrow(new RuleExecutionFailedExeption());
		assertThatThrownBy(() -> spy.execute(ruleParam, resourceAttribute)).isInstanceOf(RuleExecutionFailedExeption.class);

	}
	
	@Test
	public void getHelpTextTest() {
		assertThat(rootAccountHardwareMFACheck.getHelpText(), is(notNullValue()));
	}

	private Map<String, String> getInputParamMap() {
		Map<String, String> ruleParam = new HashMap<>();
		ruleParam.put(PacmanSdkConstants.EXECUTION_ID, "exectionid");
		ruleParam.put(PacmanSdkConstants.POLICY_ID, "AWS_rootaccount_hardware_MFA_version-1_enable_harware_mfa_account");
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
	
	private ListVirtualMFADevicesResponse mockMFAList() {
		
		ListVirtualMFADevicesResponse result = ListVirtualMFADevicesResponse.builder().build();
		VirtualMfaDevice device1 = VirtualMfaDevice.builder().build();
		device1.serialNumber("root-account-mfa-device");
		VirtualMfaDevice device2 = VirtualMfaDevice.builder().build();
		device2.serialNumber("5654767676534");
		result.virtualMfaDevices(Arrays.asList(device1,device2));
		return result;
	}
	
	private GetAccountSummaryResponse mockSummary() {
		GetAccountSummaryResponse result = GetAccountSummaryResponse.builder().build();
		
		Map<String,Integer> map = new HashMap<>();
		map.put("AccountMFAEnabled", 1);
		result.summaryMap(map);
		return result;
	}


}
