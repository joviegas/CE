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
package com.tmobile.cloud.awsrules.cloudwatchevent;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

import java.util.ArrayList;
import java.util.Collection;
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
import software.amazon.awssdk.services.cloudwatchevents.CloudWatchEventsClient;
import software.amazon.awssdk.services.cloudwatchevents.model.ListRulesResponse;
import software.amazon.awssdk.services.cloudwatchevents.model.Rule;
import com.tmobile.cloud.awsrules.utils.CommonTestUtils;
import com.tmobile.cloud.awsrules.utils.PacmanUtils;
import com.tmobile.pacman.commons.exception.InvalidInputException;
import com.tmobile.pacman.commons.exception.RuleExecutionFailedExeption;
import com.tmobile.pacman.commons.policy.BasePolicy;

@PowerMockIgnore({"javax.net.ssl.*","javax.management.*"})
@RunWith(PowerMockRunner.class)
@PrepareForTest({ PacmanUtils.class,BasePolicy.class, Annotation.class})
public class CheckCloudWatchEventsForAllAccountsRuleTest {

    @InjectMocks
    CheckCloudWatchEventsForAllAccountsRule cloudWatchEventsForAllAccountsRule;
    
    
    @Mock
    CloudWatchEventsClient cloudWatchEventsClient;

    @Before
    public void setUp() throws Exception{
        mockStatic(Annotation.class);
        when(Annotation.buildAnnotation(anyObject(), anyObject())).thenReturn(CommonTestUtils.getMockAnnotation());
        cloudWatchEventsClient = PowerMockito.mock(CloudWatchEventsClient.class); 
    }
    @Test
    public void test()throws Exception{
        Rule rules = Rule.builder().build();
        rules.name("abc");
        Collection<Rule> li = new ArrayList<>();
        li.add(rules);
        ListRulesResponse listRulesResult = ListRulesResponse.builder().build();
        listRulesResult.rules(li);
        
        Collection<Rule> emptyList = new ArrayList<>();
        ListRulesResponse emptyRulesResult = ListRulesResponse.builder().build();
        emptyRulesResult.rules(emptyList);
        
        
        mockStatic(PacmanUtils.class);
        when(PacmanUtils.doesAllHaveValue(anyString(),anyString(),anyString())).thenReturn(
                true);
        
        Map<String,Object>map=new HashMap<String, Object>();
        map.put("client", cloudWatchEventsClient);
        CheckCloudWatchEventsForAllAccountsRule spy = Mockito.spy(new CheckCloudWatchEventsForAllAccountsRule());
        
        Mockito.doReturn(map).when((BasePolicy)spy).getClientFor(anyObject(), anyString(), anyObject());
        
        when(cloudWatchEventsClient.listRules(anyObject())).thenReturn(listRulesResult);
        spy.execute(CommonTestUtils.getMapString("r_123 "),CommonTestUtils.getMapString("r_123 "));
        
        when(cloudWatchEventsClient.listRules(anyObject())).thenReturn(emptyRulesResult);
        spy.execute(CommonTestUtils.getMapString("r_123 "),CommonTestUtils.getMapString("r_123 "));
        
        when(cloudWatchEventsClient.listRules(anyObject())).thenThrow(new RuleExecutionFailedExeption());
        assertThatThrownBy( 
                () -> cloudWatchEventsForAllAccountsRule.execute(CommonTestUtils.getMapString("r_123 "),CommonTestUtils.getMapString("r_123 "))).isInstanceOf(InvalidInputException.class);
        
        
        when(PacmanUtils.doesAllHaveValue(anyString(),anyString(),anyString())).thenReturn(
                false);
        assertThatThrownBy(
                () -> cloudWatchEventsForAllAccountsRule.execute(CommonTestUtils.getMapString("r_123 "),CommonTestUtils.getMapString("r_123 "))).isInstanceOf(InvalidInputException.class);
    }
  
    
    @Test
    public void getHelpTextTest(){
        assertThat(cloudWatchEventsForAllAccountsRule.getHelpText(), is(notNullValue()));
    }

}
