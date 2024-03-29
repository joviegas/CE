/*
 *Copyright 2018 T Mobile, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); You may not use
 * this file except in compliance with the License. A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { HttpClientTestingModule } from '@angular/common/http/testing';
import { async, ComponentFixture, TestBed } from '@angular/core/testing';
import { RouterTestingModule } from '@angular/router/testing';
import { AssetGroupObservableService } from 'src/app/core/services/asset-group-observable.service';
import { DataCacheService } from 'src/app/core/services/data-cache.service';
import { DomainTypeObservableService } from 'src/app/core/services/domain-type-observable.service';
import { WorkflowService } from 'src/app/core/services/workflow.service';
import { AllPatchingTableComponent } from 'src/app/pacman-features/secondary-components/all-patching-table/all-patching-table.component';
import { PatchingCurrentStateComponent } from 'src/app/pacman-features/secondary-components/patching-current-state/patching-current-state.component';
import { PatchingIssueComponent } from 'src/app/pacman-features/secondary-components/patching-issue/patching-issue.component';
import { PatchingTrendComponent } from 'src/app/pacman-features/secondary-components/patching-trend/patching-trend.component';
import { SelectComplianceDropdown } from 'src/app/pacman-features/services/select-compliance-dropdown.service';
import { ToastObservableService } from 'src/app/post-login-app/common/services/toast-observable.service';
import { BreadcrumbComponent } from 'src/app/shared/breadcrumb/breadcrumb.component';
import { TextComponent } from 'src/app/shared/components/atoms/text/text.component';
import { DataTableComponent } from 'src/app/shared/data-table/data-table.component';
import { DownloadService } from 'src/app/shared/services/download.service';
import { ErrorHandlingService } from 'src/app/shared/services/error-handling.service';
import { HttpService } from 'src/app/shared/services/http-response.service';
import { LoggerService } from 'src/app/shared/services/logger.service';
import { RefactorFieldsService } from 'src/app/shared/services/refactor-fields.service';
import { RouterUtilityService } from 'src/app/shared/services/router-utility.service';
import { UtilsService } from 'src/app/shared/services/utils.service';
import { TitleBurgerHeadComponent } from 'src/app/shared/title-burger-head/title-burger-head.component';

import { PatchingComplianceComponent } from './patching-compliance.component';

describe('PatchingComplianceComponent', () => {
    let component: PatchingComplianceComponent;
    let fixture: ComponentFixture<PatchingComplianceComponent>;

    beforeEach(async(() => {
        TestBed.configureTestingModule({
            imports: [HttpClientTestingModule, RouterTestingModule],
            declarations: [
                PatchingComplianceComponent,
                AllPatchingTableComponent,
                BreadcrumbComponent,
                DataTableComponent,
                PatchingIssueComponent,
                PatchingTrendComponent,
                PatchingCurrentStateComponent,
                TextComponent,
                TitleBurgerHeadComponent,
            ],
            providers: [
                AssetGroupObservableService,
                DataCacheService,
                DomainTypeObservableService,
                DownloadService,
                ErrorHandlingService,
                HttpService,
                LoggerService,
                RefactorFieldsService,
                RouterUtilityService,
                SelectComplianceDropdown,
                ToastObservableService,
                UtilsService,
                WorkflowService,
            ],
        }).compileComponents();
    }));

    beforeEach(() => {
        fixture = TestBed.createComponent(PatchingComplianceComponent);
        component = fixture.componentInstance;
        fixture.detectChanges();
    });

    it('should create', () => {
        expect(component).toBeTruthy();
    });
});
