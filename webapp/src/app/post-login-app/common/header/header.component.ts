import { Component, OnInit } from "@angular/core";
import { MatIconRegistry } from "@angular/material";
import { DomSanitizer } from "@angular/platform-browser";
import { ActivatedRoute, Router } from "@angular/router";
import { DataCacheService } from "../../../core/services/data-cache.service";
import { PermissionGuardService } from "../../../core/services/permission-guard.service";
import { LoggerService } from "../../../shared/services/logger.service";

@Component({
  selector: "app-header",
  templateUrl: "./header.component.html",
  styleUrls: ["./header.component.css"],
})
export class HeaderComponent implements OnInit {
  showUserInfo = false;
  haveAdminPageAccess = false;
  FirstName: string;
  userType;
  profilePictureSrc: any = "/assets/icons/profile-picture.svg";
  queryParams;

  constructor(
    private router: Router,
    private route: ActivatedRoute,
    private dataCacheService: DataCacheService,
    private permissions: PermissionGuardService,
    private loggerService: LoggerService,
    private matIconRegistry: MatIconRegistry,
    private domSanitizer: DomSanitizer
  ) {
    this.matIconRegistry.addSvgIcon(
      `customSearchIcon`,
      this.domSanitizer.bypassSecurityTrustResourceUrl(
        "/assets/icons/header-search.svg"
      )
    );
  }

  ngOnInit() {
    try {
      this.haveAdminPageAccess = this.permissions.checkAdminPermission();
      this.userType = this.haveAdminPageAccess ? "Admin" : "";
      this.FirstName = "Guest";
      const detailsData = this.dataCacheService.getUserDetailsValue();
      const firstNameData = detailsData.getFirstName();
      if (firstNameData) {
        this.FirstName = firstNameData;
      }
      this.route.queryParams.subscribe((params) => {
        this.queryParams = params;
      });

      this.getProfilePictureOfUser();
    } catch (error) {
      this.loggerService.log("error", "JS Error" + error);
    }
  }

  handleSearch() {
    this.router
      .navigate(["/pl/omnisearch/omni-search-page"], {
        queryParams: this.queryParams,
      })
      .then((response) => {
        // Clearig page levels.
      });
  }

  closeUserInfo() {
    try {
      const x = this;
      setTimeout(function () {
        x.showUserInfo = false;
      }, 300);
    } catch (error) {
      this.loggerService.log("error", error);
    }
  }

  getProfilePictureOfUser() {
    // Get profile picture of user from azure ad.
    // this.adalService.acquireToken(CONFIGURATIONS.optional.auth.resource).subscribe(token => {
    //     const api = environment.fetchProfilePic.url;
    //     const httpMethod = environment.fetchProfilePic.method;
    //     const header = new HttpHeaders();
    //     const updatedHeader = header.append('Authorization', 'Bearer ' + token);
    //     this.httpResponseService.getBlobHttpResponse(api, httpMethod, {}, {}, {headers: updatedHeader}).subscribe(response => {
    //         this.utilService.generateBase64String(response).subscribe(image => {
    //             this.loggerService.log('info', 'user profile pic received');
    //             this.dataCacheService.setUserProfileImage(image);
    //             this.profilePictureSrc = image;
    //         });
    //     },
    //     error => {
    //         this.loggerService.log('error', 'error while fetching image from azure ad - ' + error);
    //     });
    // }, error => {
    //     this.loggerService.log('error', 'Error while fetching access token for resource - ' + error);
    // });
  }
}
