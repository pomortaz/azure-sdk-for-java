/**
 * 
 * Copyright (c) Microsoft and contributors.  All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

// Warning: This code was generated by a tool.
// 
// Changes to this file may cause incorrect behavior and will be lost if the
// code is regenerated.

package com.microsoft.windowsazure.management.websites.models;

import java.util.ArrayList;

/**
* Parameters supplied to the Update Web Site operation.
*/
public class WebSiteUpdateParameters
{
    private WebSpaceAvailabilityState availabilityState;
    
    /**
    * The state of the availability of management information for the site.
    * Possible values are Normal or Limited. Normal means that the site is
    * running correctly and that management information for the site is
    * available. Limited means that only partial management information for
    * the site is available and that detailed site information is unavailable.
    */
    public WebSpaceAvailabilityState getAvailabilityState()
    {
        return this.availabilityState;
    }
    
    /**
    * The state of the availability of management information for the site.
    * Possible values are Normal or Limited. Normal means that the site is
    * running correctly and that management information for the site is
    * available. Limited means that only partial management information for
    * the site is available and that detailed site information is unavailable.
    */
    public void setAvailabilityState(WebSpaceAvailabilityState availabilityState)
    {
        this.availabilityState = availabilityState;
    }
    
    private WebSiteComputeMode computeMode;
    
    /**
    * The Compute Mode for the web site. Possible values are Shared or
    * Dedicated.
    */
    public WebSiteComputeMode getComputeMode()
    {
        return this.computeMode;
    }
    
    /**
    * The Compute Mode for the web site. Possible values are Shared or
    * Dedicated.
    */
    public void setComputeMode(WebSiteComputeMode computeMode)
    {
        this.computeMode = computeMode;
    }
    
    private Boolean enabled;
    
    /**
    * true if the site is enabled; otherwise, false. Setting this value to
    * false disables the site (takes the site off line).
    */
    public Boolean isEnabled()
    {
        return this.enabled;
    }
    
    /**
    * true if the site is enabled; otherwise, false. Setting this value to
    * false disables the site (takes the site off line).
    */
    public void setEnabled(Boolean enabled)
    {
        this.enabled = enabled;
    }
    
    private ArrayList<String> hostNames;
    
    /**
    * An array of strings that contains the public hostnames for the site,
    * including custom domains. Important: When you add a custom domain in a
    * PUT operation, be sure to include every hostname that you want for the
    * web site. To delete a custom domain name in a PUT operation, include all
    * of the hostnames for the site that you want to keep, but leave out the
    * one that you wangt to delete.
    */
    public ArrayList<String> getHostNames()
    {
        return this.hostNames;
    }
    
    /**
    * An array of strings that contains the public hostnames for the site,
    * including custom domains. Important: When you add a custom domain in a
    * PUT operation, be sure to include every hostname that you want for the
    * web site. To delete a custom domain name in a PUT operation, include all
    * of the hostnames for the site that you want to keep, but leave out the
    * one that you wangt to delete.
    */
    public void setHostNames(ArrayList<String> hostNames)
    {
        this.hostNames = hostNames;
    }
    
    private ArrayList<WebSiteUpdateParameters.WebSiteHostNameSslState> hostNameSslStates;
    
    /**
    * SSL states bound to the website.
    */
    public ArrayList<WebSiteUpdateParameters.WebSiteHostNameSslState> getHostNameSslStates()
    {
        return this.hostNameSslStates;
    }
    
    /**
    * SSL states bound to the website.
    */
    public void setHostNameSslStates(ArrayList<WebSiteUpdateParameters.WebSiteHostNameSslState> hostNameSslStates)
    {
        this.hostNameSslStates = hostNameSslStates;
    }
    
    private WebSiteRuntimeAvailabilityState runtimeAvailabilityState;
    
    /**
    * Possible values are Normal, Degraded, or NotAvailable. Normal: the web
    * site is running correctly. Degraded: the web site is running temporarily
    * in a degraded mode (typically with less memory and a shared instance.)
    * Not Available: due to an unexpected issue, the site has been excluded
    * from provisioning. This typically occurs only for free sites.
    */
    public WebSiteRuntimeAvailabilityState getRuntimeAvailabilityState()
    {
        return this.runtimeAvailabilityState;
    }
    
    /**
    * Possible values are Normal, Degraded, or NotAvailable. Normal: the web
    * site is running correctly. Degraded: the web site is running temporarily
    * in a degraded mode (typically with less memory and a shared instance.)
    * Not Available: due to an unexpected issue, the site has been excluded
    * from provisioning. This typically occurs only for free sites.
    */
    public void setRuntimeAvailabilityState(WebSiteRuntimeAvailabilityState runtimeAvailabilityState)
    {
        this.runtimeAvailabilityState = runtimeAvailabilityState;
    }
    
    private String serverFarm;
    
    /**
    * String. If a server farm exists, this value is DefaultServerFarm.
    */
    public String getServerFarm()
    {
        return this.serverFarm;
    }
    
    /**
    * String. If a server farm exists, this value is DefaultServerFarm.
    */
    public void setServerFarm(String serverFarm)
    {
        this.serverFarm = serverFarm;
    }
    
    private WebSiteMode siteMode;
    
    /**
    * String that represents the web site mode. If the web site mode is Free,
    * this value is Limited. If the web site mode is Shared, this value is
    * Basic.  Note: The SiteMode value is not used for Reserved mode. Reserved
    * mode uses the ComputeMode setting.
    */
    public WebSiteMode getSiteMode()
    {
        return this.siteMode;
    }
    
    /**
    * String that represents the web site mode. If the web site mode is Free,
    * this value is Limited. If the web site mode is Shared, this value is
    * Basic.  Note: The SiteMode value is not used for Reserved mode. Reserved
    * mode uses the ComputeMode setting.
    */
    public void setSiteMode(WebSiteMode siteMode)
    {
        this.siteMode = siteMode;
    }
    
    private ArrayList<WebSiteUpdateParameters.WebSiteSslCertificate> sslCertificates;
    
    /**
    * SSL certificates bound to the web site.
    */
    public ArrayList<WebSiteUpdateParameters.WebSiteSslCertificate> getSslCertificates()
    {
        return this.sslCertificates;
    }
    
    /**
    * SSL certificates bound to the web site.
    */
    public void setSslCertificates(ArrayList<WebSiteUpdateParameters.WebSiteSslCertificate> sslCertificates)
    {
        this.sslCertificates = sslCertificates;
    }
    
    private WebSiteState state;
    
    /**
    * A string that describes the state of the web site. Possible values are
    * Stopped or Running.
    */
    public WebSiteState getState()
    {
        return this.state;
    }
    
    /**
    * A string that describes the state of the web site. Possible values are
    * Stopped or Running.
    */
    public void setState(WebSiteState state)
    {
        this.state = state;
    }
    
    /**
    * Initializes a new instance of the WebSiteUpdateParameters class.
    *
    */
    public WebSiteUpdateParameters()
    {
        this.hostNames = new ArrayList<String>();
        this.hostNameSslStates = new ArrayList<WebSiteUpdateParameters.WebSiteHostNameSslState>();
        this.sslCertificates = new ArrayList<WebSiteUpdateParameters.WebSiteSslCertificate>();
    }
    
    /**
    * SSL states bound to a website.
    */
    public static class WebSiteHostNameSslState
    {
        private WebSiteSslState sslState;
        
        /**
        * The SSL state. Possible values are Disabled, SniEnabled, or
        * IpBasedEnabled.
        */
        public WebSiteSslState getSslState()
        {
            return this.sslState;
        }
        
        /**
        * The SSL state. Possible values are Disabled, SniEnabled, or
        * IpBasedEnabled.
        */
        public void setSslState(WebSiteSslState sslState)
        {
            this.sslState = sslState;
        }
        
        private String thumbprint;
        
        /**
        * A string that contains the thumbprint of the SSL certificate.
        */
        public String getThumbprint()
        {
            return this.thumbprint;
        }
        
        /**
        * A string that contains the thumbprint of the SSL certificate.
        */
        public void setThumbprint(String thumbprint)
        {
            this.thumbprint = thumbprint;
        }
        
        private Boolean toUpdate;
        
        public Boolean isToUpdate()
        {
            return this.toUpdate;
        }
        
        public void setToUpdate(Boolean toUpdate)
        {
            this.toUpdate = toUpdate;
        }
    }
    
    /**
    * Contains SSL certificate properties.
    */
    public static class WebSiteSslCertificate
    {
        private Boolean isToBeDeleted;
        
        /**
        * Boolean. true if the certificate is to be deleted.
        */
        public Boolean isToBeDeleted()
        {
            return this.isToBeDeleted;
        }
        
        /**
        * Boolean. true if the certificate is to be deleted.
        */
        public void setIsToBeDeleted(Boolean isToBeDeleted)
        {
            this.isToBeDeleted = isToBeDeleted;
        }
        
        private String password;
        
        /**
        * A string that contains the password for the certificate.
        */
        public String getPassword()
        {
            return this.password;
        }
        
        /**
        * A string that contains the password for the certificate.
        */
        public void setPassword(String password)
        {
            this.password = password;
        }
        
        private byte[] pfxBlob;
        
        /**
        * A base64Binary value that contains the PfxBlob of the certificate.
        */
        public byte[] getPfxBlob()
        {
            return this.pfxBlob;
        }
        
        /**
        * A base64Binary value that contains the PfxBlob of the certificate.
        */
        public void setPfxBlob(byte[] pfxBlob)
        {
            this.pfxBlob = pfxBlob;
        }
        
        private String thumbprint;
        
        /**
        * A string that contains the certificate thumbprint.
        */
        public String getThumbprint()
        {
            return this.thumbprint;
        }
        
        /**
        * A string that contains the certificate thumbprint.
        */
        public void setThumbprint(String thumbprint)
        {
            this.thumbprint = thumbprint;
        }
    }
}