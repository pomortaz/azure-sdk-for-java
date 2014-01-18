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

package com.microsoft.windowsazure.management.monitoring.alerts.models;

import java.util.Calendar;

/**
* An alert incident indicates the activation status of an alert rule.
*/
public class Incident
{
    private Calendar activatedTime;
    
    /**
    * The time at which the incident got activated.
    */
    public Calendar getActivatedTime()
    {
        return this.activatedTime;
    }
    
    /**
    * The time at which the incident got activated.
    */
    public void setActivatedTime(Calendar activatedTime)
    {
        this.activatedTime = activatedTime;
    }
    
    private String id;
    
    /**
    * Incident identifier.
    */
    public String getId()
    {
        return this.id;
    }
    
    /**
    * Incident identifier.
    */
    public void setId(String id)
    {
        this.id = id;
    }
    
    private boolean isActive;
    
    /**
    * A boolean to indicate whether the incident is active or resolved.
    */
    public boolean isActive()
    {
        return this.isActive;
    }
    
    /**
    * A boolean to indicate whether the incident is active or resolved.
    */
    public void setIsActive(boolean isActive)
    {
        this.isActive = isActive;
    }
    
    private Calendar resolvedTime;
    
    /**
    * The time at which the incident got resolved. If null, it means the
    * incident is still active.
    */
    public Calendar getResolvedTime()
    {
        return this.resolvedTime;
    }
    
    /**
    * The time at which the incident got resolved. If null, it means the
    * incident is still active.
    */
    public void setResolvedTime(Calendar resolvedTime)
    {
        this.resolvedTime = resolvedTime;
    }
    
    private String ruleId;
    
    /**
    * Rule identifier that is associated with the incident.
    */
    public String getRuleId()
    {
        return this.ruleId;
    }
    
    /**
    * Rule identifier that is associated with the incident.
    */
    public void setRuleId(String ruleId)
    {
        this.ruleId = ruleId;
    }
}