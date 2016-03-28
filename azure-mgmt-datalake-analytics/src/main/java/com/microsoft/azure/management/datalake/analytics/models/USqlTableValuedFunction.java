/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 *
 * Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
 * Changes may cause incorrect behavior and will be lost if the code is
 * regenerated.
 */

package com.microsoft.azure.management.datalake.analytics.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A Data Lake Analytics catalog U-SQL table valued function item.
 */
public class USqlTableValuedFunction extends CatalogItem {
    /**
     * Gets or sets the name of the database.
     */
    private String databaseName;

    /**
     * Gets or sets the name of the schema associated with this database.
     */
    private String schemaName;

    /**
     * Gets or sets the name of the table valued function.
     */
    @JsonProperty(value = "tvfName")
    private String name;

    /**
     * Gets or sets the definition of the table valued function.
     */
    private String definition;

    /**
     * Get the databaseName value.
     *
     * @return the databaseName value
     */
    public String getDatabaseName() {
        return this.databaseName;
    }

    /**
     * Set the databaseName value.
     *
     * @param databaseName the databaseName value to set
     */
    public void setDatabaseName(String databaseName) {
        this.databaseName = databaseName;
    }

    /**
     * Get the schemaName value.
     *
     * @return the schemaName value
     */
    public String getSchemaName() {
        return this.schemaName;
    }

    /**
     * Set the schemaName value.
     *
     * @param schemaName the schemaName value to set
     */
    public void setSchemaName(String schemaName) {
        this.schemaName = schemaName;
    }

    /**
     * Get the name value.
     *
     * @return the name value
     */
    public String getName() {
        return this.name;
    }

    /**
     * Set the name value.
     *
     * @param name the name value to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get the definition value.
     *
     * @return the definition value
     */
    public String getDefinition() {
        return this.definition;
    }

    /**
     * Set the definition value.
     *
     * @param definition the definition value to set
     */
    public void setDefinition(String definition) {
        this.definition = definition;
    }

}