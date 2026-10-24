// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.inql;

import java.io.Serializable;

public class PoiFinding_littlespidy implements Serializable {
    private static final long serialVersionUID = 1L;

    private String category;
    private String typeName;
    private String fieldName;
    private String returnType;
    private String matchedKeyword;

    public PoiFinding_littlespidy() {}

    public PoiFinding_littlespidy(String category, String typeName, String fieldName, String returnType, String matchedKeyword) {
        this.category = category;
        this.typeName = typeName;
        this.fieldName = fieldName;
        this.returnType = returnType;
        this.matchedKeyword = matchedKeyword;
    }

    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }

    public String getTypeName() { return typeName; }
    public void setTypeName(String typeName) { this.typeName = typeName; }

    public String getFieldName() { return fieldName; }
    public void setFieldName(String fieldName) { this.fieldName = fieldName; }

    public String getReturnType() { return returnType; }
    public void setReturnType(String returnType) { this.returnType = returnType; }

    public String getMatchedKeyword() { return matchedKeyword; }
    public void setMatchedKeyword(String matchedKeyword) { this.matchedKeyword = matchedKeyword; }
}
