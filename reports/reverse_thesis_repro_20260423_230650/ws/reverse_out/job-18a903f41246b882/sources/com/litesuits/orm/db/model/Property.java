package com.litesuits.orm.db.model;

import com.litesuits.orm.db.utils.DataUtil;
import java.io.Serializable;
import java.lang.reflect.Field;

/* JADX INFO: loaded from: classes3.dex */
public class Property implements Serializable {
    private static final long serialVersionUID = 1542861322620643038L;
    public int classType;
    public String column;
    public Field field;

    public Property(String column, Field field) {
        this.classType = 0;
        this.column = column;
        this.field = field;
        if (0 <= 0) {
            this.classType = DataUtil.getFieldClassType(field);
        }
    }

    public Property(String column, Field field, int classType) {
        this.classType = 0;
        this.column = column;
        this.field = field;
        if (classType <= 0) {
            this.classType = DataUtil.getFieldClassType(field);
        }
        this.classType = classType;
    }

    public String toString() {
        return "Property{column='" + this.column + "', field=" + this.field + ", classType=" + this.classType + '}';
    }
}
