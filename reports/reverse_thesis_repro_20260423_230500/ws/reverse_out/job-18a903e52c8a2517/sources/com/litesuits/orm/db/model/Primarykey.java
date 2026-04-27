package com.litesuits.orm.db.model;

import com.litesuits.orm.db.enums.AssignType;
import java.lang.reflect.Field;

/* JADX INFO: loaded from: classes3.dex */
public class Primarykey extends Property {
    private static final long serialVersionUID = 2304252505493855513L;
    public AssignType assign;

    public Primarykey(Property p, AssignType assign) {
        this(p.column, p.field, p.classType, assign);
    }

    public Primarykey(String column, Field field, int classType, AssignType assign) {
        super(column, field, classType);
        this.assign = assign;
    }

    public boolean isAssignedBySystem() {
        return this.assign == AssignType.AUTO_INCREMENT;
    }

    public boolean isAssignedByMyself() {
        return this.assign == AssignType.BY_MYSELF;
    }
}
