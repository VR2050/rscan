package com.litesuits.orm.db.model;

import com.litesuits.orm.db.enums.Relation;
import java.lang.reflect.Field;

/* JADX INFO: loaded from: classes3.dex */
public class MapProperty extends Property {
    public static final String PRIMARYKEY = " PRIMARY KEY ";
    private static final long serialVersionUID = 1641409866866426637L;
    public Relation relation;

    public MapProperty(Property p, Relation relation) {
        this(p.column, p.field, relation);
    }

    private MapProperty(String column, Field field, Relation relation) {
        super(column, field);
        this.relation = relation;
    }

    public boolean isToMany() {
        return this.relation == Relation.ManyToMany || this.relation == Relation.OneToMany;
    }

    public boolean isToOne() {
        return this.relation == Relation.ManyToOne || this.relation == Relation.OneToOne;
    }
}
