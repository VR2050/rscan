package com.litesuits.orm.db.model;

import com.litesuits.orm.db.assit.Checker;
import com.litesuits.orm.db.assit.SQLStatement;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes3.dex */
public class MapInfo {
    public ArrayList<SQLStatement> delOldRelationSQL;
    public ArrayList<SQLStatement> mapNewRelationSQL;
    public ArrayList<MapTable> tableList;

    public static class MapTable {
        public String column1;
        public String column2;
        public String name;

        public MapTable(String name, String col1, String col2) {
            this.name = name;
            this.column1 = col1;
            this.column2 = col2;
        }
    }

    public boolean addTable(MapTable table) {
        if (table.name == null) {
            return false;
        }
        if (this.tableList == null) {
            this.tableList = new ArrayList<>();
        }
        return this.tableList.add(table);
    }

    public boolean addNewRelationSQL(SQLStatement st) {
        if (this.mapNewRelationSQL == null) {
            this.mapNewRelationSQL = new ArrayList<>();
        }
        return this.mapNewRelationSQL.add(st);
    }

    public boolean addNewRelationSQL(ArrayList<SQLStatement> list) {
        if (this.mapNewRelationSQL == null) {
            this.mapNewRelationSQL = new ArrayList<>();
        }
        return this.mapNewRelationSQL.addAll(list);
    }

    public boolean addDelOldRelationSQL(SQLStatement st) {
        if (this.delOldRelationSQL == null) {
            this.delOldRelationSQL = new ArrayList<>();
        }
        return this.delOldRelationSQL.add(st);
    }

    public boolean isEmpty() {
        return Checker.isEmpty(this.tableList) || (Checker.isEmpty(this.mapNewRelationSQL) && Checker.isEmpty(this.delOldRelationSQL));
    }
}
