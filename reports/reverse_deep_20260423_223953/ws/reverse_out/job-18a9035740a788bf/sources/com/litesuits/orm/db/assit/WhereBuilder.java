package com.litesuits.orm.db.assit;

import com.litesuits.orm.db.TableManager;

/* JADX INFO: loaded from: classes3.dex */
public class WhereBuilder {
    public static final String AND = " AND ";
    public static final String COMMA_HOLDER = ",?";
    public static final String DELETE = "DELETE FROM ";
    public static final String EQUAL_HOLDER = "=?";
    public static final String GREATER_THAN_HOLDER = ">?";
    public static final String HOLDER = "?";
    private static final String IN = " IN ";
    public static final String LESS_THAN_HOLDER = "<?";
    public static final String NOT = " NOT ";
    public static final String NOTHING = "";
    public static final String NOT_EQUAL_HOLDER = "!=?";
    public static final String OR = " OR ";
    private static final String PARENTHESES_LEFT = "(";
    private static final String PARENTHESES_RIGHT = ")";
    public static final String WHERE = " WHERE ";
    protected Class tableClass;
    protected String where;
    protected Object[] whereArgs;

    public WhereBuilder(Class tableClass) {
        this.tableClass = tableClass;
    }

    public static WhereBuilder create(Class tableClass) {
        return new WhereBuilder(tableClass);
    }

    public static WhereBuilder create(Class tableClass, String where, Object[] whereArgs) {
        return new WhereBuilder(tableClass, where, whereArgs);
    }

    public WhereBuilder(Class tableClass, String where, Object[] whereArgs) {
        this.where = where;
        this.whereArgs = whereArgs;
        this.tableClass = tableClass;
    }

    public Class getTableClass() {
        return this.tableClass;
    }

    public WhereBuilder where(String where, Object... whereArgs) {
        this.where = where;
        this.whereArgs = whereArgs;
        return this;
    }

    public WhereBuilder and(String where, Object... whereArgs) {
        return append(" AND ", where, whereArgs);
    }

    public WhereBuilder or(String where, Object... whereArgs) {
        return append(" OR ", where, whereArgs);
    }

    public WhereBuilder and() {
        if (this.where != null) {
            this.where += " AND ";
        }
        return this;
    }

    public WhereBuilder or() {
        if (this.where != null) {
            this.where += " OR ";
        }
        return this;
    }

    public WhereBuilder not() {
        if (this.where != null) {
            this.where += " NOT ";
        }
        return this;
    }

    public WhereBuilder noEquals(String column, Object value) {
        return append(null, column + NOT_EQUAL_HOLDER, value);
    }

    public WhereBuilder greaterThan(String column, Object value) {
        return append(null, column + GREATER_THAN_HOLDER, value);
    }

    public WhereBuilder lessThan(String column, Object value) {
        return append(null, column + LESS_THAN_HOLDER, value);
    }

    public WhereBuilder equals(String column, Object value) {
        return append(null, column + "=?", value);
    }

    public WhereBuilder orEquals(String column, Object value) {
        return append(" OR ", column + "=?", value);
    }

    public WhereBuilder andEquals(String column, Object value) {
        return append(" AND ", column + "=?", value);
    }

    public WhereBuilder in(String column, Object... values) {
        return append(null, buildWhereIn(column, values.length), values);
    }

    public WhereBuilder orIn(String column, Object... values) {
        return append(" OR ", buildWhereIn(column, values.length), values);
    }

    public WhereBuilder andIn(String column, Object... values) {
        return append(" AND ", buildWhereIn(column, values.length), values);
    }

    public WhereBuilder append(String connect, String whereString, Object... value) {
        if (this.where == null) {
            this.where = whereString;
            this.whereArgs = value;
        } else {
            if (connect != null) {
                this.where += connect;
            }
            this.where += whereString;
            Object[] objArr = this.whereArgs;
            if (objArr == null) {
                this.whereArgs = value;
            } else {
                Object[] newWhere = new Object[objArr.length + value.length];
                System.arraycopy(objArr, 0, newWhere, 0, objArr.length);
                System.arraycopy(value, 0, newWhere, this.whereArgs.length, value.length);
                this.whereArgs = newWhere;
            }
        }
        return this;
    }

    public String[] transToStringArray() {
        Object[] objArr = this.whereArgs;
        if (objArr != null && objArr.length > 0) {
            if (objArr instanceof String[]) {
                return (String[]) objArr;
            }
            String[] arr = new String[objArr.length];
            for (int i = 0; i < arr.length; i++) {
                arr[i] = String.valueOf(this.whereArgs[i]);
            }
            return arr;
        }
        return null;
    }

    public String createWhereString() {
        if (this.where != null) {
            return " WHERE " + this.where;
        }
        return "";
    }

    public SQLStatement createStatementDelete() {
        SQLStatement stmt = new SQLStatement();
        stmt.sql = "DELETE FROM " + TableManager.getTableName(this.tableClass) + createWhereString();
        stmt.bindArgs = transToStringArray();
        return stmt;
    }

    public String getWhere() {
        return this.where;
    }

    public void setWhere(String where) {
        this.where = where;
    }

    public Object[] getWhereArgs() {
        return this.whereArgs;
    }

    public void setWhereArgs(Object[] whereArgs) {
        this.whereArgs = whereArgs;
    }

    private String buildWhereIn(String column, int num) {
        StringBuilder sb = new StringBuilder(column);
        sb.append(" IN ");
        sb.append("(");
        StringBuilder sb2 = sb.append("?");
        for (int i = 1; i < num; i++) {
            sb2.append(",?");
        }
        sb2.append(")");
        return sb2.toString();
    }
}
