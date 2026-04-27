package com.litesuits.orm.db.assit;

import com.litesuits.orm.db.TableManager;
import java.util.regex.Pattern;

/* JADX INFO: loaded from: classes3.dex */
public class QueryBuilder<T> {
    public static final String AND = " AND ";
    public static final String ASC = " ASC";
    public static final String ASTERISK = "*";
    public static final String COMMA = ",";
    public static final String COMMA_HOLDER = ",?";
    public static final String DESC = " DESC";
    public static final String DISTINCT = " DISTINCT ";
    public static final String EQUAL_HOLDER = "=?";
    public static final String FROM = " FROM ";
    public static final String GROUP_BY = " GROUP BY ";
    public static final String HAVING = " HAVING ";
    public static final String LIMIT = " LIMIT ";
    public static final String OR = " OR ";
    public static final String ORDER_BY = " ORDER BY ";
    public static final String SELECT = "SELECT ";
    public static final String SELECT_COUNT = "SELECT COUNT(*) FROM ";
    private static final Pattern limitPattern = Pattern.compile("\\s*\\d+\\s*(,\\s*\\d+\\s*)?");
    protected Class<T> clazz;
    protected Class clazzMapping;
    protected String[] columns;
    protected boolean distinct;
    protected String group;
    protected String having;
    protected String limit;
    protected String order;
    protected WhereBuilder whereBuilder;

    public Class<T> getQueryClass() {
        return this.clazz;
    }

    public QueryBuilder(Class<T> claxx) {
        this.clazz = claxx;
        this.whereBuilder = new WhereBuilder(claxx);
    }

    public static <T> QueryBuilder<T> create(Class<T> claxx) {
        return new QueryBuilder<>(claxx);
    }

    public QueryBuilder<T> where(WhereBuilder builder) {
        this.whereBuilder = builder;
        return this;
    }

    public WhereBuilder getwhereBuilder() {
        return this.whereBuilder;
    }

    public QueryBuilder<T> where(String where, Object... whereArgs) {
        this.whereBuilder.where(where, whereArgs);
        return this;
    }

    public QueryBuilder<T> whereAppend(String where, Object... whereArgs) {
        this.whereBuilder.append(null, where, whereArgs);
        return this;
    }

    public QueryBuilder<T> whereAnd(String where, Object... whereArgs) {
        this.whereBuilder.and(where, whereArgs);
        return this;
    }

    public QueryBuilder<T> whereOr(String where, Object... whereArgs) {
        this.whereBuilder.or(where, whereArgs);
        return this;
    }

    public QueryBuilder<T> whereAppendAnd() {
        this.whereBuilder.and();
        return this;
    }

    public QueryBuilder<T> whereAppendOr() {
        this.whereBuilder.or();
        return this;
    }

    public QueryBuilder<T> whereAppendNot() {
        this.whereBuilder.not();
        return this;
    }

    public QueryBuilder<T> whereNoEquals(String column, Object value) {
        this.whereBuilder.noEquals(column, value);
        return this;
    }

    public QueryBuilder<T> whereGreaterThan(String column, Object value) {
        this.whereBuilder.greaterThan(column, value);
        return this;
    }

    public QueryBuilder<T> whereLessThan(String column, Object value) {
        this.whereBuilder.lessThan(column, value);
        return this;
    }

    public QueryBuilder<T> whereEquals(String column, Object value) {
        this.whereBuilder.equals(column, value);
        return this;
    }

    public QueryBuilder<T> whereIn(String column, Object... values) {
        this.whereBuilder.in(column, values);
        return this;
    }

    public QueryBuilder<T> columns(String[] columns) {
        this.columns = columns;
        return this;
    }

    public QueryBuilder<T> appendColumns(String[] columns) {
        String[] strArr = this.columns;
        if (strArr != null) {
            String[] newCols = new String[strArr.length + columns.length];
            System.arraycopy(strArr, 0, newCols, 0, strArr.length);
            System.arraycopy(columns, 0, newCols, this.columns.length, columns.length);
            this.columns = newCols;
        } else {
            this.columns = columns;
        }
        return this;
    }

    public QueryBuilder<T> distinct(boolean distinct) {
        this.distinct = distinct;
        return this;
    }

    public QueryBuilder<T> groupBy(String group) {
        this.group = group;
        return this;
    }

    public QueryBuilder<T> having(String having) {
        this.having = having;
        return this;
    }

    public QueryBuilder<T> orderBy(String order) {
        this.order = order;
        return this;
    }

    public QueryBuilder<T> appendOrderAscBy(String column) {
        if (this.order == null) {
            this.order = column + ASC;
        } else {
            this.order += ", " + column + ASC;
        }
        return this;
    }

    public QueryBuilder<T> appendOrderDescBy(String column) {
        if (this.order == null) {
            this.order = column + DESC;
        } else {
            this.order += ", " + column + DESC;
        }
        return this;
    }

    public QueryBuilder<T> limit(String limit) {
        this.limit = limit;
        return this;
    }

    public QueryBuilder<T> limit(int start, int length) {
        this.limit = start + "," + length;
        return this;
    }

    public QueryBuilder<T> queryMappingInfo(Class clazzMapping) {
        this.clazzMapping = clazzMapping;
        return this;
    }

    public SQLStatement createStatement() {
        if (this.clazz == null) {
            throw new IllegalArgumentException("U Must Set A Query Entity Class By queryWho(Class) or QueryBuilder(Class)");
        }
        if (Checker.isEmpty(this.group) && !Checker.isEmpty(this.having)) {
            throw new IllegalArgumentException("HAVING仅允许在有GroupBy的时候使用(HAVING clauses are only permitted when using a groupBy clause)");
        }
        if (!Checker.isEmpty(this.limit) && !limitPattern.matcher(this.limit).matches()) {
            throw new IllegalArgumentException("invalid LIMIT clauses:" + this.limit);
        }
        StringBuilder query = new StringBuilder(120);
        query.append("SELECT ");
        if (this.distinct) {
            query.append(DISTINCT);
        }
        if (!Checker.isEmpty(this.columns)) {
            appendColumns(query, this.columns);
        } else {
            query.append("*");
        }
        query.append(" FROM ");
        query.append(getTableName());
        query.append(this.whereBuilder.createWhereString());
        appendClause(query, GROUP_BY, this.group);
        appendClause(query, HAVING, this.having);
        appendClause(query, " ORDER BY ", this.order);
        appendClause(query, " LIMIT ", this.limit);
        SQLStatement stmt = new SQLStatement();
        stmt.sql = query.toString();
        stmt.bindArgs = this.whereBuilder.transToStringArray();
        return stmt;
    }

    public SQLStatement createStatementForCount() {
        StringBuilder query = new StringBuilder(120);
        query.append(SELECT_COUNT);
        query.append(getTableName());
        SQLStatement stmt = new SQLStatement();
        WhereBuilder whereBuilder = this.whereBuilder;
        if (whereBuilder != null) {
            query.append(whereBuilder.createWhereString());
            stmt.bindArgs = this.whereBuilder.transToStringArray();
        }
        stmt.sql = query.toString();
        return stmt;
    }

    public String getTableName() {
        Class cls = this.clazzMapping;
        if (cls == null) {
            return TableManager.getTableName(this.clazz);
        }
        return TableManager.getMapTableName(this.clazz, cls);
    }

    private static void appendClause(StringBuilder s, String name, String clause) {
        if (!Checker.isEmpty(clause)) {
            s.append(name);
            s.append(clause);
        }
    }

    private static void appendColumns(StringBuilder s, String[] columns) {
        int n = columns.length;
        for (int i = 0; i < n; i++) {
            String column = columns[i];
            if (column != null) {
                if (i > 0) {
                    s.append(",");
                }
                s.append(column);
            }
        }
        s.append(" ");
    }

    private String buildWhereIn(String column, int num) {
        StringBuilder sb = new StringBuilder(column).append(" IN (?");
        for (int i = 1; i < num; i++) {
            sb.append(",?");
        }
        sb.append(SQLBuilder.PARENTHESES_RIGHT);
        return sb.toString();
    }
}
