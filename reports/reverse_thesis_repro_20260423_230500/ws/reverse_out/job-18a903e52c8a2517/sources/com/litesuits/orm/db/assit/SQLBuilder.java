package com.litesuits.orm.db.assit;

import android.util.SparseArray;
import com.litesuits.orm.db.TableManager;
import com.litesuits.orm.db.annotation.Check;
import com.litesuits.orm.db.annotation.Collate;
import com.litesuits.orm.db.annotation.Conflict;
import com.litesuits.orm.db.annotation.Default;
import com.litesuits.orm.db.annotation.NotNull;
import com.litesuits.orm.db.annotation.Temporary;
import com.litesuits.orm.db.annotation.Unique;
import com.litesuits.orm.db.annotation.UniqueCombine;
import com.litesuits.orm.db.assit.CollSpliter;
import com.litesuits.orm.db.enums.AssignType;
import com.litesuits.orm.db.model.ColumnsValue;
import com.litesuits.orm.db.model.ConflictAlgorithm;
import com.litesuits.orm.db.model.EntityTable;
import com.litesuits.orm.db.model.MapInfo;
import com.litesuits.orm.db.model.MapProperty;
import com.litesuits.orm.db.model.Property;
import com.litesuits.orm.db.utils.ClassUtil;
import com.litesuits.orm.db.utils.DataUtil;
import com.litesuits.orm.db.utils.FieldUtil;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public class SQLBuilder {
    public static final String AND = " AND ";
    public static final String ASC = " ASC ";
    public static final String ASTERISK = "*";
    public static final String BLANK = " ";
    public static final String CHECK = "CHECK ";
    public static final String COLLATE = "COLLATE ";
    public static final String COMMA = ",";
    public static final String COMMA_HOLDER = ",?";
    public static final String CREATE = "CREATE ";
    public static final String DEFAULT = "DEFAULT ";
    public static final String DELETE_FROM = "DELETE FROM ";
    public static final String DESC = " DESC ";
    public static final String DROP_TABLE = "DROP TABLE ";
    public static final String EQUALS_HOLDER = "=?";
    public static final String FROM = " FROM ";
    public static final String HOLDER = "?";
    public static final String IN = " IN ";
    public static final String INSERT = "INSERT ";
    public static final String INTO = "INTO ";
    public static final String LIMIT = " LIMIT ";
    public static final String NOT = " NOT ";
    public static final String NOT_NULL = "NOT NULL ";
    public static final String ON_CONFLICT = "ON CONFLICT ";
    public static final String OR = " OR ";
    public static final String ORDER_BY = " ORDER BY ";
    public static final String PARENTHESES_LEFT = "(";
    public static final String PARENTHESES_RIGHT = ")";
    public static final String PRAGMA_TABLE_INFO = "PRAGMA table_info(";
    public static final String PRIMARY_KEY = "PRIMARY KEY ";
    public static final String PRIMARY_KEY_AUTOINCREMENT = "PRIMARY KEY AUTOINCREMENT ";
    public static final String REPLACE = "REPLACE ";
    public static final String SELECT = "SELECT ";
    public static final String SELECT_ANY_FROM = "SELECT * FROM ";
    public static final String SELECT_MAX = "SELECT MAX ";
    public static final String SELECT_TABLES = "SELECT * FROM sqlite_master WHERE type='table' ORDER BY name";
    public static final String SET = " SET ";
    public static final String TABLE_IF_NOT_EXISTS = "TABLE IF NOT EXISTS ";
    public static final String TEMP = "TEMP ";
    public static final String TWO_HOLDER = "(?,?)";
    public static final int TYPE_INSERT = 1;
    public static final int TYPE_REPLACE = 2;
    public static final int TYPE_UPDATE = 3;
    public static final String UNIQUE = "UNIQUE ";
    public static final String UPDATE = "UPDATE ";
    public static final String VALUES = "VALUES";
    public static final String WHERE = " WHERE ";

    public static SQLStatement buildTableObtainAll() {
        return new SQLStatement(SELECT_TABLES, null);
    }

    public static SQLStatement buildColumnsObtainAll(String table) {
        return new SQLStatement(PRAGMA_TABLE_INFO + table + PARENTHESES_RIGHT, null);
    }

    public static SQLStatement buildGetLastRowId(EntityTable table) {
        return new SQLStatement("SELECT MAX (" + table.key.column + PARENTHESES_RIGHT + " FROM " + table.name, null);
    }

    public static SQLStatement buildDropTable(EntityTable table) {
        return new SQLStatement(DROP_TABLE + table.name, null);
    }

    public static SQLStatement buildDropTable(String tableName) {
        return new SQLStatement(DROP_TABLE + tableName, null);
    }

    public static SQLStatement buildCreateTable(EntityTable table) {
        StringBuilder sb = new StringBuilder();
        sb.append(CREATE);
        if (table.getAnnotation(Temporary.class) != null) {
            sb.append(TEMP);
        }
        sb.append(TABLE_IF_NOT_EXISTS);
        sb.append(table.name);
        sb.append(PARENTHESES_LEFT);
        boolean hasKey = false;
        if (table.key != null) {
            hasKey = true;
            if (table.key.assign == AssignType.AUTO_INCREMENT) {
                sb.append(table.key.column);
                sb.append(DataUtil.INTEGER);
                sb.append(PRIMARY_KEY_AUTOINCREMENT);
            } else {
                sb.append(table.key.column);
                sb.append(DataUtil.getSQLDataType(table.key.classType));
                sb.append(PRIMARY_KEY);
            }
        }
        if (!Checker.isEmpty(table.pmap)) {
            if (hasKey) {
                sb.append(",");
            }
            boolean needComma = false;
            SparseArray<ArrayList<String>> combineUniqueMap = null;
            for (Map.Entry<String, Property> en : table.pmap.entrySet()) {
                if (needComma) {
                    sb.append(",");
                } else {
                    needComma = true;
                }
                String key = en.getKey();
                sb.append(key);
                if (en.getValue() == null) {
                    sb.append(DataUtil.TEXT);
                } else {
                    Field f = en.getValue().field;
                    sb.append(DataUtil.getSQLDataType(en.getValue().classType));
                    if (f.getAnnotation(NotNull.class) != null) {
                        sb.append(NOT_NULL);
                    }
                    if (f.getAnnotation(Default.class) != null) {
                        sb.append(DEFAULT);
                        sb.append(((Default) f.getAnnotation(Default.class)).value());
                        sb.append(" ");
                    }
                    if (f.getAnnotation(Unique.class) != null) {
                        sb.append(UNIQUE);
                    }
                    if (f.getAnnotation(Conflict.class) != null) {
                        sb.append(ON_CONFLICT);
                        sb.append(((Conflict) f.getAnnotation(Conflict.class)).value().getSql());
                        sb.append(" ");
                    }
                    if (f.getAnnotation(Check.class) != null) {
                        sb.append("CHECK (");
                        sb.append(((Check) f.getAnnotation(Check.class)).value());
                        sb.append(PARENTHESES_RIGHT);
                        sb.append(" ");
                    }
                    if (f.getAnnotation(Collate.class) != null) {
                        sb.append(COLLATE);
                        sb.append(((Collate) f.getAnnotation(Collate.class)).value());
                        sb.append(" ");
                    }
                    UniqueCombine uc = (UniqueCombine) f.getAnnotation(UniqueCombine.class);
                    if (uc != null) {
                        if (combineUniqueMap == null) {
                            combineUniqueMap = new SparseArray<>();
                        }
                        ArrayList<String> list = combineUniqueMap.get(uc.value());
                        if (list == null) {
                            list = new ArrayList<>();
                            combineUniqueMap.put(uc.value(), list);
                        }
                        list.add(key);
                    }
                }
            }
            if (combineUniqueMap != null) {
                int nsize = combineUniqueMap.size();
                for (int i = 0; i < nsize; i++) {
                    ArrayList<String> list2 = combineUniqueMap.valueAt(i);
                    if (list2.size() > 1) {
                        sb.append(",");
                        sb.append(UNIQUE);
                        sb.append(PARENTHESES_LEFT);
                        int size = list2.size();
                        for (int j = 0; j < size; j++) {
                            if (j != 0) {
                                sb.append(",");
                            }
                            sb.append(list2.get(j));
                        }
                        sb.append(PARENTHESES_RIGHT);
                    }
                }
            }
        }
        sb.append(PARENTHESES_RIGHT);
        return new SQLStatement(sb.toString(), null);
    }

    public static SQLStatement buildInsertSql(Object entity, ConflictAlgorithm algorithm) {
        return buildInsertSql(entity, true, 1, algorithm);
    }

    public static SQLStatement buildInsertAllSql(Object entity, ConflictAlgorithm algorithm) {
        return buildInsertSql(entity, false, 1, algorithm);
    }

    public static SQLStatement buildReplaceSql(Object entity) {
        return buildInsertSql(entity, true, 2, null);
    }

    public static SQLStatement buildReplaceAllSql(Object entity) {
        return buildInsertSql(entity, false, 2, null);
    }

    private static SQLStatement buildInsertSql(Object entity, boolean needValue, int type, ConflictAlgorithm algorithm) {
        SQLStatement stmt = new SQLStatement();
        try {
            EntityTable table = TableManager.getTable(entity);
            StringBuilder sql = new StringBuilder(128);
            if (type == 2) {
                sql.append(REPLACE);
                sql.append(INTO);
            } else {
                sql.append(INSERT);
                if (algorithm != null) {
                    sql.append(algorithm.getAlgorithm());
                    sql.append(INTO);
                } else {
                    sql.append(INTO);
                }
            }
            sql.append(table.name);
            sql.append(PARENTHESES_LEFT);
            sql.append(table.key.column);
            StringBuilder value = new StringBuilder();
            value.append(PARENTHESES_RIGHT);
            value.append(VALUES);
            value.append(PARENTHESES_LEFT);
            value.append("?");
            int i = 0;
            int size = Checker.isEmpty(table.pmap) ? 1 : 1 + table.pmap.size();
            Object[] args = null;
            if (needValue) {
                args = new Object[size];
                int i2 = 0 + 1;
                args[0] = FieldUtil.getAssignedKeyObject(table.key, entity);
                i = i2;
            }
            if (!Checker.isEmpty(table.pmap)) {
                for (Map.Entry<String, Property> en : table.pmap.entrySet()) {
                    sql.append(",");
                    sql.append(en.getKey());
                    value.append(",?");
                    if (needValue) {
                        args[i] = FieldUtil.get(en.getValue().field, entity);
                    }
                    i++;
                }
            }
            sql.append((CharSequence) value);
            sql.append(PARENTHESES_RIGHT);
            stmt.bindArgs = args;
            stmt.sql = sql.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return stmt;
    }

    public static Object[] buildInsertSqlArgsOnly(Object entity) throws IllegalAccessException {
        EntityTable table = TableManager.getTable(entity);
        int size = Checker.isEmpty(table.pmap) ? 1 : 1 + table.pmap.size();
        Object[] args = new Object[size];
        int i = 0 + 1;
        args[0] = FieldUtil.getAssignedKeyObject(table.key, entity);
        if (!Checker.isEmpty(table.pmap)) {
            for (Property p : table.pmap.values()) {
                args[i] = FieldUtil.get(p.field, entity);
                i++;
            }
        }
        return args;
    }

    public static SQLStatement buildUpdateSql(Object entity, ColumnsValue cvs, ConflictAlgorithm algorithm) {
        return buildUpdateSql(entity, cvs, algorithm, true);
    }

    public static SQLStatement buildUpdateAllSql(Object entity, ColumnsValue cvs, ConflictAlgorithm algorithm) {
        return buildUpdateSql(entity, cvs, algorithm, false);
    }

    private static SQLStatement buildUpdateSql(Object entity, ColumnsValue cvs, ConflictAlgorithm algorithm, boolean needValue) {
        SQLStatement stmt = new SQLStatement();
        try {
            EntityTable table = TableManager.getTable(entity);
            StringBuilder sql = new StringBuilder(128);
            sql.append(UPDATE);
            if (algorithm != null) {
                sql.append(algorithm.getAlgorithm());
            }
            sql.append(table.name);
            sql.append(SET);
            int size = 1;
            int i = 0;
            Object[] args = null;
            if (cvs != null && cvs.checkColumns()) {
                if (needValue) {
                    size = 1 + cvs.columns.length;
                    args = new Object[size];
                }
                while (i < cvs.columns.length) {
                    if (i > 0) {
                        sql.append(",");
                    }
                    sql.append(cvs.columns[i]);
                    sql.append("=?");
                    if (needValue) {
                        args[i] = cvs.getValue(cvs.columns[i]);
                        if (args[i] == null) {
                            args[i] = FieldUtil.get(table.pmap.get(cvs.columns[i]).field, entity);
                        }
                    }
                    i++;
                }
            } else if (!Checker.isEmpty(table.pmap)) {
                if (needValue) {
                    size = 1 + table.pmap.size();
                    args = new Object[size];
                }
                for (Map.Entry<String, Property> en : table.pmap.entrySet()) {
                    if (i > 0) {
                        sql.append(",");
                    }
                    sql.append(en.getKey());
                    sql.append("=?");
                    if (needValue) {
                        args[i] = FieldUtil.get(en.getValue().field, entity);
                    }
                    i++;
                }
            } else if (needValue) {
                args = new Object[1];
            }
            if (needValue) {
                args[size - 1] = FieldUtil.getAssignedKeyObject(table.key, entity);
            }
            sql.append(" WHERE ");
            sql.append(table.key.column);
            sql.append("=?");
            stmt.sql = sql.toString();
            stmt.bindArgs = args;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return stmt;
    }

    public static Object[] buildUpdateSqlArgsOnly(Object entity, ColumnsValue cvs) throws IllegalAccessException {
        Object[] args;
        EntityTable table = TableManager.getTable(entity);
        int size = 1;
        int i = 0;
        if (cvs != null && cvs.checkColumns()) {
            size = 1 + cvs.columns.length;
            args = new Object[size];
            while (i < cvs.columns.length) {
                args[i] = cvs.getValue(cvs.columns[i]);
                if (args[i] == null) {
                    args[i] = FieldUtil.get(table.pmap.get(cvs.columns[i]).field, entity);
                }
                i++;
            }
        } else if (!Checker.isEmpty(table.pmap)) {
            size = 1 + table.pmap.size();
            args = new Object[size];
            for (Map.Entry<String, Property> en : table.pmap.entrySet()) {
                args[i] = FieldUtil.get(en.getValue().field, entity);
                i++;
            }
        } else {
            args = new Object[1];
        }
        args[size - 1] = FieldUtil.getAssignedKeyObject(table.key, entity);
        return args;
    }

    public static SQLStatement buildUpdateSql(WhereBuilder where, ColumnsValue cvs, ConflictAlgorithm algorithm) {
        Object[] args;
        SQLStatement stmt = new SQLStatement();
        try {
            EntityTable table = TableManager.getTable((Class<?>) where.getTableClass());
            StringBuilder sql = new StringBuilder(128);
            sql.append(UPDATE);
            if (algorithm != null) {
                sql.append(algorithm.getAlgorithm());
            }
            sql.append(table.name);
            sql.append(SET);
            if (cvs != null && cvs.checkColumns()) {
                Object[] wArgs = where.getWhereArgs();
                if (wArgs != null) {
                    args = new Object[cvs.columns.length + wArgs.length];
                } else {
                    Object[] args2 = cvs.columns;
                    args = new Object[args2.length];
                }
                int i = 0;
                while (i < cvs.columns.length) {
                    if (i > 0) {
                        sql.append(",");
                    }
                    sql.append(cvs.columns[i]);
                    sql.append("=?");
                    args[i] = cvs.getValue(cvs.columns[i]);
                    i++;
                }
                if (wArgs != null) {
                    int len$ = wArgs.length;
                    int i$ = 0;
                    while (i$ < len$) {
                        Object o = wArgs[i$];
                        args[i] = o;
                        i$++;
                        i++;
                    }
                }
            } else {
                args = where.getWhereArgs();
            }
            sql.append(where.createWhereString());
            stmt.sql = sql.toString();
            stmt.bindArgs = args;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return stmt;
    }

    public static SQLStatement buildDeleteSql(Object entity) {
        SQLStatement stmt = new SQLStatement();
        try {
            EntityTable table = TableManager.getTable(entity);
            if (table.key != null) {
                stmt.sql = "DELETE FROM " + table.name + " WHERE " + table.key.column + "=?";
                stmt.bindArgs = new String[]{String.valueOf(FieldUtil.get(table.key.field, entity))};
            } else if (!Checker.isEmpty(table.pmap)) {
                StringBuilder sb = new StringBuilder();
                sb.append("DELETE FROM ");
                sb.append(table.name);
                sb.append(" WHERE ");
                Object[] args = new Object[table.pmap.size()];
                int i = 0;
                for (Map.Entry<String, Property> en : table.pmap.entrySet()) {
                    if (i == 0) {
                        sb.append(en.getKey());
                        sb.append("=?");
                    } else {
                        sb.append(" AND ");
                        sb.append(en.getKey());
                        sb.append("=?");
                    }
                    args[i] = FieldUtil.get(en.getValue().field, entity);
                    i++;
                }
                stmt.sql = sb.toString();
                stmt.bindArgs = args;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return stmt;
    }

    public static SQLStatement buildDeleteSql(Collection<?> collection) {
        SQLStatement stmt = new SQLStatement();
        try {
            StringBuilder sb = new StringBuilder(256);
            EntityTable table = null;
            Object[] args = new Object[collection.size()];
            int i = 0;
            for (Object entity : collection) {
                if (i == 0) {
                    table = TableManager.getTable(entity);
                    sb.append("DELETE FROM ");
                    sb.append(table.name);
                    sb.append(" WHERE ");
                    sb.append(table.key.column);
                    sb.append(IN);
                    sb.append(PARENTHESES_LEFT);
                    sb.append("?");
                } else {
                    sb.append(",?");
                }
                args[i] = FieldUtil.get(table.key.field, entity);
                i++;
            }
            sb.append(PARENTHESES_RIGHT);
            stmt.sql = sb.toString();
            stmt.bindArgs = args;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return stmt;
    }

    public static SQLStatement buildDeleteAllSql(Class<?> claxx) {
        SQLStatement stmt = new SQLStatement();
        EntityTable table = TableManager.getTable(claxx);
        stmt.sql = "DELETE FROM " + table.name;
        return stmt;
    }

    public static SQLStatement buildDeleteSql(Class<?> claxx, long start, long end, String orderAscColumn) {
        SQLStatement stmt = new SQLStatement();
        EntityTable table = TableManager.getTable(claxx);
        String key = table.key.column;
        String orderBy = Checker.isEmpty(orderAscColumn) ? key : orderAscColumn;
        stmt.sql = "DELETE FROM " + table.name + " WHERE " + key + IN + PARENTHESES_LEFT + "SELECT " + key + " FROM " + table.name + " ORDER BY " + orderBy + ASC + " LIMIT " + start + "," + end + PARENTHESES_RIGHT;
        return stmt;
    }

    public static SQLStatement buildAddColumnSql(String tableName, String column) {
        SQLStatement stmt = new SQLStatement();
        stmt.sql = "ALTER TABLE " + tableName + " ADD COLUMN " + column;
        return stmt;
    }

    public static MapInfo buildDelAllMappingSql(Class claxx) {
        EntityTable table1 = TableManager.getTable((Class<?>) claxx);
        if (!Checker.isEmpty(table1.mappingList)) {
            try {
                MapInfo mapInfo = new MapInfo();
                for (MapProperty map : table1.mappingList) {
                    EntityTable table2 = TableManager.getTable((Class<?>) getTypeByRelation(map));
                    String mapTableName = TableManager.getMapTableName(table1, table2);
                    MapInfo.MapTable mi = new MapInfo.MapTable(mapTableName, table1.name, table2.name);
                    mapInfo.addTable(mi);
                    SQLStatement st = buildMappingDeleteAllSql(table1, table2);
                    mapInfo.addDelOldRelationSQL(st);
                }
                return mapInfo;
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }
        return null;
    }

    public static MapInfo buildMappingInfo(Object entity, boolean insertNew, TableManager tableManager) {
        Object mapObject;
        ArrayList<SQLStatement> sqlList;
        EntityTable table1 = TableManager.getTable(entity);
        if (!Checker.isEmpty(table1.mappingList)) {
            try {
                Object key1 = FieldUtil.get(table1.key.field, entity);
                if (key1 == null) {
                    return null;
                }
                MapInfo mapInfo = new MapInfo();
                for (MapProperty map : table1.mappingList) {
                    EntityTable table2 = TableManager.getTable((Class<?>) getTypeByRelation(map));
                    String mapTableName = TableManager.getMapTableName(table1, table2);
                    MapInfo.MapTable mi = new MapInfo.MapTable(mapTableName, table1.name, table2.name);
                    mapInfo.addTable(mi);
                    if (tableManager.isSQLMapTableCreated(table1.name, table2.name)) {
                        mapInfo.addDelOldRelationSQL(buildMappingDeleteSql(key1, table1, table2));
                    }
                    if (insertNew && (mapObject = FieldUtil.get(map.field, entity)) != null) {
                        if (map.isToMany()) {
                            if (mapObject instanceof Collection) {
                                sqlList = buildMappingToManySql(key1, table1, table2, (Collection) mapObject);
                            } else if (mapObject instanceof Object[]) {
                                sqlList = buildMappingToManySql(key1, table1, table2, Arrays.asList((Object[]) mapObject));
                            } else {
                                throw new RuntimeException("OneToMany and ManyToMany Relation, You must use array or collection object");
                            }
                            if (Checker.isEmpty(sqlList)) {
                                mapInfo.addNewRelationSQL(sqlList);
                            }
                        } else {
                            SQLStatement st = buildMappingToOneSql(key1, table1, table2, mapObject);
                            if (st != null) {
                                mapInfo.addNewRelationSQL(st);
                            }
                        }
                    }
                }
                return mapInfo;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    private static Class getTypeByRelation(MapProperty mp) {
        if (mp.isToMany()) {
            Class<?> type = mp.field.getType();
            if (ClassUtil.isCollection(type)) {
                return FieldUtil.getGenericType(mp.field);
            }
            if (ClassUtil.isArray(type)) {
                return FieldUtil.getComponentType(mp.field);
            }
            throw new RuntimeException("OneToMany and ManyToMany Relation, you must use collection or array object");
        }
        return mp.field.getType();
    }

    private static SQLStatement buildMappingDeleteAllSql(EntityTable table1, EntityTable table2) throws IllegalAccessException, IllegalArgumentException {
        if (table2 != null) {
            String mapTableName = TableManager.getMapTableName(table1, table2);
            SQLStatement stmt = new SQLStatement();
            stmt.sql = "DELETE FROM " + mapTableName;
            return stmt;
        }
        return null;
    }

    public static SQLStatement buildMappingDeleteSql(Object key1, EntityTable table1, EntityTable table2) throws IllegalAccessException, IllegalArgumentException {
        if (table2 != null) {
            String mapTableName = TableManager.getMapTableName(table1, table2);
            return buildMappingDeleteSql(mapTableName, key1, table1);
        }
        return null;
    }

    public static SQLStatement buildMappingDeleteSql(String mapTableName, Object key1, EntityTable table1) throws IllegalAccessException, IllegalArgumentException {
        if (mapTableName != null) {
            SQLStatement stmt = new SQLStatement();
            stmt.sql = "DELETE FROM " + mapTableName + " WHERE " + table1.name + "=?";
            stmt.bindArgs = new Object[]{key1};
            return stmt;
        }
        return null;
    }

    public static <T> ArrayList<SQLStatement> buildMappingToManySql(final Object key1, final EntityTable table1, final EntityTable table2, Collection<T> coll) throws Exception {
        final ArrayList<SQLStatement> sqlList = new ArrayList<>();
        CollSpliter.split(coll, 499, new CollSpliter.Spliter<T>() { // from class: com.litesuits.orm.db.assit.SQLBuilder.1
            @Override // com.litesuits.orm.db.assit.CollSpliter.Spliter
            public int oneSplit(ArrayList<T> list) throws Exception {
                SQLStatement sql = SQLBuilder.buildMappingToManySqlFragment(key1, table1, table2, list);
                if (sql != null) {
                    sqlList.add(sql);
                    return 0;
                }
                return 0;
            }
        });
        return sqlList;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static SQLStatement buildMappingToManySqlFragment(Object key1, EntityTable table1, EntityTable table2, Collection<?> coll) throws IllegalAccessException, IllegalArgumentException {
        String mapTableName = TableManager.getMapTableName(table1, table2);
        if (!Checker.isEmpty(coll)) {
            boolean isF = true;
            StringBuilder values = new StringBuilder(128);
            ArrayList<String> list = new ArrayList<>();
            String key1Str = String.valueOf(key1);
            for (Object o : coll) {
                Object key2 = FieldUtil.getAssignedKeyObject(table2.key, o);
                if (key2 != null) {
                    if (isF) {
                        values.append(TWO_HOLDER);
                        isF = false;
                    } else {
                        values.append(",");
                        values.append(TWO_HOLDER);
                    }
                    list.add(key1Str);
                    list.add(String.valueOf(key2));
                }
            }
            Object[] args = list.toArray(new String[list.size()]);
            if (!Checker.isEmpty(args)) {
                SQLStatement stmt = new SQLStatement();
                stmt.sql = "REPLACE INTO " + mapTableName + PARENTHESES_LEFT + table1.name + "," + table2.name + PARENTHESES_RIGHT + VALUES + ((Object) values);
                stmt.bindArgs = args;
                return stmt;
            }
            return null;
        }
        return null;
    }

    public static SQLStatement buildMappingToOneSql(Object key1, EntityTable table1, EntityTable table2, Object obj) throws IllegalAccessException, IllegalArgumentException {
        Object key2 = FieldUtil.getAssignedKeyObject(table2.key, obj);
        if (key2 != null) {
            String mapTableName = TableManager.getMapTableName(table1, table2);
            return buildMappingToOneSql(mapTableName, key1, key2, table1, table2);
        }
        return null;
    }

    public static SQLStatement buildMappingToOneSql(String mapTableName, Object key1, Object key2, EntityTable table1, EntityTable table2) throws IllegalAccessException, IllegalArgumentException {
        if (key2 != null) {
            StringBuilder sql = new StringBuilder(128);
            sql.append(INSERT);
            sql.append(INTO);
            sql.append(mapTableName);
            sql.append(PARENTHESES_LEFT);
            sql.append(table1.name);
            sql.append(",");
            sql.append(table2.name);
            sql.append(PARENTHESES_RIGHT);
            sql.append(VALUES);
            sql.append(TWO_HOLDER);
            SQLStatement stmt = new SQLStatement();
            stmt.sql = sql.toString();
            stmt.bindArgs = new Object[]{key1, key2};
            return stmt;
        }
        return null;
    }

    public static SQLStatement buildQueryRelationSql(Class class1, Class class2, List<String> key1List) {
        return buildQueryRelationSql(class1, class2, key1List, null);
    }

    private static SQLStatement buildQueryRelationSql(Class class1, Class class2, List<String> key1List, List<String> key2List) {
        EntityTable table1 = TableManager.getTable((Class<?>) class1);
        EntityTable table2 = TableManager.getTable((Class<?>) class2);
        QueryBuilder builder = new QueryBuilder(class1).queryMappingInfo(class2);
        ArrayList<String> keyList = new ArrayList<>();
        StringBuilder sb = null;
        if (!Checker.isEmpty(key1List)) {
            sb = new StringBuilder();
            sb.append(table1.name);
            sb.append(IN);
            sb.append(PARENTHESES_LEFT);
            int size = key1List.size();
            for (int i = 0; i < size; i++) {
                if (i == 0) {
                    sb.append("?");
                } else {
                    sb.append(",?");
                }
            }
            sb.append(PARENTHESES_RIGHT);
            keyList.addAll(key1List);
        }
        if (!Checker.isEmpty(key2List)) {
            if (sb == null) {
                sb = new StringBuilder();
            } else {
                sb.append(" AND ");
            }
            sb.append(table2.name);
            sb.append(IN);
            sb.append(PARENTHESES_LEFT);
            int size2 = key2List.size();
            for (int i2 = 0; i2 < size2; i2++) {
                if (i2 == 0) {
                    sb.append("?");
                } else {
                    sb.append(",?");
                }
            }
            sb.append(PARENTHESES_RIGHT);
            keyList.addAll(key2List);
        }
        if (sb != null) {
            builder.where(sb.toString(), keyList.toArray(new String[keyList.size()]));
        }
        return builder.createStatement();
    }

    public static SQLStatement buildQueryRelationSql(EntityTable table1, EntityTable table2, Object key1) {
        SQLStatement sqlStatement = new SQLStatement();
        sqlStatement.sql = SELECT_ANY_FROM + TableManager.getMapTableName(table1, table2) + " WHERE " + table1.name + "=?";
        sqlStatement.bindArgs = new String[]{String.valueOf(key1)};
        return sqlStatement;
    }

    public static SQLStatement buildQueryMapEntitySql(EntityTable table2, Object key2) {
        SQLStatement sqlStatement = new SQLStatement();
        sqlStatement.sql = SELECT_ANY_FROM + table2.name + " WHERE " + table2.key.column + "=?";
        sqlStatement.bindArgs = new String[]{String.valueOf(key2)};
        return sqlStatement;
    }
}
