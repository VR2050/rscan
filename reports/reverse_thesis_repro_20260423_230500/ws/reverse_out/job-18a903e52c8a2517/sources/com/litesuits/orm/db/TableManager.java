package com.litesuits.orm.db;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import com.litesuits.orm.db.annotation.Column;
import com.litesuits.orm.db.annotation.Mapping;
import com.litesuits.orm.db.annotation.PrimaryKey;
import com.litesuits.orm.db.annotation.Table;
import com.litesuits.orm.db.assit.Checker;
import com.litesuits.orm.db.assit.Querier;
import com.litesuits.orm.db.assit.SQLBuilder;
import com.litesuits.orm.db.assit.SQLStatement;
import com.litesuits.orm.db.assit.Transaction;
import com.litesuits.orm.db.enums.AssignType;
import com.litesuits.orm.db.model.EntityTable;
import com.litesuits.orm.db.model.MapProperty;
import com.litesuits.orm.db.model.Primarykey;
import com.litesuits.orm.db.model.Property;
import com.litesuits.orm.db.model.SQLiteColumn;
import com.litesuits.orm.db.model.SQLiteTable;
import com.litesuits.orm.db.utils.DataUtil;
import com.litesuits.orm.db.utils.FieldUtil;
import com.litesuits.orm.log.OrmLog;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public final class TableManager {
    private String dbName;
    private final HashMap<String, SQLiteTable> mSqlTableMap = new HashMap<>();
    private static final String TAG = TableManager.class.getSimpleName();
    private static final String[] ID = {TtmlNode.ATTR_ID, "_id"};
    private static final HashMap<String, EntityTable> mEntityTableMap = new HashMap<>();

    public TableManager(String dbName, SQLiteDatabase db) {
        this.dbName = "";
        this.dbName = dbName;
        initSqlTable(db);
    }

    public void initSqlTable(SQLiteDatabase db) {
        initAllTablesFromSQLite(db);
    }

    public void clearSqlTable() {
        synchronized (this.mSqlTableMap) {
            this.mSqlTableMap.clear();
        }
    }

    public void release() {
        clearSqlTable();
        mEntityTableMap.clear();
    }

    public EntityTable checkOrCreateTable(SQLiteDatabase db, Object entity) {
        return checkOrCreateTable(db, (Class) entity.getClass());
    }

    public synchronized EntityTable checkOrCreateTable(SQLiteDatabase db, Class claxx) {
        EntityTable table;
        table = getTable((Class<?>) claxx);
        if (!checkExistAndColumns(db, table) && createTable(db, table)) {
            putNewSqlTableIntoMap(table);
        }
        return table;
    }

    public synchronized void checkOrCreateMappingTable(SQLiteDatabase db, String tableName, String column1, String column2) {
        EntityTable table = getMappingTable(tableName, column1, column2);
        if (!checkExistAndColumns(db, table) && createTable(db, table)) {
            putNewSqlTableIntoMap(table);
        }
    }

    public boolean isSQLMapTableCreated(String tableName1, String tableName2) {
        return this.mSqlTableMap.get(getMapTableName(tableName1, tableName2)) != null;
    }

    public boolean isSQLTableCreated(String tableName) {
        return this.mSqlTableMap.get(tableName) != null;
    }

    private boolean checkExistAndColumns(SQLiteDatabase db, EntityTable entityTable) {
        SQLiteTable sqlTable = this.mSqlTableMap.get(entityTable.name);
        if (sqlTable != null) {
            if (OrmLog.isPrint) {
                OrmLog.d(TAG, "Table [" + entityTable.name + "] Exist");
            }
            if (!sqlTable.isTableChecked) {
                sqlTable.isTableChecked = true;
                if (OrmLog.isPrint) {
                    OrmLog.i(TAG, "Table [" + entityTable.name + "] check column now.");
                }
                if (entityTable.key != null && sqlTable.columns.get(entityTable.key.column) == null) {
                    SQLStatement stmt = SQLBuilder.buildDropTable(sqlTable.name);
                    stmt.execute(db);
                    if (OrmLog.isPrint) {
                        OrmLog.i(TAG, "Table [" + entityTable.name + "] Primary Key has changed, so drop and recreate it later.");
                    }
                    return false;
                }
                if (entityTable.pmap != null) {
                    ArrayList<String> newColumns = new ArrayList<>();
                    for (String col : entityTable.pmap.keySet()) {
                        if (sqlTable.columns.get(col) == null) {
                            newColumns.add(col);
                        }
                    }
                    if (!Checker.isEmpty(newColumns)) {
                        Iterator<String> it = newColumns.iterator();
                        while (it.hasNext()) {
                            sqlTable.columns.put(it.next(), 1);
                        }
                        int sum = insertNewColunms(db, entityTable.name, newColumns);
                        if (OrmLog.isPrint) {
                            if (sum > 0) {
                                OrmLog.i(TAG, "Table [" + entityTable.name + "] add " + sum + " new column ： " + newColumns);
                            } else {
                                OrmLog.e(TAG, "Table [" + entityTable.name + "] add " + sum + " new column error ： " + newColumns);
                            }
                        }
                    }
                }
            }
            return true;
        }
        if (OrmLog.isPrint) {
            OrmLog.d(TAG, "Table [" + entityTable.name + "] Not Exist");
        }
        return false;
    }

    private void putNewSqlTableIntoMap(EntityTable table) {
        if (OrmLog.isPrint) {
            OrmLog.i(TAG, "Table [" + table.name + "] Create Success");
        }
        SQLiteTable sqlTable = new SQLiteTable();
        sqlTable.name = table.name;
        sqlTable.columns = new HashMap<>();
        if (table.key != null) {
            sqlTable.columns.put(table.key.column, 1);
        }
        if (table.pmap != null) {
            for (String col : table.pmap.keySet()) {
                sqlTable.columns.put(col, 1);
            }
        }
        sqlTable.isTableChecked = true;
        this.mSqlTableMap.put(sqlTable.name, sqlTable);
    }

    private void initAllTablesFromSQLite(SQLiteDatabase db) {
        synchronized (this.mSqlTableMap) {
            if (Checker.isEmpty(this.mSqlTableMap)) {
                if (OrmLog.isPrint) {
                    OrmLog.i(TAG, "Initialize SQL table start--------------------->");
                }
                SQLStatement st = SQLBuilder.buildTableObtainAll();
                final EntityTable table = getTable(SQLiteTable.class, false);
                Querier.doQuery(db, st, new Querier.CursorParser() { // from class: com.litesuits.orm.db.TableManager.1
                    @Override // com.litesuits.orm.db.assit.Querier.CursorParser
                    public void parseEachCursor(SQLiteDatabase db2, Cursor c) throws Exception {
                        SQLiteTable sqlTable = new SQLiteTable();
                        DataUtil.injectDataToObject(c, sqlTable, table);
                        ArrayList<String> colS = TableManager.this.getAllColumnsFromSQLite(db2, sqlTable.name);
                        if (Checker.isEmpty(colS)) {
                            OrmLog.e(TableManager.TAG, "读数据库失败了，开始解析建表语句");
                            colS = TableManager.this.transformSqlToColumns(sqlTable.sql);
                        }
                        sqlTable.columns = new HashMap<>();
                        for (String col : colS) {
                            sqlTable.columns.put(col, 1);
                        }
                        if (OrmLog.isPrint) {
                            OrmLog.i(TableManager.TAG, "Find One SQL Table: " + sqlTable);
                            OrmLog.i(TableManager.TAG, "Table Column: " + colS);
                        }
                        TableManager.this.mSqlTableMap.put(sqlTable.name, sqlTable);
                    }
                });
                if (OrmLog.isPrint) {
                    OrmLog.i(TAG, "Initialize SQL table end  ---------------------> " + this.mSqlTableMap.size());
                }
            }
        }
    }

    private int insertNewColunms(SQLiteDatabase db, final String tableName, final List<String> columns) {
        Integer size = null;
        if (!Checker.isEmpty(columns)) {
            size = (Integer) Transaction.execute(db, new Transaction.Worker<Integer>() { // from class: com.litesuits.orm.db.TableManager.2
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // com.litesuits.orm.db.assit.Transaction.Worker
                public Integer doTransaction(SQLiteDatabase db2) {
                    for (String c : columns) {
                        SQLStatement stmt = SQLBuilder.buildAddColumnSql(tableName, c);
                        stmt.execute(db2);
                    }
                    return Integer.valueOf(columns.size());
                }
            });
        }
        if (size == null) {
            return 0;
        }
        return size.intValue();
    }

    private boolean createTable(SQLiteDatabase db, EntityTable table) {
        return SQLBuilder.buildCreateTable(table).execute(db);
    }

    public ArrayList<String> getAllColumnsFromSQLite(SQLiteDatabase db, String tableName) {
        final EntityTable table = getTable(SQLiteColumn.class, false);
        final ArrayList<String> list = new ArrayList<>();
        SQLStatement st = SQLBuilder.buildColumnsObtainAll(tableName);
        Querier.doQuery(db, st, new Querier.CursorParser() { // from class: com.litesuits.orm.db.TableManager.3
            @Override // com.litesuits.orm.db.assit.Querier.CursorParser
            public void parseEachCursor(SQLiteDatabase db2, Cursor c) throws Exception {
                SQLiteColumn col = new SQLiteColumn();
                DataUtil.injectDataToObject(c, col, table);
                list.add(col.name);
            }
        });
        return list;
    }

    public ArrayList<String> transformSqlToColumns(String sql) {
        if (sql != null) {
            int start = sql.indexOf(SQLBuilder.PARENTHESES_LEFT);
            int end = sql.lastIndexOf(SQLBuilder.PARENTHESES_RIGHT);
            if (start > 0 && end > 0) {
                String sql2 = sql.substring(start + 1, end);
                String[] cloumns = sql2.split(",");
                ArrayList<String> colList = new ArrayList<>();
                for (String str : cloumns) {
                    String col = str.trim();
                    int endS = col.indexOf(" ");
                    if (endS > 0) {
                        col = col.substring(0, endS);
                    }
                    colList.add(col);
                }
                OrmLog.e(TAG, "降级：语义分析表结构（" + colList.toString() + " , Origin SQL is: " + sql2);
                return colList;
            }
            return null;
        }
        return null;
    }

    private static EntityTable getEntityTable(String name) {
        return mEntityTableMap.get(name);
    }

    private static EntityTable putEntityTable(String tableName, EntityTable entity) {
        return mEntityTableMap.put(tableName, entity);
    }

    private EntityTable getMappingTable(String tableName, String column1, String column2) {
        EntityTable table = getEntityTable(this.dbName + tableName);
        if (table == null) {
            EntityTable table2 = new EntityTable();
            table2.name = tableName;
            table2.pmap = new LinkedHashMap<>();
            table2.pmap.put(column1, null);
            table2.pmap.put(column2, null);
            putEntityTable(this.dbName + tableName, table2);
            return table2;
        }
        return table;
    }

    public static EntityTable getTable(Object entity) {
        return getTable(entity.getClass(), true);
    }

    public static EntityTable getTable(Class<?> claxx) {
        return getTable(claxx, true);
    }

    public static synchronized EntityTable getTable(Class<?> claxx, boolean needPK) {
        EntityTable table;
        table = getEntityTable(claxx.getName());
        if (table == null) {
            table = new EntityTable();
            table.claxx = claxx;
            table.name = getTableName(claxx);
            table.pmap = new LinkedHashMap<>();
            List<Field> fields = FieldUtil.getAllDeclaredFields(claxx);
            for (Field f : fields) {
                if (!FieldUtil.isInvalid(f)) {
                    Column col = (Column) f.getAnnotation(Column.class);
                    String column = col != null ? col.value() : f.getName();
                    Property p = new Property(column, f);
                    PrimaryKey key = (PrimaryKey) f.getAnnotation(PrimaryKey.class);
                    if (key != null) {
                        table.key = new Primarykey(p, key.value());
                        checkPrimaryKey(table.key);
                    } else {
                        Mapping mapping = (Mapping) f.getAnnotation(Mapping.class);
                        if (mapping != null) {
                            table.addMapping(new MapProperty(p, mapping.value()));
                        } else {
                            table.pmap.put(p.column, p);
                        }
                    }
                }
            }
            if (table.key == null) {
                for (String col2 : table.pmap.keySet()) {
                    String[] arr$ = ID;
                    int len$ = arr$.length;
                    int i$ = 0;
                    while (true) {
                        if (i$ >= len$) {
                            break;
                        }
                        String id = arr$[i$];
                        if (id.equalsIgnoreCase(col2)) {
                            Property p2 = table.pmap.get(col2);
                            if (p2.field.getType() == String.class) {
                                table.pmap.remove(col2);
                                table.key = new Primarykey(p2, AssignType.BY_MYSELF);
                                break;
                            }
                            if (FieldUtil.isNumber(p2.field.getType())) {
                                table.pmap.remove(col2);
                                table.key = new Primarykey(p2, AssignType.AUTO_INCREMENT);
                                break;
                            }
                        }
                        i$++;
                    }
                    if (table.key != null) {
                        break;
                    }
                }
            }
            if (needPK && table.key == null) {
                throw new RuntimeException("你必须为[" + table.claxx.getSimpleName() + "]设置主键(you must set the primary key...)\n 提示：在对象的属性上加PrimaryKey注解来设置主键。");
            }
            putEntityTable(claxx.getName(), table);
        }
        return table;
    }

    private static void checkPrimaryKey(Primarykey key) {
        if (key.isAssignedBySystem()) {
            if (!FieldUtil.isNumber(key.field.getType())) {
                throw new RuntimeException(AssignType.AUTO_INCREMENT + " Auto increment primary key must be a number ...\n 错误提示：自增主键必须设置为数字类型");
            }
            return;
        }
        if (key.isAssignedByMyself()) {
            if (String.class != key.field.getType() && !FieldUtil.isNumber(key.field.getType())) {
                throw new RuntimeException(AssignType.BY_MYSELF + " Custom primary key must be string or number ...\n 错误提示：自定义主键值必须为String或者Number类型");
            }
            return;
        }
        throw new RuntimeException(" Primary key without Assign Type ...\n 错误提示：主键无类型");
    }

    public static String getTableName(Class<?> claxx) {
        Table anno = (Table) claxx.getAnnotation(Table.class);
        if (anno != null) {
            return anno.value();
        }
        return claxx.getName().replaceAll("\\.", "_");
    }

    public static String getMapTableName(Class c1, Class c2) {
        return getMapTableName(getTableName(c1), getTableName(c2));
    }

    public static String getMapTableName(EntityTable t1, EntityTable t2) {
        return getMapTableName(t1.name, t2.name);
    }

    public static String getMapTableName(String tableName1, String tableName2) {
        if (tableName1.compareTo(tableName2) < 0) {
            return tableName1 + "_" + tableName2;
        }
        return tableName2 + "_" + tableName1;
    }
}
