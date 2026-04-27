package com.litesuits.orm.db.impl;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import com.litesuits.orm.LiteOrm;
import com.litesuits.orm.db.DataBaseConfig;
import com.litesuits.orm.db.TableManager;
import com.litesuits.orm.db.assit.Checker;
import com.litesuits.orm.db.assit.Querier;
import com.litesuits.orm.db.assit.QueryBuilder;
import com.litesuits.orm.db.assit.SQLBuilder;
import com.litesuits.orm.db.assit.SQLStatement;
import com.litesuits.orm.db.assit.Transaction;
import com.litesuits.orm.db.assit.WhereBuilder;
import com.litesuits.orm.db.model.ColumnsValue;
import com.litesuits.orm.db.model.ConflictAlgorithm;
import com.litesuits.orm.db.model.EntityTable;
import com.litesuits.orm.db.model.MapProperty;
import com.litesuits.orm.db.model.Property;
import com.litesuits.orm.db.model.RelationKey;
import com.litesuits.orm.db.utils.ClassUtil;
import com.litesuits.orm.db.utils.DataUtil;
import com.litesuits.orm.db.utils.FieldUtil;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public final class CascadeSQLiteImpl extends LiteOrm {
    public static final String TAG = CascadeSQLiteImpl.class.getSimpleName();
    public static final int TYPE_DELETE = 3;
    public static final int TYPE_INSERT = 1;
    public static final int TYPE_UPDATE = 2;

    protected CascadeSQLiteImpl(LiteOrm dataBase) {
        super(dataBase);
    }

    private CascadeSQLiteImpl(DataBaseConfig config) {
        super(config);
    }

    public static synchronized LiteOrm newInstance(DataBaseConfig config) {
        return new CascadeSQLiteImpl(config);
    }

    @Override // com.litesuits.orm.LiteOrm
    public LiteOrm single() {
        if (this.otherDatabase == null) {
            this.otherDatabase = new SingleSQLiteImpl(this);
        }
        return this.otherDatabase;
    }

    @Override // com.litesuits.orm.LiteOrm
    public LiteOrm cascade() {
        return this;
    }

    @Override // com.litesuits.orm.db.DataBase
    public long save(final Object entity) {
        acquireReference();
        try {
            SQLiteDatabase db = this.mHelper.getWritableDatabase();
            Long rowID = (Long) Transaction.execute(db, new Transaction.Worker<Long>() { // from class: com.litesuits.orm.db.impl.CascadeSQLiteImpl.1
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // com.litesuits.orm.db.assit.Transaction.Worker
                public Long doTransaction(SQLiteDatabase db2) throws Exception {
                    HashMap<String, Integer> handleMap = new HashMap<>();
                    return Long.valueOf(CascadeSQLiteImpl.this.checkTableAndSaveRecursive(entity, db2, handleMap));
                }
            });
            return rowID == null ? -1L : rowID.longValue();
        } finally {
            releaseReference();
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> int save(Collection<T> collection) {
        acquireReference();
        try {
            return saveCollection(collection);
        } finally {
            releaseReference();
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    public long insert(Object entity) {
        return insert(entity, (ConflictAlgorithm) null);
    }

    @Override // com.litesuits.orm.db.DataBase
    public long insert(final Object entity, final ConflictAlgorithm conflictAlgorithm) {
        acquireReference();
        long jLongValue = -1;
        try {
            SQLiteDatabase db = this.mHelper.getWritableDatabase();
            Long rowID = (Long) Transaction.execute(db, new Transaction.Worker<Long>() { // from class: com.litesuits.orm.db.impl.CascadeSQLiteImpl.2
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // com.litesuits.orm.db.assit.Transaction.Worker
                public Long doTransaction(SQLiteDatabase db2) throws Exception {
                    CascadeSQLiteImpl.this.mTableManager.checkOrCreateTable(db2, entity);
                    return Long.valueOf(CascadeSQLiteImpl.this.insertRecursive(SQLBuilder.buildInsertSql(entity, conflictAlgorithm), entity, db2, new HashMap()));
                }
            });
            if (rowID != null) {
                jLongValue = rowID.longValue();
            }
            return jLongValue;
        } catch (Exception e) {
            e.printStackTrace();
            return -1L;
        } finally {
            releaseReference();
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> int insert(Collection<T> collection) {
        return insert((Collection) collection, (ConflictAlgorithm) null);
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> int insert(Collection<T> collection, ConflictAlgorithm conflictAlgorithm) {
        acquireReference();
        try {
            try {
                return insertCollection(collection, conflictAlgorithm);
            } catch (Exception e) {
                e.printStackTrace();
                releaseReference();
                return -1;
            }
        } finally {
            releaseReference();
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    public int update(Object entity) {
        return update(entity, (ColumnsValue) null, (ConflictAlgorithm) null);
    }

    @Override // com.litesuits.orm.db.DataBase
    public int update(Object entity, ConflictAlgorithm conflictAlgorithm) {
        return update(entity, (ColumnsValue) null, conflictAlgorithm);
    }

    @Override // com.litesuits.orm.db.DataBase
    public int update(final Object entity, final ColumnsValue cvs, final ConflictAlgorithm conflictAlgorithm) {
        acquireReference();
        int iIntValue = -1;
        try {
            SQLiteDatabase db = this.mHelper.getWritableDatabase();
            Integer rowID = (Integer) Transaction.execute(db, new Transaction.Worker<Integer>() { // from class: com.litesuits.orm.db.impl.CascadeSQLiteImpl.3
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // com.litesuits.orm.db.assit.Transaction.Worker
                public Integer doTransaction(SQLiteDatabase db2) throws Exception {
                    HashMap<String, Integer> handleMap = new HashMap<>();
                    SQLStatement stmt = SQLBuilder.buildUpdateSql(entity, cvs, conflictAlgorithm);
                    CascadeSQLiteImpl.this.mTableManager.checkOrCreateTable(db2, entity);
                    return Integer.valueOf(CascadeSQLiteImpl.this.updateRecursive(stmt, entity, db2, handleMap));
                }
            });
            if (rowID != null) {
                iIntValue = rowID.intValue();
            }
            return iIntValue;
        } catch (Exception e) {
            e.printStackTrace();
            return -1;
        } finally {
            releaseReference();
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> int update(Collection<T> collection) {
        return update((Collection) collection, (ColumnsValue) null, (ConflictAlgorithm) null);
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> int update(Collection<T> collection, ConflictAlgorithm conflictAlgorithm) {
        return update((Collection) collection, (ColumnsValue) null, conflictAlgorithm);
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> int update(Collection<T> collection, ColumnsValue cvs, ConflictAlgorithm conflictAlgorithm) {
        acquireReference();
        try {
            try {
                return updateCollection(collection, cvs, conflictAlgorithm);
            } catch (Exception e) {
                e.printStackTrace();
                releaseReference();
                return -1;
            }
        } finally {
            releaseReference();
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    public int delete(final Object entity) {
        acquireReference();
        try {
            try {
                SQLiteDatabase db = this.mHelper.getWritableDatabase();
                Integer rowID = (Integer) Transaction.execute(db, new Transaction.Worker<Integer>() { // from class: com.litesuits.orm.db.impl.CascadeSQLiteImpl.4
                    /* JADX WARN: Can't rename method to resolve collision */
                    @Override // com.litesuits.orm.db.assit.Transaction.Worker
                    public Integer doTransaction(SQLiteDatabase db2) throws Exception {
                        HashMap<String, Integer> handleMap = new HashMap<>();
                        return Integer.valueOf(CascadeSQLiteImpl.this.checkTableAndDeleteRecursive(entity, db2, handleMap));
                    }
                });
                if (rowID != null) {
                    return rowID.intValue();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            releaseReference();
            return -1;
        } finally {
            releaseReference();
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> int delete(Class<T> claxx) {
        return deleteAll(claxx);
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> int delete(Collection<T> collection) {
        acquireReference();
        try {
            try {
                return deleteCollectionIfTableHasCreated(collection);
            } catch (Exception e) {
                e.printStackTrace();
                releaseReference();
                return -1;
            }
        } finally {
            releaseReference();
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> int delete(Class<T> claxx, WhereBuilder where) {
        acquireReference();
        try {
            try {
                EntityTable table = TableManager.getTable((Class<?>) claxx);
                delete((Collection) query(QueryBuilder.create(claxx).columns(new String[]{table.key.column}).where(where)));
            } catch (Exception e) {
                e.printStackTrace();
            }
            releaseReference();
            return -1;
        } catch (Throwable th) {
            releaseReference();
            throw th;
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    public int delete(WhereBuilder where) {
        acquireReference();
        try {
            try {
                EntityTable table = TableManager.getTable((Class<?>) where.getTableClass());
                deleteCollectionIfTableHasCreated(query(QueryBuilder.create(where.getTableClass()).columns(new String[]{table.key.column}).where(where)));
            } catch (Exception e) {
                e.printStackTrace();
            }
            releaseReference();
            return -1;
        } catch (Throwable th) {
            releaseReference();
            throw th;
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> int deleteAll(Class<T> claxx) {
        acquireReference();
        try {
            EntityTable table = TableManager.getTable((Class<?>) claxx);
            return delete((Collection) query(QueryBuilder.create(claxx).columns(new String[]{table.key.column})));
        } finally {
            releaseReference();
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> int delete(Class<T> claxx, long start, long end, String orderAscColumn) {
        acquireReference();
        try {
            if (start < 0 || end < start) {
                throw new RuntimeException("start must >=0 and smaller than end");
            }
            if (start != 0) {
                start--;
            }
            long end2 = end == 2147483647L ? -1L : end - start;
            EntityTable table = TableManager.getTable((Class<?>) claxx);
            return delete((Collection) query(QueryBuilder.create(claxx).limit(start + "," + end2).appendOrderAscBy(orderAscColumn).columns(new String[]{table.key.column})));
        } finally {
            releaseReference();
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> ArrayList<T> query(Class<T> claxx) {
        return checkTableAndQuery(claxx, new QueryBuilder(claxx));
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> ArrayList<T> query(QueryBuilder<T> qb) {
        return checkTableAndQuery(qb.getQueryClass(), qb);
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> T queryById(long j, Class<T> cls) {
        return (T) queryById(String.valueOf(j), cls);
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> T queryById(String id, Class<T> claxx) {
        EntityTable table = TableManager.getTable((Class<?>) claxx);
        ArrayList<T> list = checkTableAndQuery(claxx, new QueryBuilder(claxx).whereEquals(table.key.column, String.valueOf(id)));
        if (!Checker.isEmpty(list)) {
            return list.get(0);
        }
        return null;
    }

    private <T> ArrayList<T> checkTableAndQuery(final Class<T> claxx, QueryBuilder builder) {
        acquireReference();
        final ArrayList<T> list = new ArrayList<>();
        try {
            try {
                final EntityTable table = TableManager.getTable(claxx, false);
                if (this.mTableManager.isSQLTableCreated(table.name)) {
                    final HashMap<String, Object> entityMap = new HashMap<>();
                    HashMap<String, Integer> queryMap = new HashMap<>();
                    SQLiteDatabase db = this.mHelper.getReadableDatabase();
                    Querier.doQuery(db, builder.createStatement(), new Querier.CursorParser() { // from class: com.litesuits.orm.db.impl.CascadeSQLiteImpl.5
                        @Override // com.litesuits.orm.db.assit.Querier.CursorParser
                        public void parseEachCursor(SQLiteDatabase db2, Cursor c) throws Exception {
                            Object objNewInstance = ClassUtil.newInstance(claxx);
                            DataUtil.injectDataToObject(c, objNewInstance, table);
                            list.add(objNewInstance);
                            entityMap.put(table.name + FieldUtil.get(table.key.field, objNewInstance), objNewInstance);
                        }
                    });
                    for (T t : list) {
                        queryForMappingRecursive(t, db, queryMap, entityMap);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return list;
        } finally {
            releaseReference();
        }
    }

    private void queryForMappingRecursive(Object obj1, SQLiteDatabase db, HashMap<String, Integer> queryMap, HashMap<String, Object> entityMap) throws IllegalAccessException, InstantiationException {
        EntityTable table1 = TableManager.getTable(obj1);
        Object key1 = FieldUtil.getAssignedKeyObject(table1.key, obj1);
        String key = table1.name + key1;
        if (queryMap.get(key) == null) {
            queryMap.put(key, 1);
            if (table1.mappingList != null) {
                for (MapProperty mp : table1.mappingList) {
                    if (mp.isToOne()) {
                        queryMapToOne(table1, key1, obj1, mp.field, db, queryMap, entityMap);
                    } else if (mp.isToMany()) {
                        queryMapToMany(table1, key1, obj1, mp.field, db, queryMap, entityMap);
                    }
                }
            }
        }
    }

    private void queryMapToOne(final EntityTable table1, Object key1, Object obj1, Field field, SQLiteDatabase db, HashMap<String, Integer> queryMap, HashMap<String, Object> entityMap) throws IllegalAccessException, InstantiationException {
        final EntityTable table2 = TableManager.getTable(field.getType());
        if (this.mTableManager.isSQLMapTableCreated(table1.name, table2.name)) {
            SQLStatement relationSql = SQLBuilder.buildQueryRelationSql(table1, table2, key1);
            final RelationKey relation = new RelationKey();
            Querier.doQuery(db, relationSql, new Querier.CursorParser() { // from class: com.litesuits.orm.db.impl.CascadeSQLiteImpl.6
                @Override // com.litesuits.orm.db.assit.Querier.CursorParser
                public void parseEachCursor(SQLiteDatabase db2, Cursor c) throws Exception {
                    relation.key1 = c.getString(c.getColumnIndex(table1.name));
                    relation.key2 = c.getString(c.getColumnIndex(table2.name));
                    stopParse();
                }
            });
            if (relation.isOK()) {
                String key = table2.name + relation.key2;
                Object obj2 = entityMap.get(key);
                if (obj2 == null) {
                    SQLStatement entitySql = SQLBuilder.buildQueryMapEntitySql(table2, relation.key2);
                    obj2 = entitySql.queryOneEntity(db, table2.claxx);
                    entityMap.put(key, obj2);
                }
                if (obj2 != null) {
                    FieldUtil.set(field, obj1, obj2);
                    queryForMappingRecursive(obj2, db, queryMap, entityMap);
                }
            }
        }
    }

    private void queryMapToMany(EntityTable table1, Object key1, Object obj1, Field field, SQLiteDatabase db, HashMap<String, Integer> queryMap, final HashMap<String, Object> entityMap) throws IllegalAccessException, InstantiationException {
        Class<?> class2;
        ArrayList<Object> allList2;
        if (Collection.class.isAssignableFrom(field.getType())) {
            class2 = FieldUtil.getGenericType(field);
        } else {
            Class<?> class22 = field.getType();
            if (!class22.isArray()) {
                throw new RuntimeException("OneToMany and ManyToMany Relation, you must use collection or array object");
            }
            class2 = FieldUtil.getComponentType(field);
        }
        final EntityTable table2 = TableManager.getTable(class2);
        if (this.mTableManager.isSQLMapTableCreated(table1.name, table2.name)) {
            SQLStatement relationSql = SQLBuilder.buildQueryRelationSql(table1, table2, key1);
            final ArrayList<String> key2List = new ArrayList<>();
            Querier.doQuery(db, relationSql, new Querier.CursorParser() { // from class: com.litesuits.orm.db.impl.CascadeSQLiteImpl.7
                @Override // com.litesuits.orm.db.assit.Querier.CursorParser
                public void parseEachCursor(SQLiteDatabase db2, Cursor c) throws Exception {
                    key2List.add(c.getString(c.getColumnIndex(table2.name)));
                }
            });
            if (!Checker.isEmpty(key2List)) {
                ArrayList<Object> allList22 = new ArrayList<>();
                for (int i = key2List.size() - 1; i >= 0; i--) {
                    Object obj2 = entityMap.get(table2.name + key2List.get(i));
                    if (obj2 != null) {
                        allList22.add(obj2);
                        key2List.remove(i);
                    }
                }
                int i2 = 0;
                int start = 0;
                while (start < key2List.size()) {
                    int i3 = i2 + 1;
                    int i4 = i3 * SQLStatement.IN_TOP_LIMIT;
                    int i5 = key2List.size();
                    int end = Math.min(i5, i4);
                    List<String> subList = key2List.subList(start, end);
                    QueryBuilder queryBuilderCreate = QueryBuilder.create(class2);
                    String str = table2.key.column;
                    int end2 = subList.size();
                    SQLStatement entitySql = queryBuilderCreate.whereIn(str, subList.toArray(new String[end2])).createStatement();
                    final Class<?> cls = class2;
                    final ArrayList<Object> allList23 = allList22;
                    Querier.doQuery(db, entitySql, new Querier.CursorParser() { // from class: com.litesuits.orm.db.impl.CascadeSQLiteImpl.8
                        @Override // com.litesuits.orm.db.assit.Querier.CursorParser
                        public void parseEachCursor(SQLiteDatabase db2, Cursor c) throws Exception {
                            Object t = ClassUtil.newInstance(cls);
                            DataUtil.injectDataToObject(c, t, table2);
                            allList23.add(t);
                            entityMap.put(table2.name + FieldUtil.get(table2.key.field, t), t);
                        }
                    });
                    i2 = i3;
                    start = i4;
                    allList22 = allList23;
                    key2List = key2List;
                    relationSql = relationSql;
                }
                ArrayList<Object> allList24 = allList22;
                if (!Checker.isEmpty(allList24)) {
                    if (Collection.class.isAssignableFrom(field.getType())) {
                        Collection coll = (Collection) ClassUtil.newCollectionForField(field);
                        allList2 = allList24;
                        coll.addAll(allList2);
                        FieldUtil.set(field, obj1, coll);
                    } else {
                        allList2 = allList24;
                        if (!field.getType().isArray()) {
                            throw new RuntimeException("OneToMany and ManyToMany Relation, you must use collection or array object");
                        }
                        Object[] arrObj = (Object[]) ClassUtil.newArray(class2, allList2.size());
                        FieldUtil.set(field, obj1, allList2.toArray(arrObj));
                    }
                    Iterator<Object> it = allList2.iterator();
                    while (it.hasNext()) {
                        queryForMappingRecursive(it.next(), db, queryMap, entityMap);
                    }
                }
            }
        }
    }

    private <T> int saveCollection(final Collection<T> collection) {
        if (!Checker.isEmpty((Collection<?>) collection)) {
            SQLiteDatabase db = this.mHelper.getWritableDatabase();
            Integer rowID = (Integer) Transaction.execute(db, new Transaction.Worker<Integer>() { // from class: com.litesuits.orm.db.impl.CascadeSQLiteImpl.9
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // com.litesuits.orm.db.assit.Transaction.Worker
                public Integer doTransaction(SQLiteDatabase db2) throws Exception {
                    HashMap<String, Integer> handleMap = new HashMap<>();
                    Iterator it = collection.iterator();
                    Object entity = it.next();
                    SQLStatement stmt = SQLBuilder.buildReplaceSql(entity);
                    CascadeSQLiteImpl.this.mTableManager.checkOrCreateTable(db2, entity);
                    CascadeSQLiteImpl.this.insertRecursive(stmt, entity, db2, handleMap);
                    while (it.hasNext()) {
                        Object entity2 = it.next();
                        stmt.bindArgs = SQLBuilder.buildInsertSqlArgsOnly(entity2);
                        CascadeSQLiteImpl.this.insertRecursive(stmt, entity2, db2, handleMap);
                    }
                    return Integer.valueOf(collection.size());
                }
            });
            if (rowID != null) {
                return rowID.intValue();
            }
            return -1;
        }
        return -1;
    }

    private <T> int insertCollection(final Collection<T> collection, final ConflictAlgorithm conflictAlgorithm) {
        if (!Checker.isEmpty((Collection<?>) collection)) {
            SQLiteDatabase db = this.mHelper.getWritableDatabase();
            Integer rowID = (Integer) Transaction.execute(db, new Transaction.Worker<Integer>() { // from class: com.litesuits.orm.db.impl.CascadeSQLiteImpl.10
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // com.litesuits.orm.db.assit.Transaction.Worker
                public Integer doTransaction(SQLiteDatabase db2) throws Exception {
                    HashMap<String, Integer> handleMap = new HashMap<>();
                    Iterator it = collection.iterator();
                    Object entity = it.next();
                    SQLStatement stmt = SQLBuilder.buildInsertSql(entity, conflictAlgorithm);
                    CascadeSQLiteImpl.this.mTableManager.checkOrCreateTable(db2, entity);
                    CascadeSQLiteImpl.this.insertRecursive(stmt, entity, db2, handleMap);
                    while (it.hasNext()) {
                        Object entity2 = it.next();
                        stmt.bindArgs = SQLBuilder.buildInsertSqlArgsOnly(entity2);
                        CascadeSQLiteImpl.this.insertRecursive(stmt, entity2, db2, handleMap);
                    }
                    return Integer.valueOf(collection.size());
                }
            });
            if (rowID != null) {
                return rowID.intValue();
            }
            return -1;
        }
        return -1;
    }

    private <T> int updateCollection(final Collection<T> collection, final ColumnsValue cvs, final ConflictAlgorithm conflictAlgorithm) {
        if (!Checker.isEmpty((Collection<?>) collection)) {
            SQLiteDatabase db = this.mHelper.getWritableDatabase();
            Integer rowID = (Integer) Transaction.execute(db, new Transaction.Worker<Integer>() { // from class: com.litesuits.orm.db.impl.CascadeSQLiteImpl.11
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // com.litesuits.orm.db.assit.Transaction.Worker
                public Integer doTransaction(SQLiteDatabase db2) throws Exception {
                    HashMap<String, Integer> handleMap = new HashMap<>();
                    Iterator it = collection.iterator();
                    Object entity = it.next();
                    SQLStatement stmt = SQLBuilder.buildUpdateSql(entity, cvs, conflictAlgorithm);
                    CascadeSQLiteImpl.this.mTableManager.checkOrCreateTable(db2, entity);
                    CascadeSQLiteImpl.this.updateRecursive(stmt, entity, db2, handleMap);
                    while (it.hasNext()) {
                        Object entity2 = it.next();
                        stmt.bindArgs = SQLBuilder.buildUpdateSqlArgsOnly(entity2, cvs);
                        CascadeSQLiteImpl.this.updateRecursive(stmt, entity2, db2, handleMap);
                    }
                    return Integer.valueOf(collection.size());
                }
            });
            if (rowID != null) {
                return rowID.intValue();
            }
            return -1;
        }
        return -1;
    }

    private <T> int deleteCollectionIfTableHasCreated(final Collection<T> collection) {
        if (!Checker.isEmpty((Collection<?>) collection)) {
            final Iterator<T> iterator = collection.iterator();
            final Object entity = iterator.next();
            EntityTable table = TableManager.getTable(entity);
            if (this.mTableManager.isSQLTableCreated(table.name)) {
                SQLiteDatabase db = this.mHelper.getWritableDatabase();
                Integer rowID = (Integer) Transaction.execute(db, new Transaction.Worker<Integer>() { // from class: com.litesuits.orm.db.impl.CascadeSQLiteImpl.12
                    /* JADX WARN: Can't rename method to resolve collision */
                    @Override // com.litesuits.orm.db.assit.Transaction.Worker
                    public Integer doTransaction(SQLiteDatabase db2) throws Exception {
                        HashMap<String, Integer> handleMap = new HashMap<>();
                        SQLStatement stmt = SQLBuilder.buildDeleteSql(entity);
                        CascadeSQLiteImpl.this.deleteRecursive(stmt, entity, db2, handleMap);
                        while (iterator.hasNext()) {
                            Object next = iterator.next();
                            stmt.bindArgs = CascadeSQLiteImpl.getDeleteStatementArgs(next);
                            CascadeSQLiteImpl.this.deleteRecursive(stmt, next, db2, handleMap);
                        }
                        return Integer.valueOf(collection.size());
                    }
                });
                if (rowID != null) {
                    return rowID.intValue();
                }
                return -1;
            }
            return -1;
        }
        return -1;
    }

    public static Object[] getDeleteStatementArgs(Object entity) throws IllegalAccessException {
        EntityTable table = TableManager.getTable(entity);
        if (table.key != null) {
            return new String[]{String.valueOf(FieldUtil.get(table.key.field, entity))};
        }
        if (!Checker.isEmpty(table.pmap)) {
            Object[] args = new Object[table.pmap.size()];
            int i = 0;
            for (Property p : table.pmap.values()) {
                args[i] = FieldUtil.get(p.field, entity);
                i++;
            }
            return args;
        }
        return null;
    }

    private long handleEntityRecursive(int type, SQLStatement stmt, Object obj1, SQLiteDatabase db, HashMap<String, Integer> handleMap) throws Exception {
        Object key1;
        long rowID;
        EntityTable table1 = TableManager.getTable(obj1);
        Object key12 = FieldUtil.get(table1.key.field, obj1);
        if (handleMap.get(table1.name + key12) == null) {
            if (type != 1) {
                if (type != 2) {
                    if (type != 3) {
                        key1 = key12;
                        rowID = -1;
                    } else {
                        long rowID2 = stmt.execDelete(db);
                        key1 = key12;
                        rowID = rowID2;
                    }
                } else {
                    long rowID3 = stmt.execUpdate(db);
                    key1 = key12;
                    rowID = rowID3;
                }
            } else {
                long rowID4 = stmt.execInsert(db, obj1);
                key1 = FieldUtil.get(table1.key.field, obj1);
                rowID = rowID4;
            }
            handleMap.put(table1.name + key1, 1);
            boolean insertNew = type != 3;
            handleMapping(key1, obj1, db, insertNew, handleMap);
            return rowID;
        }
        return -1L;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int updateRecursive(SQLStatement stmt, Object obj1, SQLiteDatabase db, HashMap<String, Integer> handleMap) throws Exception {
        EntityTable table1 = TableManager.getTable(obj1);
        if (handleMap.get(table1.name + FieldUtil.get(table1.key.field, obj1)) != null) {
            return -1;
        }
        int rowID = stmt.execUpdate(db);
        Object key1 = FieldUtil.get(table1.key.field, obj1);
        handleMap.put(table1.name + key1, 1);
        handleMapping(key1, obj1, db, true, handleMap);
        return rowID;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int deleteRecursive(SQLStatement stmt, Object obj1, SQLiteDatabase db, HashMap<String, Integer> handleMap) throws Exception {
        EntityTable table1 = TableManager.getTable(obj1);
        Object key1 = FieldUtil.get(table1.key.field, obj1);
        if (handleMap.get(table1.name + key1) != null) {
            return -1;
        }
        int rowID = stmt.execDelete(db);
        handleMap.put(table1.name + key1, 1);
        handleMapping(key1, obj1, db, false, handleMap);
        return rowID;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public long insertRecursive(SQLStatement stmt, Object obj1, SQLiteDatabase db, HashMap<String, Integer> handleMap) throws Exception {
        EntityTable table1 = TableManager.getTable(obj1);
        if (handleMap.get(table1.name + FieldUtil.get(table1.key.field, obj1)) != null) {
            return -1L;
        }
        long rowID = stmt.execInsert(db, obj1);
        Object key1 = FieldUtil.get(table1.key.field, obj1);
        handleMap.put(table1.name + key1, 1);
        handleMapping(key1, obj1, db, true, handleMap);
        return rowID;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public long checkTableAndSaveRecursive(Object obj1, SQLiteDatabase db, HashMap<String, Integer> handleMap) throws Exception {
        this.mTableManager.checkOrCreateTable(db, obj1);
        return insertRecursive(SQLBuilder.buildReplaceSql(obj1), obj1, db, handleMap);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int checkTableAndDeleteRecursive(Object obj1, SQLiteDatabase db, HashMap<String, Integer> handleMap) throws Exception {
        EntityTable table = TableManager.getTable(obj1);
        if (this.mTableManager.isSQLTableCreated(table.name)) {
            return deleteRecursive(SQLBuilder.buildDeleteSql(obj1), obj1, db, handleMap);
        }
        return -1;
    }

    private void handleMapping(Object key1, Object obj1, SQLiteDatabase db, boolean insertNew, HashMap<String, Integer> handleMap) throws Exception {
        EntityTable table1 = TableManager.getTable(obj1);
        if (table1.mappingList != null) {
            for (MapProperty map : table1.mappingList) {
                if (map.isToOne()) {
                    Object obj2 = FieldUtil.get(map.field, obj1);
                    EntityTable table2 = TableManager.getTable(map.field.getType());
                    handleMapToOne(table1, table2, key1, obj2, db, insertNew, handleMap);
                } else if (map.isToMany()) {
                    Object array = FieldUtil.get(map.field, obj1);
                    if (ClassUtil.isCollection(map.field.getType())) {
                        EntityTable table22 = TableManager.getTable(FieldUtil.getGenericType(map.field));
                        handleMapToMany(table1, table22, key1, (Collection) array, db, insertNew, handleMap);
                    } else if (ClassUtil.isArray(map.field.getType())) {
                        EntityTable table23 = TableManager.getTable(FieldUtil.getComponentType(map.field));
                        Collection<?> coll = null;
                        if (array != null) {
                            coll = Arrays.asList((Object[]) array);
                        }
                        handleMapToMany(table1, table23, key1, coll, db, insertNew, handleMap);
                    } else {
                        throw new RuntimeException("OneToMany and ManyToMany Relation, you must use collection or array object");
                    }
                } else {
                    continue;
                }
            }
        }
    }

    private void handleMapToOne(EntityTable table1, EntityTable table2, Object key1, Object obj2, SQLiteDatabase db, boolean insertNew, HashMap<String, Integer> handleMap) throws Exception {
        if (obj2 != null) {
            if (insertNew) {
                checkTableAndSaveRecursive(obj2, db, handleMap);
            } else {
                checkTableAndDeleteRecursive(obj2, db, handleMap);
            }
        }
        String mapTableName = TableManager.getMapTableName(table1, table2);
        this.mTableManager.checkOrCreateMappingTable(db, mapTableName, table1.name, table2.name);
        SQLBuilder.buildMappingDeleteSql(mapTableName, key1, table1).execDelete(db);
        if (insertNew && obj2 != null) {
            Object key2 = FieldUtil.get(table2.key.field, obj2);
            SQLStatement st = SQLBuilder.buildMappingToOneSql(mapTableName, key1, key2, table1, table2);
            if (st != null) {
                st.execInsert(db);
            }
        }
    }

    private void handleMapToMany(EntityTable table1, EntityTable table2, Object key1, Collection coll, SQLiteDatabase db, boolean insertNew, HashMap<String, Integer> handleMap) throws Exception {
        if (coll != null) {
            for (Object obj2 : coll) {
                if (obj2 != null) {
                    if (insertNew) {
                        checkTableAndSaveRecursive(obj2, db, handleMap);
                    } else {
                        checkTableAndDeleteRecursive(obj2, db, handleMap);
                    }
                }
            }
        }
        String tableName = TableManager.getMapTableName(table1, table2);
        this.mTableManager.checkOrCreateMappingTable(db, tableName, table1.name, table2.name);
        SQLStatement delSql = SQLBuilder.buildMappingDeleteSql(tableName, key1, table1);
        delSql.execDelete(db);
        if (insertNew && !Checker.isEmpty((Collection<?>) coll)) {
            ArrayList<SQLStatement> sqlList = SQLBuilder.buildMappingToManySql(key1, table1, table2, coll);
            if (!Checker.isEmpty(sqlList)) {
                for (SQLStatement sql : sqlList) {
                    sql.execInsert(db);
                }
            }
        }
    }
}
