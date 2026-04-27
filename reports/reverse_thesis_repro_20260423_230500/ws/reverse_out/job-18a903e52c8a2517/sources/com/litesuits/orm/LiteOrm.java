package com.litesuits.orm;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteClosable;
import android.database.sqlite.SQLiteDatabase;
import com.litesuits.orm.db.DataBase;
import com.litesuits.orm.db.DataBaseConfig;
import com.litesuits.orm.db.TableManager;
import com.litesuits.orm.db.assit.Checker;
import com.litesuits.orm.db.assit.CollSpliter;
import com.litesuits.orm.db.assit.Querier;
import com.litesuits.orm.db.assit.QueryBuilder;
import com.litesuits.orm.db.assit.SQLBuilder;
import com.litesuits.orm.db.assit.SQLStatement;
import com.litesuits.orm.db.assit.SQLiteHelper;
import com.litesuits.orm.db.assit.WhereBuilder;
import com.litesuits.orm.db.impl.CascadeSQLiteImpl;
import com.litesuits.orm.db.impl.SingleSQLiteImpl;
import com.litesuits.orm.db.model.ColumnsValue;
import com.litesuits.orm.db.model.ConflictAlgorithm;
import com.litesuits.orm.db.model.EntityTable;
import com.litesuits.orm.db.model.MapProperty;
import com.litesuits.orm.db.model.RelationKey;
import com.litesuits.orm.db.utils.ClassUtil;
import com.litesuits.orm.db.utils.DataUtil;
import com.litesuits.orm.db.utils.FieldUtil;
import com.litesuits.orm.log.OrmLog;
import java.io.File;
import java.io.FileFilter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public abstract class LiteOrm extends SQLiteClosable implements DataBase {
    public static final String TAG = LiteOrm.class.getSimpleName();
    protected DataBaseConfig mConfig;
    protected SQLiteHelper mHelper;
    protected TableManager mTableManager;
    protected LiteOrm otherDatabase;

    public abstract LiteOrm cascade();

    public abstract LiteOrm single();

    protected LiteOrm(LiteOrm dataBase) {
        this.mHelper = dataBase.mHelper;
        this.mConfig = dataBase.mConfig;
        this.mTableManager = dataBase.mTableManager;
        this.otherDatabase = dataBase;
    }

    protected LiteOrm(DataBaseConfig config) {
        config.context = config.context.getApplicationContext();
        if (config.dbName == null) {
            config.dbName = DataBaseConfig.DEFAULT_DB_NAME;
        }
        if (config.dbVersion <= 0) {
            config.dbVersion = 1;
        }
        this.mConfig = config;
        setDebugged(config.debugged);
        openOrCreateDatabase();
    }

    @Override // com.litesuits.orm.db.DataBase
    public SQLiteDatabase openOrCreateDatabase() {
        initDatabasePath(this.mConfig.dbName);
        if (this.mHelper != null) {
            justRelease();
        }
        this.mHelper = new SQLiteHelper(this.mConfig.context.getApplicationContext(), this.mConfig.dbName, null, this.mConfig.dbVersion, this.mConfig.onUpdateListener);
        this.mTableManager = new TableManager(this.mConfig.dbName, this.mHelper.getReadableDatabase());
        return this.mHelper.getWritableDatabase();
    }

    private void initDatabasePath(String path) {
        OrmLog.i(TAG, "create  database path: " + path);
        String path2 = this.mConfig.context.getDatabasePath(this.mConfig.dbName).getPath();
        OrmLog.i(TAG, "context database path: " + path2);
        File dbp = new File(path2).getParentFile();
        if (dbp != null && !dbp.exists()) {
            boolean mks = dbp.mkdirs();
            OrmLog.i(TAG, "create database, parent file mkdirs: " + mks + "  path:" + dbp.getAbsolutePath());
        }
    }

    public static LiteOrm newSingleInstance(Context context, String dbName) {
        return newSingleInstance(new DataBaseConfig(context, dbName));
    }

    public static synchronized LiteOrm newSingleInstance(DataBaseConfig config) {
        return SingleSQLiteImpl.newInstance(config);
    }

    public static LiteOrm newCascadeInstance(Context context, String dbName) {
        return newCascadeInstance(new DataBaseConfig(context, dbName));
    }

    public static synchronized LiteOrm newCascadeInstance(DataBaseConfig config) {
        return CascadeSQLiteImpl.newInstance(config);
    }

    public void setDebugged(boolean debugged) {
        this.mConfig.debugged = debugged;
        OrmLog.isPrint = debugged;
    }

    @Override // com.litesuits.orm.db.DataBase
    public ArrayList<RelationKey> queryRelation(final Class class1, final Class class2, final List<String> key1List) throws Throwable {
        final EntityTable table1;
        final EntityTable table2;
        acquireReference();
        final ArrayList<RelationKey> rList = new ArrayList<>();
        try {
            try {
                table1 = TableManager.getTable((Class<?>) class1);
                table2 = TableManager.getTable((Class<?>) class2);
            } catch (Throwable th) {
                th = th;
                releaseReference();
                throw th;
            }
            try {
            } catch (Exception e) {
                e = e;
            } catch (Throwable th2) {
                th = th2;
                releaseReference();
                throw th;
            }
        } catch (Exception e2) {
            e = e2;
        } catch (Throwable th3) {
            th = th3;
        }
        if (!this.mTableManager.isSQLMapTableCreated(table1.name, table2.name)) {
            releaseReference();
            return rList;
        }
        try {
            CollSpliter.split(key1List, SQLStatement.IN_TOP_LIMIT, new CollSpliter.Spliter<String>() { // from class: com.litesuits.orm.LiteOrm.1
                @Override // com.litesuits.orm.db.assit.CollSpliter.Spliter
                public int oneSplit(ArrayList<String> list) throws Exception {
                    SQLStatement stmt = SQLBuilder.buildQueryRelationSql(class1, class2, (List<String>) key1List);
                    Querier.doQuery(LiteOrm.this.mHelper.getReadableDatabase(), stmt, new Querier.CursorParser() { // from class: com.litesuits.orm.LiteOrm.1.1
                        @Override // com.litesuits.orm.db.assit.Querier.CursorParser
                        public void parseEachCursor(SQLiteDatabase db, Cursor c) throws Exception {
                            RelationKey relation = new RelationKey();
                            relation.key1 = c.getString(c.getColumnIndex(table1.name));
                            relation.key2 = c.getString(c.getColumnIndex(table2.name));
                            rList.add(relation);
                        }
                    });
                    return 0;
                }
            });
        } catch (Exception e3) {
            e = e3;
            e.printStackTrace();
        }
        releaseReference();
        return rList;
        e.printStackTrace();
        releaseReference();
        return rList;
    }

    @Override // com.litesuits.orm.db.DataBase
    public <E, T> boolean mapping(Collection<E> col1, Collection<T> col2) {
        if (Checker.isEmpty((Collection<?>) col1) || Checker.isEmpty((Collection<?>) col2)) {
            return false;
        }
        acquireReference();
        try {
            return keepMapping(col1, col2) | keepMapping(col2, col1);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        } finally {
            releaseReference();
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    public SQLStatement createSQLStatement(String sql, Object[] bindArgs) {
        return new SQLStatement(sql, bindArgs);
    }

    @Override // com.litesuits.orm.db.DataBase
    public boolean execute(SQLiteDatabase db, SQLStatement statement) {
        acquireReference();
        if (statement != null) {
            try {
                try {
                    return statement.execute(db);
                } catch (Exception e) {
                    e.printStackTrace();
                    releaseReference();
                    return false;
                }
            } finally {
                releaseReference();
            }
        }
        releaseReference();
        return false;
    }

    @Override // com.litesuits.orm.db.DataBase
    @Deprecated
    public boolean dropTable(Object entity) {
        return dropTable(entity.getClass());
    }

    @Override // com.litesuits.orm.db.DataBase
    public boolean dropTable(Class<?> claxx) {
        return dropTable(TableManager.getTable(claxx, false).name);
    }

    @Override // com.litesuits.orm.db.DataBase
    public boolean dropTable(String tableName) {
        acquireReference();
        try {
            try {
                return SQLBuilder.buildDropTable(tableName).execute(this.mHelper.getWritableDatabase());
            } catch (Exception e) {
                e.printStackTrace();
                releaseReference();
                return false;
            }
        } finally {
            releaseReference();
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> long queryCount(Class<T> claxx) {
        return queryCount(new QueryBuilder(claxx));
    }

    @Override // com.litesuits.orm.db.DataBase
    public long queryCount(QueryBuilder qb) {
        acquireReference();
        try {
            try {
                if (!this.mTableManager.isSQLTableCreated(qb.getTableName())) {
                    return 0L;
                }
                SQLiteDatabase db = this.mHelper.getReadableDatabase();
                SQLStatement stmt = qb.createStatementForCount();
                return stmt.queryForLong(db);
            } catch (Exception e) {
                e.printStackTrace();
                releaseReference();
                return -1L;
            }
        } finally {
            releaseReference();
        }
        releaseReference();
    }

    @Override // com.litesuits.orm.db.DataBase
    public int update(WhereBuilder where, ColumnsValue cvs, ConflictAlgorithm conflictAlgorithm) {
        acquireReference();
        try {
            try {
                SQLiteDatabase db = this.mHelper.getWritableDatabase();
                SQLStatement stmt = SQLBuilder.buildUpdateSql(where, cvs, conflictAlgorithm);
                return stmt.execUpdate(db);
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
    public synchronized SQLiteDatabase getReadableDatabase() {
        return this.mHelper.getReadableDatabase();
    }

    @Override // com.litesuits.orm.db.DataBase
    public synchronized SQLiteDatabase getWritableDatabase() {
        return this.mHelper.getWritableDatabase();
    }

    @Override // com.litesuits.orm.db.DataBase
    public TableManager getTableManager() {
        return this.mTableManager;
    }

    @Override // com.litesuits.orm.db.DataBase
    public SQLiteHelper getSQLiteHelper() {
        return this.mHelper;
    }

    @Override // com.litesuits.orm.db.DataBase
    public DataBaseConfig getDataBaseConfig() {
        return this.mConfig;
    }

    @Override // com.litesuits.orm.db.DataBase
    public SQLiteDatabase openOrCreateDatabase(String path, SQLiteDatabase.CursorFactory factory) {
        String path2 = this.mConfig.context.getDatabasePath(this.mConfig.dbName).getPath();
        return SQLiteDatabase.openOrCreateDatabase(path2, factory);
    }

    @Override // com.litesuits.orm.db.DataBase
    public boolean deleteDatabase() {
        String path = this.mHelper.getWritableDatabase().getPath();
        justRelease();
        OrmLog.i(TAG, "data has cleared. delete Database path: " + path);
        return deleteDatabase(new File(path));
    }

    @Override // com.litesuits.orm.db.DataBase
    public boolean deleteDatabase(File file) {
        acquireReference();
        try {
            try {
                if (file == null) {
                    throw new IllegalArgumentException("file must not be null");
                }
                boolean deleted = file.delete() | new File(file.getPath() + "-journal").delete() | new File(file.getPath() + "-shm").delete() | new File(file.getPath() + "-wal").delete();
                File dir = file.getParentFile();
                if (dir != null) {
                    final String prefix = file.getName() + "-mj";
                    FileFilter filter = new FileFilter() { // from class: com.litesuits.orm.LiteOrm.2
                        @Override // java.io.FileFilter
                        public boolean accept(File candidate) {
                            return candidate.getName().startsWith(prefix);
                        }
                    };
                    File[] arr$ = dir.listFiles(filter);
                    for (File masterJournal : arr$) {
                        deleted |= masterJournal.delete();
                    }
                }
                return deleted;
            } catch (Exception e) {
                e.printStackTrace();
                releaseReference();
                return false;
            }
        } finally {
            releaseReference();
        }
    }

    @Override // android.database.sqlite.SQLiteClosable, java.io.Closeable, java.lang.AutoCloseable, com.litesuits.orm.db.DataBase
    public synchronized void close() {
        releaseReference();
    }

    @Override // android.database.sqlite.SQLiteClosable
    protected void onAllReferencesReleased() {
        justRelease();
    }

    protected void justRelease() {
        SQLiteHelper sQLiteHelper = this.mHelper;
        if (sQLiteHelper != null) {
            sQLiteHelper.getWritableDatabase().close();
            this.mHelper.close();
            this.mHelper = null;
        }
        TableManager tableManager = this.mTableManager;
        if (tableManager != null) {
            tableManager.release();
            this.mTableManager = null;
        }
    }

    public static int releaseMemory() {
        return SQLiteDatabase.releaseMemory();
    }

    /* JADX WARN: Multi-variable type inference failed */
    private <E, T> boolean keepMapping(Collection<E> collection, Collection<T> collection2) throws Throwable {
        Class componentType;
        HashMap map;
        Iterator<E> it;
        EntityTable entityTable;
        ArrayList arrayList;
        Class cls;
        Object obj;
        Class cls2 = collection.iterator().next().getClass();
        Class cls3 = collection2.iterator().next().getClass();
        EntityTable table = TableManager.getTable((Class<?>) cls2);
        EntityTable table2 = TableManager.getTable((Class<?>) cls3);
        if (table.mappingList != null) {
            for (MapProperty mapProperty : table.mappingList) {
                Class type = mapProperty.field.getType();
                if (mapProperty.isToMany()) {
                    if (ClassUtil.isCollection(type)) {
                        componentType = FieldUtil.getGenericType(mapProperty.field);
                    } else if (type.isArray()) {
                        componentType = FieldUtil.getComponentType(mapProperty.field);
                    } else {
                        throw new RuntimeException("OneToMany and ManyToMany Relation, Must use collection or array object");
                    }
                } else {
                    componentType = type;
                }
                if (componentType == cls3) {
                    ArrayList arrayList2 = new ArrayList();
                    HashMap map2 = new HashMap();
                    for (E e : collection) {
                        if (e != null && (obj = FieldUtil.get(table.key.field, e)) != null) {
                            arrayList2.add(obj.toString());
                            map2.put(obj.toString(), e);
                        }
                    }
                    ArrayList<RelationKey> arrayListQueryRelation = queryRelation(cls2, cls3, arrayList2);
                    if (!Checker.isEmpty(arrayListQueryRelation)) {
                        HashMap map3 = new HashMap();
                        for (T t : collection2) {
                            if (t == null) {
                                cls = cls2;
                            } else {
                                Object obj2 = FieldUtil.get(table2.key.field, t);
                                if (obj2 == null) {
                                    cls = cls2;
                                } else {
                                    cls = cls2;
                                    map3.put(obj2.toString(), t);
                                }
                            }
                            cls2 = cls;
                        }
                        HashMap map4 = new HashMap();
                        for (RelationKey relationKey : arrayListQueryRelation) {
                            Object obj3 = map2.get(relationKey.key1);
                            Class cls4 = cls3;
                            Object obj4 = map3.get(relationKey.key2);
                            if (obj3 == null || obj4 == null) {
                                entityTable = table;
                            } else if (mapProperty.isToMany()) {
                                ArrayList arrayList3 = (ArrayList) map4.get(obj3);
                                if (arrayList3 != null) {
                                    entityTable = table;
                                    arrayList = arrayList3;
                                } else {
                                    entityTable = table;
                                    ArrayList arrayList4 = new ArrayList();
                                    map4.put(obj3, arrayList4);
                                    arrayList = arrayList4;
                                }
                                arrayList.add(obj4);
                            } else {
                                entityTable = table;
                                FieldUtil.set(mapProperty.field, obj3, obj4);
                            }
                            cls3 = cls4;
                            table = entityTable;
                        }
                        if (!Checker.isEmpty(map4)) {
                            Iterator<E> it2 = map4.entrySet().iterator();
                            while (it2.hasNext()) {
                                Map.Entry entry = (Map.Entry) it2.next();
                                Object key = entry.getKey();
                                Collection<? extends E> collection3 = (Collection) entry.getValue();
                                if (ClassUtil.isCollection(componentType)) {
                                    Collection collection4 = (Collection) FieldUtil.get(mapProperty.field, key);
                                    if (collection4 == null) {
                                        map = map4;
                                        FieldUtil.set(mapProperty.field, key, collection3);
                                    } else {
                                        map = map4;
                                        collection4.addAll(collection3);
                                    }
                                    it = it2;
                                } else {
                                    map = map4;
                                    if (!ClassUtil.isArray(componentType)) {
                                        it = it2;
                                    } else {
                                        Object[] objArr = (Object[]) ClassUtil.newArray(componentType, collection3.size());
                                        collection3.toArray(objArr);
                                        Object[] objArr2 = (Object[]) FieldUtil.get(mapProperty.field, key);
                                        if (objArr2 == null) {
                                            it = it2;
                                            FieldUtil.set(mapProperty.field, key, objArr);
                                        } else {
                                            it = it2;
                                            FieldUtil.set(mapProperty.field, key, DataUtil.concat(objArr2, objArr));
                                        }
                                    }
                                }
                                map4 = map;
                                it2 = it;
                            }
                            return true;
                        }
                        return true;
                    }
                }
                cls2 = cls2;
                cls3 = cls3;
                table = table;
            }
            return false;
        }
        return false;
    }
}
