package com.litesuits.orm.db.assit;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteStatement;
import android.os.Build;
import com.litesuits.orm.db.TableManager;
import com.litesuits.orm.db.assit.Querier;
import com.litesuits.orm.db.assit.Transaction;
import com.litesuits.orm.db.model.ColumnsValue;
import com.litesuits.orm.db.model.EntityTable;
import com.litesuits.orm.db.model.MapInfo;
import com.litesuits.orm.db.model.Property;
import com.litesuits.orm.db.utils.ClassUtil;
import com.litesuits.orm.db.utils.DataUtil;
import com.litesuits.orm.db.utils.FieldUtil;
import com.litesuits.orm.log.OrmLog;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

/* JADX INFO: loaded from: classes3.dex */
public class SQLStatement implements Serializable {
    public static final int IN_TOP_LIMIT = 999;
    public static final short NONE = -1;
    public static final short NORMAL = 0;
    private static final String TAG = SQLStatement.class.getSimpleName();
    private static final long serialVersionUID = -3790876762607683712L;
    public Object[] bindArgs;
    private SQLiteStatement mStatement;
    public String sql;

    public SQLStatement() {
    }

    public SQLStatement(String sql, Object[] args) {
        this.sql = sql;
        this.bindArgs = args;
    }

    protected void bind(int i, Object o) throws IOException {
        if (o == null) {
            this.mStatement.bindNull(i);
            return;
        }
        if ((o instanceof CharSequence) || (o instanceof Boolean) || (o instanceof Character)) {
            this.mStatement.bindString(i, String.valueOf(o));
            return;
        }
        if ((o instanceof Float) || (o instanceof Double)) {
            this.mStatement.bindDouble(i, ((Number) o).doubleValue());
            return;
        }
        if (o instanceof Number) {
            this.mStatement.bindLong(i, ((Number) o).longValue());
            return;
        }
        if (o instanceof Date) {
            this.mStatement.bindLong(i, ((Date) o).getTime());
            return;
        }
        if (o instanceof byte[]) {
            this.mStatement.bindBlob(i, (byte[]) o);
        } else if (o instanceof Serializable) {
            this.mStatement.bindBlob(i, DataUtil.objectToByte(o));
        } else {
            this.mStatement.bindNull(i);
        }
    }

    public long execInsert(SQLiteDatabase db) throws IllegalAccessException, IOException {
        return execInsertWithMapping(db, null, null);
    }

    public long execInsert(SQLiteDatabase db, Object entity) throws IllegalAccessException, IOException {
        return execInsertWithMapping(db, entity, null);
    }

    public long execInsertWithMapping(SQLiteDatabase db, Object entity, TableManager tableManager) throws IllegalAccessException, IOException {
        printSQL();
        this.mStatement = db.compileStatement(this.sql);
        Object keyObj = null;
        if (!Checker.isEmpty(this.bindArgs)) {
            keyObj = this.bindArgs[0];
            int i = 0;
            while (true) {
                Object[] objArr = this.bindArgs;
                if (i >= objArr.length) {
                    break;
                }
                bind(i + 1, objArr[i]);
                i++;
            }
        }
        try {
            long rowID = this.mStatement.executeInsert();
            realease();
            if (OrmLog.isPrint) {
                OrmLog.i(TAG, "SQL Execute Insert RowID --> " + rowID + "    sql: " + this.sql);
            }
            if (entity != null) {
                FieldUtil.setKeyValueIfneed(entity, TableManager.getTable(entity).key, keyObj, rowID);
            }
            if (tableManager != null) {
                mapRelationToDb(entity, true, true, db, tableManager);
            }
            return rowID;
        } catch (Throwable th) {
            realease();
            throw th;
        }
    }

    public int execInsertCollection(SQLiteDatabase db, Collection<?> list) {
        return execInsertCollectionWithMapping(db, list, null);
    }

    public int execInsertCollectionWithMapping(SQLiteDatabase db, Collection<?> list, TableManager tableManager) throws Throwable {
        EntityTable table;
        Object keyObj;
        printSQL();
        db.beginTransaction();
        if (OrmLog.isPrint) {
            OrmLog.i(TAG, "----> BeginTransaction[insert col]");
        }
        EntityTable table2 = null;
        try {
            try {
                try {
                    this.mStatement = db.compileStatement(this.sql);
                    boolean mapTableCheck = true;
                    for (Object obj : list) {
                        this.mStatement.clearBindings();
                        if (table2 == null) {
                            EntityTable table3 = TableManager.getTable(obj);
                            table = table3;
                        } else {
                            table = table2;
                        }
                        int j = 1;
                        try {
                            if (table.key != null) {
                                Object keyObj2 = FieldUtil.getAssignedKeyObject(table.key, obj);
                                int j2 = 1 + 1;
                                bind(1, keyObj2);
                                keyObj = keyObj2;
                                j = j2;
                            } else {
                                keyObj = null;
                            }
                            if (!Checker.isEmpty(table.pmap)) {
                                for (Property p : table.pmap.values()) {
                                    bind(j, FieldUtil.get(p.field, obj));
                                    j++;
                                }
                            }
                            long rowID = this.mStatement.executeInsert();
                            FieldUtil.setKeyValueIfneed(obj, table.key, keyObj, rowID);
                            if (tableManager != null) {
                                mapRelationToDb(obj, true, mapTableCheck, db, tableManager);
                                mapTableCheck = false;
                            }
                            table2 = table;
                        } catch (Exception e) {
                            e = e;
                            if (OrmLog.isPrint) {
                                OrmLog.e(TAG, "----> BeginTransaction[insert col] Failling");
                            }
                            e.printStackTrace();
                            realease();
                            db.endTransaction();
                            return -1;
                        } catch (Throwable th) {
                            th = th;
                            realease();
                            db.endTransaction();
                            throw th;
                        }
                    }
                    if (OrmLog.isPrint) {
                        OrmLog.i(TAG, "Exec insert [" + list.size() + "] rows , SQL: " + this.sql);
                    }
                    db.setTransactionSuccessful();
                    if (OrmLog.isPrint) {
                        OrmLog.i(TAG, "----> BeginTransaction[insert col] Successful");
                    }
                    int size = list.size();
                    realease();
                    db.endTransaction();
                    return size;
                } catch (Exception e2) {
                    e = e2;
                }
            } catch (Throwable th2) {
                th = th2;
            }
        } catch (Exception e3) {
            e = e3;
        } catch (Throwable th3) {
            th = th3;
        }
    }

    public int execUpdate(SQLiteDatabase db) throws IOException {
        return execUpdateWithMapping(db, null, null);
    }

    public int execUpdateWithMapping(SQLiteDatabase db, Object entity, TableManager tableManager) throws IOException {
        int rows;
        printSQL();
        this.mStatement = db.compileStatement(this.sql);
        if (!Checker.isEmpty(this.bindArgs)) {
            int i = 0;
            while (true) {
                Object[] objArr = this.bindArgs;
                if (i >= objArr.length) {
                    break;
                }
                bind(i + 1, objArr[i]);
                i++;
            }
        }
        if (Build.VERSION.SDK_INT < 11) {
            this.mStatement.execute();
            rows = 0;
        } else {
            rows = this.mStatement.executeUpdateDelete();
        }
        realease();
        if (OrmLog.isPrint) {
            OrmLog.i(TAG, "SQL Execute update, changed rows --> " + rows);
        }
        if (tableManager != null && entity != null) {
            mapRelationToDb(entity, true, true, db, tableManager);
        }
        return rows;
    }

    public int execUpdateCollection(SQLiteDatabase db, Collection<?> list, ColumnsValue cvs) {
        return execUpdateCollectionWithMapping(db, list, cvs, null);
    }

    public int execUpdateCollectionWithMapping(SQLiteDatabase db, Collection<?> list, ColumnsValue cvs, TableManager tableManager) {
        printSQL();
        db.beginTransaction();
        if (OrmLog.isPrint) {
            OrmLog.d(TAG, "----> BeginTransaction[update col]");
        }
        try {
            try {
                this.mStatement = db.compileStatement(this.sql);
                boolean mapTableCheck = true;
                EntityTable table = null;
                for (Object obj : list) {
                    this.mStatement.clearBindings();
                    if (table == null) {
                        table = TableManager.getTable(obj);
                    }
                    Object[] objArrBuildUpdateSqlArgsOnly = SQLBuilder.buildUpdateSqlArgsOnly(obj, cvs);
                    this.bindArgs = objArrBuildUpdateSqlArgsOnly;
                    if (!Checker.isEmpty(objArrBuildUpdateSqlArgsOnly)) {
                        for (int i = 0; i < this.bindArgs.length; i++) {
                            bind(i + 1, this.bindArgs[i]);
                        }
                    }
                    this.mStatement.execute();
                    if (tableManager != null) {
                        mapRelationToDb(obj, true, mapTableCheck, db, tableManager);
                        mapTableCheck = false;
                    }
                }
                if (OrmLog.isPrint) {
                    OrmLog.i(TAG, "Exec update [" + list.size() + "] rows , SQL: " + this.sql);
                }
                db.setTransactionSuccessful();
                if (OrmLog.isPrint) {
                    OrmLog.d(TAG, "----> BeginTransaction[update col] Successful");
                }
                return list.size();
            } catch (Exception e) {
                if (OrmLog.isPrint) {
                    OrmLog.e(TAG, "----> BeginTransaction[update col] Failling");
                }
                e.printStackTrace();
                realease();
                db.endTransaction();
                return -1;
            }
        } finally {
            realease();
            db.endTransaction();
        }
    }

    public int execDelete(SQLiteDatabase db) throws IOException {
        return execDeleteWithMapping(db, null, null);
    }

    public int execDeleteWithMapping(SQLiteDatabase db, Object entity, TableManager tableManager) throws IOException {
        int nums;
        printSQL();
        this.mStatement = db.compileStatement(this.sql);
        if (this.bindArgs != null) {
            int i = 0;
            while (true) {
                Object[] objArr = this.bindArgs;
                if (i >= objArr.length) {
                    break;
                }
                bind(i + 1, objArr[i]);
                i++;
            }
        }
        if (Build.VERSION.SDK_INT < 11) {
            this.mStatement.execute();
            nums = 0;
        } else {
            nums = this.mStatement.executeUpdateDelete();
        }
        if (OrmLog.isPrint) {
            OrmLog.v(TAG, "SQL execute delete, changed rows--> " + nums);
        }
        realease();
        if (tableManager != null && entity != null) {
            mapRelationToDb(entity, false, false, db, tableManager);
        }
        return nums;
    }

    public int execDeleteCollection(SQLiteDatabase db, Collection<?> collection) throws IOException {
        return execDeleteCollectionWithMapping(db, collection, null);
    }

    public int execDeleteCollectionWithMapping(SQLiteDatabase db, final Collection<?> collection, final TableManager tableManager) throws IOException {
        int nums;
        printSQL();
        this.mStatement = db.compileStatement(this.sql);
        if (this.bindArgs != null) {
            int i = 0;
            while (true) {
                Object[] objArr = this.bindArgs;
                if (i >= objArr.length) {
                    break;
                }
                bind(i + 1, objArr[i]);
                i++;
            }
        }
        int i2 = Build.VERSION.SDK_INT;
        if (i2 < 11) {
            this.mStatement.execute();
            nums = collection.size();
        } else {
            nums = this.mStatement.executeUpdateDelete();
        }
        if (OrmLog.isPrint) {
            OrmLog.v(TAG, "SQL execute delete, changed rows --> " + nums);
        }
        realease();
        if (tableManager != null) {
            Boolean suc = (Boolean) Transaction.execute(db, new Transaction.Worker<Boolean>() { // from class: com.litesuits.orm.db.assit.SQLStatement.1
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // com.litesuits.orm.db.assit.Transaction.Worker
                public Boolean doTransaction(SQLiteDatabase db2) throws Exception {
                    boolean mapTableCheck = true;
                    for (Object o : collection) {
                        SQLStatement.this.mapRelationToDb(o, false, mapTableCheck, db2, tableManager);
                        mapTableCheck = false;
                    }
                    return true;
                }
            });
            if (OrmLog.isPrint) {
                String str = TAG;
                StringBuilder sb = new StringBuilder();
                sb.append("Exec delete collection mapping: ");
                sb.append((suc == null || !suc.booleanValue()) ? "失败" : "成功");
                OrmLog.i(str, sb.toString());
            }
        }
        return nums;
    }

    public boolean execute(SQLiteDatabase db) {
        printSQL();
        try {
            try {
                this.mStatement = db.compileStatement(this.sql);
                if (this.bindArgs != null) {
                    for (int i = 0; i < this.bindArgs.length; i++) {
                        bind(i + 1, this.bindArgs[i]);
                    }
                }
                this.mStatement.execute();
                realease();
                return true;
            } catch (Exception e) {
                e.printStackTrace();
                realease();
                return false;
            }
        } catch (Throwable th) {
            realease();
            throw th;
        }
    }

    public long queryForLong(SQLiteDatabase db) {
        printSQL();
        long count = 0;
        try {
            try {
                this.mStatement = db.compileStatement(this.sql);
                if (this.bindArgs != null) {
                    for (int i = 0; i < this.bindArgs.length; i++) {
                        bind(i + 1, this.bindArgs[i]);
                    }
                }
                count = this.mStatement.simpleQueryForLong();
                if (OrmLog.isPrint) {
                    OrmLog.i(TAG, "SQL execute query for count --> " + count);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return count;
        } finally {
            realease();
        }
    }

    public <T> ArrayList<T> query(SQLiteDatabase db, final Class<T> claxx) {
        printSQL();
        final ArrayList<T> list = new ArrayList<>();
        try {
            final EntityTable table = TableManager.getTable(claxx, false);
            Querier.doQuery(db, this, new Querier.CursorParser() { // from class: com.litesuits.orm.db.assit.SQLStatement.2
                @Override // com.litesuits.orm.db.assit.Querier.CursorParser
                public void parseEachCursor(SQLiteDatabase db2, Cursor c) throws Exception {
                    Object objNewInstance = ClassUtil.newInstance(claxx);
                    DataUtil.injectDataToObject(c, objNewInstance, table);
                    list.add(objNewInstance);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
        return list;
    }

    public <T> T queryOneEntity(SQLiteDatabase sQLiteDatabase, final Class<T> cls) {
        printSQL();
        final EntityTable table = TableManager.getTable(cls, false);
        return (T) Querier.doQuery(sQLiteDatabase, this, new Querier.CursorParser<T>() { // from class: com.litesuits.orm.db.assit.SQLStatement.3
            T t;

            @Override // com.litesuits.orm.db.assit.Querier.CursorParser
            public void parseEachCursor(SQLiteDatabase sQLiteDatabase2, Cursor cursor) throws Exception {
                T t = (T) ClassUtil.newInstance(cls);
                this.t = t;
                DataUtil.injectDataToObject(cursor, t, table);
                stopParse();
            }

            @Override // com.litesuits.orm.db.assit.Querier.CursorParser
            public T returnResult() {
                return this.t;
            }
        });
    }

    public String toString() {
        return "SQLStatement [sql=" + this.sql + ", bindArgs=" + Arrays.toString(this.bindArgs) + ", mStatement=" + this.mStatement + "]";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void mapRelationToDb(Object entity, final boolean insertNew, final boolean tableCheck, SQLiteDatabase db, final TableManager tableManager) {
        final MapInfo mapTable = SQLBuilder.buildMappingInfo(entity, insertNew, tableManager);
        if (mapTable != null && !mapTable.isEmpty()) {
            Transaction.execute(db, new Transaction.Worker<Boolean>() { // from class: com.litesuits.orm.db.assit.SQLStatement.4
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // com.litesuits.orm.db.assit.Transaction.Worker
                public Boolean doTransaction(SQLiteDatabase db2) throws Exception {
                    if (insertNew && tableCheck) {
                        for (MapInfo.MapTable table : mapTable.tableList) {
                            tableManager.checkOrCreateMappingTable(db2, table.name, table.column1, table.column2);
                        }
                    }
                    if (mapTable.delOldRelationSQL != null) {
                        for (SQLStatement st : mapTable.delOldRelationSQL) {
                            long rowId = st.execDelete(db2);
                            if (OrmLog.isPrint) {
                                OrmLog.v(SQLStatement.TAG, "Exec delete mapping success, nums: " + rowId);
                            }
                        }
                    }
                    if (insertNew && mapTable.mapNewRelationSQL != null) {
                        for (SQLStatement st2 : mapTable.mapNewRelationSQL) {
                            long rowId2 = st2.execInsert(db2);
                            if (OrmLog.isPrint) {
                                OrmLog.v(SQLStatement.TAG, "Exec save mapping success, nums: " + rowId2);
                            }
                        }
                    }
                    return true;
                }
            });
        }
    }

    private void printSQL() {
        if (OrmLog.isPrint) {
            OrmLog.d(TAG, "SQL Execute: [" + this.sql + "] ARGS--> " + Arrays.toString(this.bindArgs));
        }
    }

    private void realease() {
        SQLiteStatement sQLiteStatement = this.mStatement;
        if (sQLiteStatement != null) {
            sQLiteStatement.close();
        }
        this.bindArgs = null;
        this.mStatement = null;
    }
}
