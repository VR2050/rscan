package com.litesuits.orm.db.impl;

import android.database.sqlite.SQLiteDatabase;
import com.litesuits.orm.LiteOrm;
import com.litesuits.orm.db.DataBaseConfig;
import com.litesuits.orm.db.TableManager;
import com.litesuits.orm.db.assit.Checker;
import com.litesuits.orm.db.assit.CollSpliter;
import com.litesuits.orm.db.assit.QueryBuilder;
import com.litesuits.orm.db.assit.SQLBuilder;
import com.litesuits.orm.db.assit.SQLStatement;
import com.litesuits.orm.db.assit.WhereBuilder;
import com.litesuits.orm.db.model.ColumnsValue;
import com.litesuits.orm.db.model.ConflictAlgorithm;
import com.litesuits.orm.db.model.EntityTable;
import java.util.ArrayList;
import java.util.Collection;

/* JADX INFO: loaded from: classes3.dex */
public final class SingleSQLiteImpl extends LiteOrm {
    public static final String TAG = SingleSQLiteImpl.class.getSimpleName();

    protected SingleSQLiteImpl(LiteOrm dataBase) {
        super(dataBase);
    }

    private SingleSQLiteImpl(DataBaseConfig config) {
        super(config);
    }

    public static synchronized LiteOrm newInstance(DataBaseConfig config) {
        return new SingleSQLiteImpl(config);
    }

    @Override // com.litesuits.orm.LiteOrm
    public LiteOrm single() {
        return this;
    }

    @Override // com.litesuits.orm.LiteOrm
    public LiteOrm cascade() {
        if (this.otherDatabase == null) {
            this.otherDatabase = new CascadeSQLiteImpl(this);
        }
        return this.otherDatabase;
    }

    @Override // com.litesuits.orm.db.DataBase
    public long save(Object entity) {
        acquireReference();
        try {
            try {
                SQLiteDatabase db = this.mHelper.getWritableDatabase();
                this.mTableManager.checkOrCreateTable(db, entity);
                return SQLBuilder.buildReplaceSql(entity).execInsert(db, entity);
            } catch (Exception e) {
                e.printStackTrace();
                releaseReference();
                return -1L;
            }
        } finally {
            releaseReference();
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> int save(Collection<T> collection) {
        acquireReference();
        try {
            try {
                if (!Checker.isEmpty((Collection<?>) collection)) {
                    SQLiteDatabase db = this.mHelper.getWritableDatabase();
                    Object entity = collection.iterator().next();
                    this.mTableManager.checkOrCreateTable(db, entity);
                    SQLStatement stmt = SQLBuilder.buildReplaceAllSql(entity);
                    return stmt.execInsertCollection(db, collection);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return -1;
        } finally {
            releaseReference();
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    public long insert(Object entity) {
        return insert(entity, (ConflictAlgorithm) null);
    }

    @Override // com.litesuits.orm.db.DataBase
    public long insert(Object entity, ConflictAlgorithm conflictAlgorithm) {
        acquireReference();
        try {
            try {
                SQLiteDatabase db = this.mHelper.getWritableDatabase();
                this.mTableManager.checkOrCreateTable(db, entity);
                return SQLBuilder.buildInsertSql(entity, conflictAlgorithm).execInsert(db, entity);
            } catch (Exception e) {
                e.printStackTrace();
                releaseReference();
                return -1L;
            }
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
                if (!Checker.isEmpty((Collection<?>) collection)) {
                    SQLiteDatabase db = this.mHelper.getWritableDatabase();
                    Object entity = collection.iterator().next();
                    SQLStatement stmt = SQLBuilder.buildInsertAllSql(entity, conflictAlgorithm);
                    this.mTableManager.checkOrCreateTable(db, entity);
                    return stmt.execInsertCollection(db, collection);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return -1;
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
    public int update(Object entity, ColumnsValue cvs, ConflictAlgorithm conflictAlgorithm) {
        acquireReference();
        try {
            try {
                SQLiteDatabase db = this.mHelper.getWritableDatabase();
                this.mTableManager.checkOrCreateTable(db, entity);
                return SQLBuilder.buildUpdateSql(entity, cvs, conflictAlgorithm).execUpdate(db);
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
                if (!Checker.isEmpty((Collection<?>) collection)) {
                    SQLiteDatabase db = this.mHelper.getWritableDatabase();
                    Object entity = collection.iterator().next();
                    this.mTableManager.checkOrCreateTable(db, entity);
                    SQLStatement stmt = SQLBuilder.buildUpdateAllSql(entity, cvs, conflictAlgorithm);
                    return stmt.execUpdateCollection(db, collection, cvs);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return -1;
        } finally {
            releaseReference();
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    public int delete(Object entity) {
        EntityTable table = TableManager.getTable(entity);
        if (this.mTableManager.isSQLTableCreated(table.name)) {
            acquireReference();
            try {
                SQLiteDatabase db = this.mHelper.getWritableDatabase();
                return SQLBuilder.buildDeleteSql(entity).execDelete(db);
            } catch (Exception e) {
                e.printStackTrace();
                return -1;
            } finally {
                releaseReference();
            }
        }
        return -1;
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> int delete(Class<T> claxx) {
        return deleteAll(claxx);
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> int delete(Collection<T> collection) {
        Throwable th;
        acquireReference();
        try {
            try {
                if (!Checker.isEmpty((Collection<?>) collection)) {
                    EntityTable table = TableManager.getTable(collection.iterator().next());
                    if (this.mTableManager.isSQLTableCreated(table.name)) {
                        final SQLiteDatabase db = this.mHelper.getWritableDatabase();
                        db.beginTransaction();
                        try {
                            int rows = CollSpliter.split(collection, SQLStatement.IN_TOP_LIMIT, new CollSpliter.Spliter<T>() { // from class: com.litesuits.orm.db.impl.SingleSQLiteImpl.1
                                @Override // com.litesuits.orm.db.assit.CollSpliter.Spliter
                                public int oneSplit(ArrayList<T> list) throws Exception {
                                    return SQLBuilder.buildDeleteSql((Collection<?>) list).execDeleteCollection(db, list);
                                }
                            });
                            try {
                                db.setTransactionSuccessful();
                                db.endTransaction();
                                return rows;
                            } catch (Throwable th2) {
                                th = th2;
                                db.endTransaction();
                                throw th;
                            }
                        } catch (Throwable th3) {
                            th = th3;
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return -1;
        } finally {
            releaseReference();
        }
    }

    @Override // com.litesuits.orm.db.DataBase
    @Deprecated
    public <T> int delete(Class<T> claxx, WhereBuilder where) {
        return delete(where);
    }

    @Override // com.litesuits.orm.db.DataBase
    public int delete(WhereBuilder where) {
        EntityTable table = TableManager.getTable(where.getTableClass(), false);
        if (this.mTableManager.isSQLTableCreated(table.name)) {
            acquireReference();
            try {
                SQLiteDatabase db = this.mHelper.getWritableDatabase();
                return where.createStatementDelete().execDelete(db);
            } catch (Exception e) {
                e.printStackTrace();
                return -1;
            } finally {
                releaseReference();
            }
        }
        return -1;
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> int deleteAll(Class<T> claxx) {
        EntityTable table = TableManager.getTable(claxx, false);
        if (this.mTableManager.isSQLTableCreated(table.name)) {
            acquireReference();
            try {
                SQLiteDatabase db = this.mHelper.getWritableDatabase();
                SQLStatement stmt = SQLBuilder.buildDeleteAllSql(claxx);
                return stmt.execDelete(db);
            } catch (Exception e) {
                e.printStackTrace();
                return -1;
            } finally {
                releaseReference();
            }
        }
        return -1;
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> int delete(Class<T> claxx, long start, long end, String orderAscColumn) throws Throwable {
        Throwable th;
        long end2;
        Exception e;
        EntityTable table = TableManager.getTable(claxx, false);
        if (!this.mTableManager.isSQLTableCreated(table.name)) {
            return -1;
        }
        acquireReference();
        if (start >= 0 && end >= start) {
            if (start != 0) {
                start--;
            }
            end2 = end == 2147483647L ? -1L : end - start;
            try {
                try {
                    SQLStatement stmt = SQLBuilder.buildDeleteSql(claxx, start, end2, orderAscColumn);
                    SQLiteDatabase db = this.mHelper.getWritableDatabase();
                    int iExecDelete = stmt.execDelete(db);
                    releaseReference();
                    return iExecDelete;
                } catch (Exception e2) {
                    e = e2;
                    e.printStackTrace();
                    releaseReference();
                    return -1;
                }
            } catch (Throwable th2) {
                th = th2;
                releaseReference();
                throw th;
            }
        }
        try {
            throw new RuntimeException("start must >=0 and smaller than end");
        } catch (Exception e3) {
            end2 = end;
            e = e3;
        } catch (Throwable th3) {
            th = th3;
            releaseReference();
            throw th;
        }
        e.printStackTrace();
        releaseReference();
        return -1;
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> ArrayList<T> query(Class<T> claxx) {
        return query(new QueryBuilder<>(claxx));
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> ArrayList<T> query(QueryBuilder<T> qb) {
        EntityTable table = TableManager.getTable(qb.getQueryClass(), false);
        if (this.mTableManager.isSQLTableCreated(table.name)) {
            acquireReference();
            try {
                return qb.createStatement().query(this.mHelper.getReadableDatabase(), qb.getQueryClass());
            } finally {
                releaseReference();
            }
        }
        return new ArrayList<>();
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> T queryById(long j, Class<T> cls) {
        return (T) queryById(String.valueOf(j), cls);
    }

    @Override // com.litesuits.orm.db.DataBase
    public <T> T queryById(String id, Class<T> claxx) {
        EntityTable table = TableManager.getTable(claxx, false);
        if (this.mTableManager.isSQLTableCreated(table.name)) {
            acquireReference();
            try {
                SQLStatement stmt = new QueryBuilder(claxx).where(table.key.column + "=?", id).createStatement();
                ArrayList<T> list = stmt.query(this.mHelper.getReadableDatabase(), claxx);
                if (!Checker.isEmpty(list)) {
                    return list.get(0);
                }
                return null;
            } finally {
                releaseReference();
            }
        }
        return null;
    }
}
