package androidx.room.paging;

import android.database.Cursor;
import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.paging.PositionalDataSource;
import androidx.room.InvalidationTracker;
import androidx.room.RoomDatabase;
import androidx.room.RoomSQLiteQuery;
import androidx.sqlite.p004db.SupportSQLiteQuery;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import p005b.p131d.p132a.p133a.C1499a;

@RestrictTo({RestrictTo.Scope.LIBRARY_GROUP_PREFIX})
/* loaded from: classes.dex */
public abstract class LimitOffsetDataSource<T> extends PositionalDataSource<T> {
    private final String mCountQuery;
    private final RoomDatabase mDb;
    private final boolean mInTransaction;
    private final String mLimitOffsetQuery;
    private final InvalidationTracker.Observer mObserver;
    private final RoomSQLiteQuery mSourceQuery;

    public LimitOffsetDataSource(RoomDatabase roomDatabase, SupportSQLiteQuery supportSQLiteQuery, boolean z, String... strArr) {
        this(roomDatabase, RoomSQLiteQuery.copyFrom(supportSQLiteQuery), z, strArr);
    }

    private RoomSQLiteQuery getSQLiteQuery(int i2, int i3) {
        RoomSQLiteQuery acquire = RoomSQLiteQuery.acquire(this.mLimitOffsetQuery, this.mSourceQuery.getArgCount() + 2);
        acquire.copyArgumentsFrom(this.mSourceQuery);
        acquire.bindLong(acquire.getArgCount() - 1, i3);
        acquire.bindLong(acquire.getArgCount(), i2);
        return acquire;
    }

    public abstract List<T> convertRows(Cursor cursor);

    public int countItems() {
        RoomSQLiteQuery acquire = RoomSQLiteQuery.acquire(this.mCountQuery, this.mSourceQuery.getArgCount());
        acquire.copyArgumentsFrom(this.mSourceQuery);
        Cursor query = this.mDb.query(acquire);
        try {
            if (query.moveToFirst()) {
                return query.getInt(0);
            }
            return 0;
        } finally {
            query.close();
            acquire.release();
        }
    }

    public boolean isInvalid() {
        this.mDb.getInvalidationTracker().refreshVersionsSync();
        return super.isInvalid();
    }

    public void loadInitial(@NonNull PositionalDataSource.LoadInitialParams loadInitialParams, @NonNull PositionalDataSource.LoadInitialCallback<T> loadInitialCallback) {
        RoomSQLiteQuery roomSQLiteQuery;
        int i2;
        RoomSQLiteQuery roomSQLiteQuery2;
        List<T> emptyList = Collections.emptyList();
        this.mDb.beginTransaction();
        Cursor cursor = null;
        try {
            int countItems = countItems();
            if (countItems != 0) {
                int computeInitialLoadPosition = computeInitialLoadPosition(loadInitialParams, countItems);
                roomSQLiteQuery = getSQLiteQuery(computeInitialLoadPosition, computeInitialLoadSize(loadInitialParams, computeInitialLoadPosition, countItems));
                try {
                    cursor = this.mDb.query(roomSQLiteQuery);
                    List<T> convertRows = convertRows(cursor);
                    this.mDb.setTransactionSuccessful();
                    roomSQLiteQuery2 = roomSQLiteQuery;
                    i2 = computeInitialLoadPosition;
                    emptyList = convertRows;
                } catch (Throwable th) {
                    th = th;
                    if (cursor != null) {
                        cursor.close();
                    }
                    this.mDb.endTransaction();
                    if (roomSQLiteQuery != null) {
                        roomSQLiteQuery.release();
                    }
                    throw th;
                }
            } else {
                i2 = 0;
                roomSQLiteQuery2 = null;
            }
            if (cursor != null) {
                cursor.close();
            }
            this.mDb.endTransaction();
            if (roomSQLiteQuery2 != null) {
                roomSQLiteQuery2.release();
            }
            loadInitialCallback.onResult(emptyList, i2, countItems);
        } catch (Throwable th2) {
            th = th2;
            roomSQLiteQuery = null;
        }
    }

    public void loadRange(@NonNull PositionalDataSource.LoadRangeParams loadRangeParams, @NonNull PositionalDataSource.LoadRangeCallback<T> loadRangeCallback) {
        loadRangeCallback.onResult(loadRange(loadRangeParams.startPosition, loadRangeParams.loadSize));
    }

    public LimitOffsetDataSource(RoomDatabase roomDatabase, RoomSQLiteQuery roomSQLiteQuery, boolean z, String... strArr) {
        this.mDb = roomDatabase;
        this.mSourceQuery = roomSQLiteQuery;
        this.mInTransaction = z;
        StringBuilder m586H = C1499a.m586H("SELECT COUNT(*) FROM ( ");
        m586H.append(roomSQLiteQuery.getSql());
        m586H.append(" )");
        this.mCountQuery = m586H.toString();
        StringBuilder m586H2 = C1499a.m586H("SELECT * FROM ( ");
        m586H2.append(roomSQLiteQuery.getSql());
        m586H2.append(" ) LIMIT ? OFFSET ?");
        this.mLimitOffsetQuery = m586H2.toString();
        InvalidationTracker.Observer observer = new InvalidationTracker.Observer(strArr) { // from class: androidx.room.paging.LimitOffsetDataSource.1
            @Override // androidx.room.InvalidationTracker.Observer
            public void onInvalidated(@NonNull Set<String> set) {
                LimitOffsetDataSource.this.invalidate();
            }
        };
        this.mObserver = observer;
        roomDatabase.getInvalidationTracker().addWeakObserver(observer);
    }

    @NonNull
    public List<T> loadRange(int i2, int i3) {
        RoomSQLiteQuery sQLiteQuery = getSQLiteQuery(i2, i3);
        if (!this.mInTransaction) {
            Cursor query = this.mDb.query(sQLiteQuery);
            try {
                return convertRows(query);
            } finally {
                query.close();
                sQLiteQuery.release();
            }
        }
        this.mDb.beginTransaction();
        Cursor cursor = null;
        try {
            cursor = this.mDb.query(sQLiteQuery);
            List<T> convertRows = convertRows(cursor);
            this.mDb.setTransactionSuccessful();
            return convertRows;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
            this.mDb.endTransaction();
            sQLiteQuery.release();
        }
    }
}
