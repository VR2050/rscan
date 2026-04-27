package com.google.android.exoplayer2.offline;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.DatabaseUtils;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.net.Uri;
import com.google.android.exoplayer2.offline.DownloadStateCursor;
import com.google.android.exoplayer2.util.Assertions;
import com.google.android.exoplayer2.util.Util;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/* JADX INFO: loaded from: classes2.dex */
public final class DefaultDownloadIndex implements DownloadIndex {
    private static final String DATABASE_NAME = "exoplayer_internal.db";
    private final DatabaseProvider databaseProvider;
    private DownloadStateTable downloadStateTable;

    public interface DatabaseProvider {
        void close();

        SQLiteDatabase getReadableDatabase();

        SQLiteDatabase getWritableDatabase();
    }

    public DefaultDownloadIndex(Context context) {
        this(new DefaultDatabaseProvider(context));
    }

    public DefaultDownloadIndex(DatabaseProvider databaseProvider) {
        this.databaseProvider = databaseProvider;
    }

    @Override // com.google.android.exoplayer2.offline.DownloadIndex
    public void release() {
        this.databaseProvider.close();
    }

    @Override // com.google.android.exoplayer2.offline.DownloadIndex
    public DownloadState getDownloadState(String id) {
        return getDownloadStateTable().get(id);
    }

    @Override // com.google.android.exoplayer2.offline.DownloadIndex
    public DownloadStateCursor getDownloadStates(int... states) {
        return getDownloadStateTable().get(states);
    }

    @Override // com.google.android.exoplayer2.offline.DownloadIndex
    public void putDownloadState(DownloadState downloadState) {
        getDownloadStateTable().replace(downloadState);
    }

    @Override // com.google.android.exoplayer2.offline.DownloadIndex
    public void removeDownloadState(String id) {
        getDownloadStateTable().delete(id);
    }

    private DownloadStateTable getDownloadStateTable() {
        if (this.downloadStateTable == null) {
            this.downloadStateTable = new DownloadStateTable(this.databaseProvider);
        }
        return this.downloadStateTable;
    }

    static boolean doesTableExist(DatabaseProvider databaseProvider, String tableName) {
        SQLiteDatabase readableDatabase = databaseProvider.getReadableDatabase();
        long count = DatabaseUtils.queryNumEntries(readableDatabase, "sqlite_master", "tbl_name = ?", new String[]{tableName});
        return count > 0;
    }

    private static final class DownloadStateCursorImpl implements DownloadStateCursor {
        private final Cursor cursor;

        @Override // com.google.android.exoplayer2.offline.DownloadStateCursor
        public /* synthetic */ boolean isAfterLast() {
            return DownloadStateCursor.CC.$default$isAfterLast(this);
        }

        @Override // com.google.android.exoplayer2.offline.DownloadStateCursor
        public /* synthetic */ boolean isBeforeFirst() {
            return DownloadStateCursor.CC.$default$isBeforeFirst(this);
        }

        @Override // com.google.android.exoplayer2.offline.DownloadStateCursor
        public /* synthetic */ boolean isFirst() {
            return DownloadStateCursor.CC.$default$isFirst(this);
        }

        @Override // com.google.android.exoplayer2.offline.DownloadStateCursor
        public /* synthetic */ boolean isLast() {
            return DownloadStateCursor.CC.$default$isLast(this);
        }

        @Override // com.google.android.exoplayer2.offline.DownloadStateCursor
        public /* synthetic */ boolean moveToFirst() {
            return moveToPosition(0);
        }

        @Override // com.google.android.exoplayer2.offline.DownloadStateCursor
        public /* synthetic */ boolean moveToLast() {
            return moveToPosition(getCount() - 1);
        }

        @Override // com.google.android.exoplayer2.offline.DownloadStateCursor
        public /* synthetic */ boolean moveToNext() {
            return moveToPosition(getPosition() + 1);
        }

        @Override // com.google.android.exoplayer2.offline.DownloadStateCursor
        public /* synthetic */ boolean moveToPrevious() {
            return moveToPosition(getPosition() - 1);
        }

        private DownloadStateCursorImpl(Cursor cursor) {
            this.cursor = cursor;
        }

        @Override // com.google.android.exoplayer2.offline.DownloadStateCursor
        public DownloadState getDownloadState() {
            return DownloadStateTable.getDownloadState(this.cursor);
        }

        @Override // com.google.android.exoplayer2.offline.DownloadStateCursor
        public int getCount() {
            return this.cursor.getCount();
        }

        @Override // com.google.android.exoplayer2.offline.DownloadStateCursor
        public int getPosition() {
            return this.cursor.getPosition();
        }

        @Override // com.google.android.exoplayer2.offline.DownloadStateCursor
        public boolean moveToPosition(int position) {
            return this.cursor.moveToPosition(position);
        }

        @Override // com.google.android.exoplayer2.offline.DownloadStateCursor
        public void close() {
            this.cursor.close();
        }

        @Override // com.google.android.exoplayer2.offline.DownloadStateCursor
        public boolean isClosed() {
            return this.cursor.isClosed();
        }
    }

    static final class DownloadStateTable {
        private static final String COLUMN_ID = "id";
        private static final int COLUMN_INDEX_CACHE_KEY = 3;
        private static final int COLUMN_INDEX_CUSTOM_METADATA = 13;
        private static final int COLUMN_INDEX_DOWNLOADED_BYTES = 6;
        private static final int COLUMN_INDEX_DOWNLOAD_PERCENTAGE = 5;
        private static final int COLUMN_INDEX_FAILURE_REASON = 8;
        private static final int COLUMN_INDEX_ID = 0;
        private static final int COLUMN_INDEX_START_TIME_MS = 10;
        private static final int COLUMN_INDEX_STATE = 4;
        private static final int COLUMN_INDEX_STOP_FLAGS = 9;
        private static final int COLUMN_INDEX_STREAM_KEYS = 12;
        private static final int COLUMN_INDEX_TOTAL_BYTES = 7;
        private static final int COLUMN_INDEX_TYPE = 1;
        private static final int COLUMN_INDEX_UPDATE_TIME_MS = 11;
        private static final int COLUMN_INDEX_URI = 2;
        private static final String COLUMN_SELECTION_ID = "id = ?";
        private static final String COLUMN_STATE = "state";
        private static final String SQL_CREATE_TABLE = "CREATE TABLE IF NOT EXISTS ExoPlayerDownloadStates (id TEXT PRIMARY KEY NOT NULL,title TEXT NOT NULL,subtitle TEXT NOT NULL,cache_key TEXT,state INTEGER NOT NULL,download_percentage REAL NOT NULL,downloaded_bytes INTEGER NOT NULL,total_bytes INTEGER NOT NULL,failure_reason INTEGER NOT NULL,stop_flags INTEGER NOT NULL,start_time_ms INTEGER NOT NULL,update_time_ms INTEGER NOT NULL,stream_keys TEXT NOT NULL,custom_metadata BLOB NOT NULL)";
        private static final String SQL_DROP_TABLE = "DROP TABLE IF EXISTS ExoPlayerDownloadStates";
        static final String TABLE_NAME = "ExoPlayerDownloadStates";
        static final int TABLE_VERSION = 1;
        private final DatabaseProvider databaseProvider;
        private static final String COLUMN_TYPE = "title";
        private static final String COLUMN_URI = "subtitle";
        private static final String COLUMN_CACHE_KEY = "cache_key";
        private static final String COLUMN_DOWNLOAD_PERCENTAGE = "download_percentage";
        private static final String COLUMN_DOWNLOADED_BYTES = "downloaded_bytes";
        private static final String COLUMN_TOTAL_BYTES = "total_bytes";
        private static final String COLUMN_FAILURE_REASON = "failure_reason";
        private static final String COLUMN_STOP_FLAGS = "stop_flags";
        private static final String COLUMN_START_TIME_MS = "start_time_ms";
        private static final String COLUMN_UPDATE_TIME_MS = "update_time_ms";
        private static final String COLUMN_STREAM_KEYS = "stream_keys";
        private static final String COLUMN_CUSTOM_METADATA = "custom_metadata";
        private static final String[] COLUMNS = {"id", COLUMN_TYPE, COLUMN_URI, COLUMN_CACHE_KEY, "state", COLUMN_DOWNLOAD_PERCENTAGE, COLUMN_DOWNLOADED_BYTES, COLUMN_TOTAL_BYTES, COLUMN_FAILURE_REASON, COLUMN_STOP_FLAGS, COLUMN_START_TIME_MS, COLUMN_UPDATE_TIME_MS, COLUMN_STREAM_KEYS, COLUMN_CUSTOM_METADATA};

        public DownloadStateTable(DatabaseProvider databaseProvider) {
            this.databaseProvider = databaseProvider;
            VersionTable versionTable = new VersionTable(databaseProvider);
            int version = versionTable.getVersion(0);
            if (!DefaultDownloadIndex.doesTableExist(databaseProvider, TABLE_NAME) || version == 0 || version > 1) {
                SQLiteDatabase writableDatabase = databaseProvider.getWritableDatabase();
                writableDatabase.beginTransaction();
                try {
                    writableDatabase.execSQL(SQL_DROP_TABLE);
                    writableDatabase.execSQL(SQL_CREATE_TABLE);
                    versionTable.setVersion(0, 1);
                    writableDatabase.setTransactionSuccessful();
                    return;
                } finally {
                    writableDatabase.endTransaction();
                }
            }
            if (version < 1) {
                throw new IllegalStateException();
            }
        }

        public void replace(DownloadState downloadState) {
            ContentValues values = new ContentValues();
            values.put("id", downloadState.id);
            values.put(COLUMN_TYPE, downloadState.type);
            values.put(COLUMN_URI, downloadState.uri.toString());
            values.put(COLUMN_CACHE_KEY, downloadState.cacheKey);
            values.put("state", Integer.valueOf(downloadState.state));
            values.put(COLUMN_DOWNLOAD_PERCENTAGE, Float.valueOf(downloadState.downloadPercentage));
            values.put(COLUMN_DOWNLOADED_BYTES, Long.valueOf(downloadState.downloadedBytes));
            values.put(COLUMN_TOTAL_BYTES, Long.valueOf(downloadState.totalBytes));
            values.put(COLUMN_FAILURE_REASON, Integer.valueOf(downloadState.failureReason));
            values.put(COLUMN_STOP_FLAGS, Integer.valueOf(downloadState.stopFlags));
            values.put(COLUMN_START_TIME_MS, Long.valueOf(downloadState.startTimeMs));
            values.put(COLUMN_UPDATE_TIME_MS, Long.valueOf(downloadState.updateTimeMs));
            values.put(COLUMN_STREAM_KEYS, encodeStreamKeys(downloadState.streamKeys));
            values.put(COLUMN_CUSTOM_METADATA, downloadState.customMetadata);
            SQLiteDatabase writableDatabase = this.databaseProvider.getWritableDatabase();
            writableDatabase.replace(TABLE_NAME, null, values);
        }

        public DownloadState get(String id) {
            String[] selectionArgs = {id};
            Cursor cursor = query(COLUMN_SELECTION_ID, selectionArgs);
            try {
                if (cursor.getCount() != 0) {
                    cursor.moveToNext();
                    DownloadState downloadState = getDownloadState(cursor);
                    Assertions.checkState(id.equals(downloadState.id));
                    if (cursor != null) {
                        cursor.close();
                    }
                    return downloadState;
                }
                if (cursor != null) {
                    cursor.close();
                }
                return null;
            } catch (Throwable th) {
                try {
                    throw th;
                } catch (Throwable th2) {
                    if (cursor != null) {
                        try {
                            cursor.close();
                        } catch (Throwable th3) {
                            th.addSuppressed(th3);
                        }
                    }
                    throw th2;
                }
            }
        }

        public DownloadStateCursor get(int... states) {
            String selection = null;
            if (states.length > 0) {
                StringBuilder selectionBuilder = new StringBuilder();
                selectionBuilder.append("state");
                selectionBuilder.append(" IN (");
                for (int i = 0; i < states.length; i++) {
                    if (i > 0) {
                        selectionBuilder.append(',');
                    }
                    selectionBuilder.append(states[i]);
                }
                selectionBuilder.append(')');
                selection = selectionBuilder.toString();
            }
            Cursor cursor = query(selection, null);
            return new DownloadStateCursorImpl(cursor);
        }

        public void delete(String id) {
            String[] selectionArgs = {id};
            this.databaseProvider.getWritableDatabase().delete(TABLE_NAME, COLUMN_SELECTION_ID, selectionArgs);
        }

        private Cursor query(String selection, String[] selectionArgs) {
            return this.databaseProvider.getReadableDatabase().query(TABLE_NAME, COLUMNS, selection, selectionArgs, null, null, "start_time_ms ASC");
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static DownloadState getDownloadState(Cursor cursor) {
            return new DownloadState(cursor.getString(0), cursor.getString(1), Uri.parse(cursor.getString(2)), cursor.getString(3), cursor.getInt(4), cursor.getFloat(5), cursor.getLong(6), cursor.getLong(7), cursor.getInt(8), cursor.getInt(9), cursor.getLong(10), cursor.getLong(11), decodeStreamKeys(cursor.getString(12)), cursor.getBlob(13));
        }

        private static String encodeStreamKeys(StreamKey[] streamKeys) {
            StringBuilder stringBuilder = new StringBuilder();
            for (StreamKey streamKey : streamKeys) {
                stringBuilder.append(streamKey.periodIndex);
                stringBuilder.append('.');
                stringBuilder.append(streamKey.groupIndex);
                stringBuilder.append('.');
                stringBuilder.append(streamKey.trackIndex);
                stringBuilder.append(',');
            }
            if (stringBuilder.length() > 0) {
                stringBuilder.setLength(stringBuilder.length() - 1);
            }
            return stringBuilder.toString();
        }

        private static StreamKey[] decodeStreamKeys(String encodedStreamKeys) {
            if (encodedStreamKeys.isEmpty()) {
                return new StreamKey[0];
            }
            String[] streamKeysStrings = Util.split(encodedStreamKeys, ",");
            int streamKeysCount = streamKeysStrings.length;
            StreamKey[] streamKeys = new StreamKey[streamKeysCount];
            for (int i = 0; i < streamKeysCount; i++) {
                String[] indices = Util.split(streamKeysStrings[i], "\\.");
                Assertions.checkState(indices.length == 3);
                streamKeys[i] = new StreamKey(Integer.parseInt(indices[0]), Integer.parseInt(indices[1]), Integer.parseInt(indices[2]));
            }
            return streamKeys;
        }
    }

    static final class VersionTable {
        private static final String COLUMN_FEATURE = "feature";
        private static final String COLUMN_VERSION = "version";
        public static final int FEATURE_CACHE = 1;
        public static final int FEATURE_OFFLINE = 0;
        private static final String SQL_CREATE_TABLE = "CREATE TABLE IF NOT EXISTS ExoPlayerVersions (feature INTEGER PRIMARY KEY NOT NULL,version INTEGER NOT NULL)";
        private static final String TABLE_NAME = "ExoPlayerVersions";
        private final DatabaseProvider databaseProvider;

        @Documented
        @Retention(RetentionPolicy.SOURCE)
        private @interface Feature {
        }

        public VersionTable(DatabaseProvider databaseProvider) {
            this.databaseProvider = databaseProvider;
            if (!DefaultDownloadIndex.doesTableExist(databaseProvider, TABLE_NAME)) {
                databaseProvider.getWritableDatabase().execSQL(SQL_CREATE_TABLE);
            }
        }

        public void setVersion(int feature, int version) {
            ContentValues values = new ContentValues();
            values.put(COLUMN_FEATURE, Integer.valueOf(feature));
            values.put(COLUMN_VERSION, Integer.valueOf(version));
            SQLiteDatabase writableDatabase = this.databaseProvider.getWritableDatabase();
            writableDatabase.replace(TABLE_NAME, null, values);
        }

        public int getVersion(int feature) {
            String[] selectionArgs = {Integer.toString(feature)};
            Cursor cursor = this.databaseProvider.getReadableDatabase().query(TABLE_NAME, new String[]{COLUMN_VERSION}, "feature = ?", selectionArgs, null, null, null);
            try {
                if (cursor.getCount() != 0) {
                    cursor.moveToNext();
                    int i = cursor.getInt(0);
                    if (cursor != null) {
                        cursor.close();
                    }
                    return i;
                }
                if (cursor != null) {
                    cursor.close();
                }
                return 0;
            } catch (Throwable th) {
                try {
                    throw th;
                } catch (Throwable th2) {
                    if (cursor != null) {
                        try {
                            cursor.close();
                        } catch (Throwable th3) {
                            th.addSuppressed(th3);
                        }
                    }
                    throw th2;
                }
            }
        }
    }

    private static final class DefaultDatabaseProvider extends SQLiteOpenHelper implements DatabaseProvider {
        public DefaultDatabaseProvider(Context context) {
            super(context, DefaultDownloadIndex.DATABASE_NAME, (SQLiteDatabase.CursorFactory) null, 1);
        }

        @Override // android.database.sqlite.SQLiteOpenHelper
        public void onCreate(SQLiteDatabase db) {
        }

        @Override // android.database.sqlite.SQLiteOpenHelper
        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        }

        @Override // android.database.sqlite.SQLiteOpenHelper
        public void onDowngrade(SQLiteDatabase db, int oldVersion, int newVersion) {
            super.onDowngrade(db, oldVersion, newVersion);
        }

        @Override // android.database.sqlite.SQLiteOpenHelper, java.lang.AutoCloseable, com.google.android.exoplayer2.offline.DefaultDownloadIndex.DatabaseProvider
        public synchronized void close() {
            super.close();
        }

        @Override // android.database.sqlite.SQLiteOpenHelper, com.google.android.exoplayer2.offline.DefaultDownloadIndex.DatabaseProvider
        public SQLiteDatabase getWritableDatabase() {
            return super.getWritableDatabase();
        }

        @Override // android.database.sqlite.SQLiteOpenHelper, com.google.android.exoplayer2.offline.DefaultDownloadIndex.DatabaseProvider
        public SQLiteDatabase getReadableDatabase() {
            return super.getReadableDatabase();
        }
    }
}
