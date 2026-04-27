package im.uwrkaxlmjj.messenger;

import android.text.TextUtils;
import android.util.LongSparseArray;
import android.util.SparseArray;
import android.util.SparseIntArray;
import androidx.recyclerview.widget.ItemTouchHelper;
import com.litesuits.orm.db.assit.SQLBuilder;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.support.SparseLongArray;
import im.uwrkaxlmjj.sqlite.SQLiteCursor;
import im.uwrkaxlmjj.sqlite.SQLiteDatabase;
import im.uwrkaxlmjj.sqlite.SQLitePreparedStatement;
import im.uwrkaxlmjj.tgnet.NativeByteBuffer;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicLong;
import org.webrtc.mozi.ScreenAudioCapturer;

/* JADX INFO: loaded from: classes2.dex */
public class MessagesStorage extends BaseController {
    private static volatile MessagesStorage[] Instance = new MessagesStorage[3];
    private static final int LAST_DB_VERSION = 68;
    private File cacheFile;
    private SQLiteDatabase database;
    private int lastDateValue;
    private int lastPtsValue;
    private int lastQtsValue;
    private int lastSavedDate;
    private int lastSavedPts;
    private int lastSavedQts;
    private int lastSavedSeq;
    private int lastSecretVersion;
    private int lastSeqValue;
    private AtomicLong lastTaskId;
    private CountDownLatch openSync;
    private int secretG;
    private byte[] secretPBytes;
    private File shmCacheFile;
    private DispatchQueue storageQueue;
    private File walCacheFile;

    public interface BooleanCallback {
        void run(boolean z);
    }

    public interface IntCallback {
        void run(int i);
    }

    public static MessagesStorage getInstance(int num) {
        MessagesStorage localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (MessagesStorage.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    MessagesStorage[] messagesStorageArr = Instance;
                    MessagesStorage messagesStorage = new MessagesStorage(num);
                    localInstance = messagesStorage;
                    messagesStorageArr[num] = messagesStorage;
                }
            }
        }
        return localInstance;
    }

    private void ensureOpened() {
        try {
            this.openSync.await();
        } catch (Throwable th) {
        }
    }

    public int getLastDateValue() {
        ensureOpened();
        return this.lastDateValue;
    }

    public void setLastDateValue(int value) {
        ensureOpened();
        this.lastDateValue = value;
    }

    public int getLastPtsValue() {
        ensureOpened();
        return this.lastPtsValue;
    }

    public void setLastPtsValue(int value) {
        ensureOpened();
        this.lastPtsValue = value;
    }

    public int getLastQtsValue() {
        ensureOpened();
        return this.lastQtsValue;
    }

    public void setLastQtsValue(int value) {
        ensureOpened();
        this.lastQtsValue = value;
    }

    public int getLastSeqValue() {
        ensureOpened();
        return this.lastSeqValue;
    }

    public void setLastSeqValue(int value) {
        ensureOpened();
        this.lastSeqValue = value;
    }

    public int getLastSecretVersion() {
        ensureOpened();
        return this.lastSecretVersion;
    }

    public void setLastSecretVersion(int value) {
        ensureOpened();
        this.lastSecretVersion = value;
    }

    public byte[] getSecretPBytes() {
        ensureOpened();
        return this.secretPBytes;
    }

    public void setSecretPBytes(byte[] value) {
        ensureOpened();
        this.secretPBytes = value;
    }

    public int getSecretG() {
        ensureOpened();
        return this.secretG;
    }

    public void setSecretG(int value) {
        ensureOpened();
        this.secretG = value;
    }

    public MessagesStorage(int instance) {
        super(instance);
        this.storageQueue = new DispatchQueue("storageQueue");
        this.lastTaskId = new AtomicLong(System.currentTimeMillis());
        this.lastDateValue = 0;
        this.lastPtsValue = 0;
        this.lastQtsValue = 0;
        this.lastSeqValue = 0;
        this.lastSecretVersion = 0;
        this.secretPBytes = null;
        this.secretG = 0;
        this.lastSavedSeq = 0;
        this.lastSavedPts = 0;
        this.lastSavedDate = 0;
        this.lastSavedQts = 0;
        this.openSync = new CountDownLatch(1);
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$nWYlstxZrdyYOODX0sGt1oT3WzA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$new$0$MessagesStorage();
            }
        });
    }

    public /* synthetic */ void lambda$new$0$MessagesStorage() {
        openDatabase(1);
    }

    public SQLiteDatabase getDatabase() {
        return this.database;
    }

    public DispatchQueue getStorageQueue() {
        return this.storageQueue;
    }

    public long getDatabaseSize() {
        File file = this.cacheFile;
        long size = file != null ? 0 + file.length() : 0L;
        File file2 = this.shmCacheFile;
        if (file2 != null) {
            return size + file2.length();
        }
        return size;
    }

    /* JADX WARN: Removed duplicated region for block: B:44:0x06d5 A[Catch: all -> 0x06a9, PHI: r6
      0x06d5: PHI (r6v16 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement) = 
      (r6v14 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement)
      (r6v20 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement)
     binds: [B:51:0x06e3, B:43:0x06d3] A[DONT_GENERATE, DONT_INLINE], TRY_ENTER, TRY_LEAVE, TryCatch #3 {all -> 0x06a9, blocks: (B:21:0x064f, B:23:0x0660, B:25:0x068f, B:26:0x0692, B:28:0x069a, B:30:0x069d, B:31:0x069f, B:40:0x06ae, B:44:0x06d5, B:63:0x06fd, B:65:0x0701, B:41:0x06b3, B:50:0x06de), top: B:103:0x064f, inners: #1, #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:54:0x06e8 A[Catch: all -> 0x070f, Exception -> 0x0712, TRY_ENTER, TryCatch #5 {Exception -> 0x0712, blocks: (B:9:0x0058, B:12:0x009a, B:14:0x009e, B:15:0x00a3, B:16:0x0626, B:18:0x0638, B:34:0x06a5, B:58:0x06f0, B:67:0x0704, B:69:0x0708, B:54:0x06e8, B:70:0x0709, B:71:0x070e), top: B:108:0x0058, outer: #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:58:0x06f0 A[Catch: all -> 0x070f, Exception -> 0x0712, TRY_LEAVE, TryCatch #5 {Exception -> 0x0712, blocks: (B:9:0x0058, B:12:0x009a, B:14:0x009e, B:15:0x00a3, B:16:0x0626, B:18:0x0638, B:34:0x06a5, B:58:0x06f0, B:67:0x0704, B:69:0x0708, B:54:0x06e8, B:70:0x0709, B:71:0x070e), top: B:108:0x0058, outer: #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:61:0x06f6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void openDatabase(int r22) {
        /*
            Method dump skipped, instruction units count: 1910
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.openDatabase(int):void");
    }

    private void updateDbToLastVersion(final int currentVersion) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$_DqFilSwWY7GQ0MJsChTGLFrs8Q
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateDbToLastVersion$1$MessagesStorage(currentVersion);
            }
        });
    }

    public /* synthetic */ void lambda$updateDbToLastVersion$1$MessagesStorage(int currentVersion) {
        SQLiteCursor cursor = null;
        NativeByteBuffer data = null;
        NativeByteBuffer data2 = null;
        SQLitePreparedStatement state = null;
        int version = currentVersion;
        if (version < 4) {
            try {
                try {
                    this.database.executeFast("CREATE TABLE IF NOT EXISTS user_photos(uid INTEGER, id INTEGER, data BLOB, PRIMARY KEY (uid, id))").stepThis().dispose();
                    this.database.executeFast("DROP INDEX IF EXISTS read_state_out_idx_messages;").stepThis().dispose();
                    this.database.executeFast("DROP INDEX IF EXISTS ttl_idx_messages;").stepThis().dispose();
                    this.database.executeFast("DROP INDEX IF EXISTS date_idx_messages;").stepThis().dispose();
                    this.database.executeFast("CREATE INDEX IF NOT EXISTS mid_out_idx_messages ON messages(mid, out);").stepThis().dispose();
                    this.database.executeFast("CREATE INDEX IF NOT EXISTS task_idx_messages ON messages(uid, out, read_state, ttl, date, send_state);").stepThis().dispose();
                    this.database.executeFast("CREATE INDEX IF NOT EXISTS uid_date_mid_idx_messages ON messages(uid, date, mid);").stepThis().dispose();
                    this.database.executeFast("CREATE TABLE IF NOT EXISTS user_contacts_v6(uid INTEGER PRIMARY KEY, fname TEXT, sname TEXT)").stepThis().dispose();
                    this.database.executeFast("CREATE TABLE IF NOT EXISTS user_phones_v6(uid INTEGER, phone TEXT, sphone TEXT, deleted INTEGER, PRIMARY KEY (uid, phone))").stepThis().dispose();
                    this.database.executeFast("CREATE INDEX IF NOT EXISTS sphone_deleted_idx_user_phones ON user_phones_v6(sphone, deleted);").stepThis().dispose();
                    this.database.executeFast("CREATE INDEX IF NOT EXISTS mid_idx_randoms ON randoms(mid);").stepThis().dispose();
                    this.database.executeFast("CREATE TABLE IF NOT EXISTS sent_files_v2(uid TEXT, type INTEGER, data BLOB, PRIMARY KEY (uid, type))").stepThis().dispose();
                    this.database.executeFast("CREATE TABLE IF NOT EXISTS download_queue(uid INTEGER, type INTEGER, date INTEGER, data BLOB, PRIMARY KEY (uid, type));").stepThis().dispose();
                    this.database.executeFast("CREATE INDEX IF NOT EXISTS type_date_idx_download_queue ON download_queue(type, date);").stepThis().dispose();
                    this.database.executeFast("CREATE TABLE IF NOT EXISTS dialog_settings(did INTEGER PRIMARY KEY, flags INTEGER);").stepThis().dispose();
                    this.database.executeFast("CREATE INDEX IF NOT EXISTS unread_count_idx_dialogs ON dialogs(unread_count);").stepThis().dispose();
                    this.database.executeFast("UPDATE messages SET send_state = 2 WHERE mid < 0 AND send_state = 1").stepThis().dispose();
                    fixNotificationSettings();
                    this.database.executeFast("PRAGMA user_version = 4").stepThis().dispose();
                    state = null;
                    version = 4;
                } catch (Exception e) {
                    FileLog.e("updateDbToLastVersion ---> exception 2 ", e);
                    if (data != null) {
                        data.reuse();
                    }
                    if (data2 != null) {
                        data2.reuse();
                    }
                    if (cursor != null) {
                        cursor.dispose();
                    }
                    if (state == null) {
                        return;
                    }
                }
            } catch (Throwable th) {
                if (data != null) {
                    data.reuse();
                }
                if (data2 != null) {
                    data2.reuse();
                }
                if (cursor != null) {
                    cursor.dispose();
                }
                if (state != null) {
                    state.dispose();
                }
                throw th;
            }
        }
        if (version == 4) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS enc_tasks_v2(mid INTEGER PRIMARY KEY, date INTEGER)").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS date_idx_enc_tasks_v2 ON enc_tasks_v2(date);").stepThis().dispose();
            try {
                this.database.beginTransaction();
            } catch (Exception e2) {
                FileLog.e("updateDbToLastVersion ---> exception 1 ", e2);
            }
            SQLiteCursor cursor2 = this.database.queryFinalized("SELECT date, data FROM enc_tasks WHERE 1", new Object[0]);
            SQLitePreparedStatement state2 = this.database.executeFast("REPLACE INTO enc_tasks_v2 VALUES(?, ?)");
            if (cursor2.next()) {
                int date = cursor2.intValue(0);
                data = cursor2.byteBufferValue(1);
                if (data != null) {
                    int length = data.limit();
                    for (int a = 0; a < length / 4; a++) {
                        state2.requery();
                        state2.bindInteger(1, data.readInt32(false));
                        state2.bindInteger(2, date);
                        state2.step();
                    }
                    data.reuse();
                    data = null;
                }
            }
            state2.dispose();
            cursor2.dispose();
            cursor = null;
            this.database.commitTransaction();
            this.database.executeFast("DROP INDEX IF EXISTS date_idx_enc_tasks;").stepThis().dispose();
            this.database.executeFast("DROP TABLE IF EXISTS enc_tasks;").stepThis().dispose();
            this.database.executeFast("ALTER TABLE messages ADD COLUMN media INTEGER default 0").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 6").stepThis().dispose();
            state = null;
            version = 6;
        }
        if (version == 6) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS messages_seq(mid INTEGER PRIMARY KEY, seq_in INTEGER, seq_out INTEGER);").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS seq_idx_messages_seq ON messages_seq(seq_in, seq_out);").stepThis().dispose();
            this.database.executeFast("ALTER TABLE enc_chats ADD COLUMN layer INTEGER default 0").stepThis().dispose();
            this.database.executeFast("ALTER TABLE enc_chats ADD COLUMN seq_in INTEGER default 0").stepThis().dispose();
            this.database.executeFast("ALTER TABLE enc_chats ADD COLUMN seq_out INTEGER default 0").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 7").stepThis().dispose();
            state = null;
            version = 7;
        }
        if (version == 7 || version == 8 || version == 9) {
            this.database.executeFast("ALTER TABLE enc_chats ADD COLUMN use_count INTEGER default 0").stepThis().dispose();
            this.database.executeFast("ALTER TABLE enc_chats ADD COLUMN exchange_id INTEGER default 0").stepThis().dispose();
            this.database.executeFast("ALTER TABLE enc_chats ADD COLUMN key_date INTEGER default 0").stepThis().dispose();
            this.database.executeFast("ALTER TABLE enc_chats ADD COLUMN fprint INTEGER default 0").stepThis().dispose();
            this.database.executeFast("ALTER TABLE enc_chats ADD COLUMN fauthkey BLOB default NULL").stepThis().dispose();
            this.database.executeFast("ALTER TABLE enc_chats ADD COLUMN khash BLOB default NULL").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 10").stepThis().dispose();
            state = null;
            version = 10;
        }
        if (version == 10) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS web_recent_v3(id TEXT, type INTEGER, image_url TEXT, thumb_url TEXT, local_url TEXT, width INTEGER, height INTEGER, size INTEGER, date INTEGER, PRIMARY KEY (id, type));").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 11").stepThis().dispose();
            state = null;
            version = 11;
        }
        if (version == 11 || version == 12) {
            this.database.executeFast("DROP INDEX IF EXISTS uid_mid_idx_media;").stepThis().dispose();
            this.database.executeFast("DROP INDEX IF EXISTS mid_idx_media;").stepThis().dispose();
            this.database.executeFast("DROP INDEX IF EXISTS uid_date_mid_idx_media;").stepThis().dispose();
            this.database.executeFast("DROP TABLE IF EXISTS media;").stepThis().dispose();
            this.database.executeFast("DROP TABLE IF EXISTS media_counts;").stepThis().dispose();
            this.database.executeFast("CREATE TABLE IF NOT EXISTS media_v2(mid INTEGER PRIMARY KEY, uid INTEGER, date INTEGER, type INTEGER, data BLOB)").stepThis().dispose();
            this.database.executeFast("CREATE TABLE IF NOT EXISTS media_counts_v2(uid INTEGER, type INTEGER, count INTEGER, PRIMARY KEY(uid, type))").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS uid_mid_type_date_idx_media ON media_v2(uid, mid, type, date);").stepThis().dispose();
            this.database.executeFast("CREATE TABLE IF NOT EXISTS keyvalue(id TEXT PRIMARY KEY, value TEXT)").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 13").stepThis().dispose();
            state = null;
            version = 13;
        }
        if (version == 13) {
            this.database.executeFast("ALTER TABLE messages ADD COLUMN replydata BLOB default NULL").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 14").stepThis().dispose();
            state = null;
            version = 14;
        }
        if (version == 14) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS hashtag_recent_v2(id TEXT PRIMARY KEY, date INTEGER);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 15").stepThis().dispose();
            state = null;
            version = 15;
        }
        if (version == 15) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS webpage_pending(id INTEGER, mid INTEGER, PRIMARY KEY (id, mid));").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 16").stepThis().dispose();
            state = null;
            version = 16;
        }
        if (version == 16) {
            this.database.executeFast("ALTER TABLE dialogs ADD COLUMN inbox_max INTEGER default 0").stepThis().dispose();
            this.database.executeFast("ALTER TABLE dialogs ADD COLUMN outbox_max INTEGER default 0").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 17").stepThis().dispose();
            state = null;
            version = 17;
        }
        if (version == 17) {
            this.database.executeFast("CREATE TABLE bot_info(uid INTEGER PRIMARY KEY, info BLOB)").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 18").stepThis().dispose();
            state = null;
            version = 18;
        }
        if (version == 18) {
            this.database.executeFast("DROP TABLE IF EXISTS stickers;").stepThis().dispose();
            this.database.executeFast("CREATE TABLE IF NOT EXISTS stickers_v2(id INTEGER PRIMARY KEY, data BLOB, date INTEGER, hash TEXT);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 19").stepThis().dispose();
            state = null;
            version = 19;
        }
        if (version == 19) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS bot_keyboard(uid INTEGER PRIMARY KEY, mid INTEGER, info BLOB)").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS bot_keyboard_idx_mid ON bot_keyboard(mid);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 20").stepThis().dispose();
            state = null;
            version = 20;
        }
        if (version == 20) {
            this.database.executeFast("CREATE TABLE search_recent(did INTEGER PRIMARY KEY, date INTEGER);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 21").stepThis().dispose();
            state = null;
            version = 21;
        }
        if (version == 21) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS chat_settings_v2(uid INTEGER PRIMARY KEY, info BLOB)").stepThis().dispose();
            SQLiteCursor cursor3 = this.database.queryFinalized("SELECT uid, participants FROM chat_settings WHERE uid < 0", new Object[0]);
            SQLitePreparedStatement state3 = this.database.executeFast("REPLACE INTO chat_settings_v2 VALUES(?, ?)");
            while (cursor3.next()) {
                int chat_id = cursor3.intValue(0);
                data = cursor3.byteBufferValue(1);
                if (data != null) {
                    TLRPC.ChatParticipants participants = TLRPC.ChatParticipants.TLdeserialize(data, data.readInt32(false), false);
                    data.reuse();
                    if (participants != null) {
                        TLRPC.TL_chatFull chatFull = new TLRPC.TL_chatFull();
                        chatFull.id = chat_id;
                        chatFull.chat_photo = new TLRPC.TL_photoEmpty();
                        chatFull.notify_settings = new TLRPC.TL_peerNotifySettingsEmpty_layer77();
                        chatFull.exported_invite = new TLRPC.TL_chatInviteEmpty();
                        chatFull.participants = participants;
                        NativeByteBuffer data22 = new NativeByteBuffer(chatFull.getObjectSize());
                        chatFull.serializeToStream(data22);
                        state3.requery();
                        state3.bindInteger(1, chat_id);
                        state3.bindByteBuffer(2, data22);
                        state3.step();
                        data22.reuse();
                        data2 = null;
                    }
                }
            }
            state3.dispose();
            cursor3.dispose();
            cursor = null;
            this.database.executeFast("DROP TABLE IF EXISTS chat_settings;").stepThis().dispose();
            this.database.executeFast("ALTER TABLE dialogs ADD COLUMN last_mid_i INTEGER default 0").stepThis().dispose();
            this.database.executeFast("ALTER TABLE dialogs ADD COLUMN unread_count_i INTEGER default 0").stepThis().dispose();
            this.database.executeFast("ALTER TABLE dialogs ADD COLUMN pts INTEGER default 0").stepThis().dispose();
            this.database.executeFast("ALTER TABLE dialogs ADD COLUMN date_i INTEGER default 0").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS last_mid_i_idx_dialogs ON dialogs(last_mid_i);").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS unread_count_i_idx_dialogs ON dialogs(unread_count_i);").stepThis().dispose();
            this.database.executeFast("ALTER TABLE messages ADD COLUMN imp INTEGER default 0").stepThis().dispose();
            this.database.executeFast("CREATE TABLE IF NOT EXISTS messages_holes(uid INTEGER, start INTEGER, end INTEGER, PRIMARY KEY(uid, start));").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS uid_end_messages_holes ON messages_holes(uid, end);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 22").stepThis().dispose();
            state = null;
            version = 22;
        }
        if (version == 22) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS media_holes_v2(uid INTEGER, type INTEGER, start INTEGER, end INTEGER, PRIMARY KEY(uid, type, start));").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS uid_end_media_holes_v2 ON media_holes_v2(uid, type, end);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 23").stepThis().dispose();
            state = null;
            version = 23;
        }
        if (version == 23 || version == 24) {
            this.database.executeFast("DELETE FROM media_holes_v2 WHERE uid != 0 AND type >= 0 AND start IN (0, 1)").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 25").stepThis().dispose();
            state = null;
            version = 25;
        }
        if (version == 25 || version == 26) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS channel_users_v2(did INTEGER, uid INTEGER, date INTEGER, data BLOB, PRIMARY KEY(did, uid))").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 27").stepThis().dispose();
            state = null;
            version = 27;
        }
        if (version == 27) {
            this.database.executeFast("ALTER TABLE web_recent_v3 ADD COLUMN document BLOB default NULL").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 28").stepThis().dispose();
            state = null;
            version = 28;
        }
        if (version == 28 || version == 29) {
            this.database.executeFast("DELETE FROM sent_files_v2 WHERE 1").stepThis().dispose();
            this.database.executeFast("DELETE FROM download_queue WHERE 1").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 30").stepThis().dispose();
            state = null;
            version = 30;
        }
        if (version == 30) {
            this.database.executeFast("ALTER TABLE chat_settings_v2 ADD COLUMN pinned INTEGER default 0").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS chat_settings_pinned_idx ON chat_settings_v2(uid, pinned) WHERE pinned != 0;").stepThis().dispose();
            this.database.executeFast("CREATE TABLE IF NOT EXISTS chat_pinned(uid INTEGER PRIMARY KEY, pinned INTEGER, data BLOB)").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS chat_pinned_mid_idx ON chat_pinned(uid, pinned) WHERE pinned != 0;").stepThis().dispose();
            this.database.executeFast("CREATE TABLE IF NOT EXISTS users_data(uid INTEGER PRIMARY KEY, about TEXT)").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 31").stepThis().dispose();
            state = null;
            version = 31;
        }
        if (version == 31) {
            this.database.executeFast("DROP TABLE IF EXISTS bot_recent;").stepThis().dispose();
            this.database.executeFast("CREATE TABLE IF NOT EXISTS chat_hints(did INTEGER, type INTEGER, rating REAL, date INTEGER, PRIMARY KEY(did, type))").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS chat_hints_rating_idx ON chat_hints(rating);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 32").stepThis().dispose();
            state = null;
            version = 32;
        }
        if (version == 32) {
            this.database.executeFast("DROP INDEX IF EXISTS uid_mid_idx_imp_messages;").stepThis().dispose();
            this.database.executeFast("DROP INDEX IF EXISTS uid_date_mid_imp_idx_messages;").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 33").stepThis().dispose();
            state = null;
            version = 33;
        }
        if (version == 33) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS pending_tasks(id INTEGER PRIMARY KEY, data BLOB);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 34").stepThis().dispose();
            state = null;
            version = 34;
        }
        if (version == 34) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS stickers_featured(id INTEGER PRIMARY KEY, data BLOB, unread BLOB, date INTEGER, hash TEXT);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 35").stepThis().dispose();
            state = null;
            version = 35;
        }
        if (version == 35) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS requested_holes(uid INTEGER, seq_out_start INTEGER, seq_out_end INTEGER, PRIMARY KEY (uid, seq_out_start, seq_out_end));").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 36").stepThis().dispose();
            state = null;
            version = 36;
        }
        if (version == 36) {
            this.database.executeFast("ALTER TABLE enc_chats ADD COLUMN in_seq_no INTEGER default 0").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 37").stepThis().dispose();
            state = null;
            version = 37;
        }
        if (version == 37) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS botcache(id TEXT PRIMARY KEY, date INTEGER, data BLOB)").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS botcache_date_idx ON botcache(date);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 38").stepThis().dispose();
            state = null;
            version = 38;
        }
        if (version == 38) {
            this.database.executeFast("ALTER TABLE dialogs ADD COLUMN pinned INTEGER default 0").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 39").stepThis().dispose();
            state = null;
            version = 39;
        }
        if (version == 39) {
            this.database.executeFast("ALTER TABLE enc_chats ADD COLUMN admin_id INTEGER default 0").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 40").stepThis().dispose();
            state = null;
            version = 40;
        }
        if (version == 40) {
            fixNotificationSettings();
            this.database.executeFast("PRAGMA user_version = 41").stepThis().dispose();
            state = null;
            version = 41;
        }
        if (version == 41) {
            this.database.executeFast("ALTER TABLE messages ADD COLUMN mention INTEGER default 0").stepThis().dispose();
            this.database.executeFast("ALTER TABLE user_contacts_v6 ADD COLUMN imported INTEGER default 0").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS uid_mention_idx_messages ON messages(uid, mention, read_state);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 42").stepThis().dispose();
            state = null;
            version = 42;
        }
        if (version == 42) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS sharing_locations(uid INTEGER PRIMARY KEY, mid INTEGER, date INTEGER, period INTEGER, message BLOB);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 43").stepThis().dispose();
            state = null;
            version = 43;
        }
        if (version == 43) {
            this.database.executeFast("PRAGMA user_version = 44").stepThis().dispose();
            state = null;
            version = 44;
        }
        if (version == 44) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS user_contacts_v7(key TEXT PRIMARY KEY, uid INTEGER, fname TEXT, sname TEXT, imported INTEGER)").stepThis().dispose();
            this.database.executeFast("CREATE TABLE IF NOT EXISTS user_phones_v7(key TEXT, phone TEXT, sphone TEXT, deleted INTEGER, PRIMARY KEY (key, phone))").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS sphone_deleted_idx_user_phones ON user_phones_v7(sphone, deleted);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 45").stepThis().dispose();
            state = null;
            version = 45;
        }
        if (version == 45) {
            this.database.executeFast("ALTER TABLE enc_chats ADD COLUMN mtproto_seq INTEGER default 0").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 46").stepThis().dispose();
            state = null;
            version = 46;
        }
        if (version == 46) {
            this.database.executeFast("DELETE FROM botcache WHERE 1").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 47").stepThis().dispose();
            state = null;
            version = 47;
        }
        if (version == 47) {
            this.database.executeFast("ALTER TABLE dialogs ADD COLUMN flags INTEGER default 0").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 48").stepThis().dispose();
            state = null;
            version = 48;
        }
        if (version == 48) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS unread_push_messages(uid INTEGER, mid INTEGER, random INTEGER, date INTEGER, data BLOB, fm TEXT, name TEXT, uname TEXT, flags INTEGER, PRIMARY KEY(uid, mid))").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS unread_push_messages_idx_date ON unread_push_messages(date);").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS unread_push_messages_idx_random ON unread_push_messages(random);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 49").stepThis().dispose();
            state = null;
            version = 49;
        }
        if (version == 49) {
            this.database.executeFast("DELETE FROM chat_pinned WHERE uid = 1").stepThis().dispose();
            this.database.executeFast("CREATE TABLE IF NOT EXISTS user_settings(uid INTEGER PRIMARY KEY, info BLOB, pinned INTEGER)").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS user_settings_pinned_idx ON user_settings(uid, pinned) WHERE pinned != 0;").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 50").stepThis().dispose();
            state = null;
            version = 50;
        }
        if (version == 50) {
            this.database.executeFast("DELETE FROM sent_files_v2 WHERE 1").stepThis().dispose();
            this.database.executeFast("ALTER TABLE sent_files_v2 ADD COLUMN parent TEXT").stepThis().dispose();
            this.database.executeFast("DELETE FROM download_queue WHERE 1").stepThis().dispose();
            this.database.executeFast("ALTER TABLE download_queue ADD COLUMN parent TEXT").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 51").stepThis().dispose();
            state = null;
            version = 51;
        }
        if (version == 51) {
            this.database.executeFast("ALTER TABLE media_counts_v2 ADD COLUMN old INTEGER").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 52").stepThis().dispose();
            state = null;
            version = 52;
        }
        if (version == 52) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS polls(mid INTEGER PRIMARY KEY, id INTEGER);").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS polls_id ON polls(id);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 53").stepThis().dispose();
            state = null;
            version = 53;
        }
        if (version == 53) {
            this.database.executeFast("ALTER TABLE chat_settings_v2 ADD COLUMN online INTEGER default 0").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 54").stepThis().dispose();
            state = null;
            version = 54;
        }
        if (version == 54) {
            this.database.executeFast("DROP TABLE IF EXISTS wallpapers;").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 55").stepThis().dispose();
            state = null;
            version = 55;
        }
        if (version == 55) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS wallpapers2(uid INTEGER PRIMARY KEY, data BLOB, num INTEGER)").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS wallpapers_num ON wallpapers2(num);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 56").stepThis().dispose();
            state = null;
            version = 56;
        }
        if (version == 56 || version == 57) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS emoji_keywords_v2(lang TEXT, keyword TEXT, emoji TEXT, PRIMARY KEY(lang, keyword, emoji));").stepThis().dispose();
            this.database.executeFast("CREATE TABLE IF NOT EXISTS emoji_keywords_info_v2(lang TEXT PRIMARY KEY, alias TEXT, version INTEGER);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 58").stepThis().dispose();
            state = null;
            version = 58;
        }
        if (version == 58) {
            this.database.executeFast("CREATE INDEX IF NOT EXISTS emoji_keywords_v2_keyword ON emoji_keywords_v2(keyword);").stepThis().dispose();
            this.database.executeFast("ALTER TABLE emoji_keywords_info_v2 ADD COLUMN date INTEGER default 0").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 59").stepThis().dispose();
            state = null;
            version = 59;
        }
        if (version == 59) {
            this.database.executeFast("ALTER TABLE dialogs ADD COLUMN folder_id INTEGER default 0").stepThis().dispose();
            this.database.executeFast("ALTER TABLE dialogs ADD COLUMN data BLOB default NULL").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS folder_id_idx_dialogs ON dialogs(folder_id);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 60").stepThis().dispose();
            state = null;
            version = 60;
        }
        if (version == 60) {
            this.database.executeFast("DROP TABLE IF EXISTS channel_admins;").stepThis().dispose();
            this.database.executeFast("DROP TABLE IF EXISTS blocked_users;").stepThis().dispose();
            this.database.executeFast("CREATE TABLE IF NOT EXISTS channel_admins_v2(did INTEGER, uid INTEGER, rank TEXT, PRIMARY KEY(did, uid))").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 61").stepThis().dispose();
            state = null;
            version = 61;
        }
        if (version == 61) {
            this.database.executeFast("DROP INDEX IF EXISTS send_state_idx_messages;").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS send_state_idx_messages2 ON messages(mid, send_state, date);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 62").stepThis().dispose();
            state = null;
            version = 62;
        }
        if (version == 62) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS scheduled_messages(mid INTEGER PRIMARY KEY, uid INTEGER, send_state INTEGER, date INTEGER, data BLOB, ttl INTEGER, replydata BLOB)").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS send_state_idx_scheduled_messages ON scheduled_messages(mid, send_state, date);").stepThis().dispose();
            this.database.executeFast("CREATE INDEX IF NOT EXISTS uid_date_idx_scheduled_messages ON scheduled_messages(uid, date);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 63").stepThis().dispose();
            state = null;
            version = 63;
        }
        if (version == 63) {
            this.database.executeFast("CREATE TABLE IF NOT EXISTS contacts_apply_info(apply_id INTEGER PRIMARY KEY, for_apply_id INTEGER, uid INTEGER, state INTEGER, greet TEXT, date INTEGER, expire INTEGER);").stepThis().dispose();
            this.database.executeFast("PRAGMA user_version = 64").stepThis().dispose();
            state = null;
        }
        if (version < 68) {
            this.database.executeFast("ALTER TABLE messages ADD COLUMN trans_dst TEXT").stepThis().dispose();
            state = this.database.executeFast("PRAGMA user_version = 67");
            state.stepThis().dispose();
            state = null;
        }
        if (data != null) {
            data.reuse();
        }
        if (data2 != null) {
            data2.reuse();
        }
        if (cursor != null) {
            cursor.dispose();
        }
        if (state == null) {
            return;
        }
        state.dispose();
    }

    private void cleanupInternal(boolean deleteFiles) {
        this.lastDateValue = 0;
        this.lastSeqValue = 0;
        this.lastPtsValue = 0;
        this.lastQtsValue = 0;
        this.lastSecretVersion = 0;
        this.lastSavedSeq = 0;
        this.lastSavedPts = 0;
        this.lastSavedDate = 0;
        this.lastSavedQts = 0;
        this.secretPBytes = null;
        this.secretG = 0;
        SQLiteDatabase sQLiteDatabase = this.database;
        if (sQLiteDatabase != null) {
            sQLiteDatabase.close();
            this.database = null;
        }
        if (deleteFiles) {
            File file = this.cacheFile;
            if (file != null) {
                file.delete();
                this.cacheFile = null;
            }
            File file2 = this.walCacheFile;
            if (file2 != null) {
                file2.delete();
                this.walCacheFile = null;
            }
            File file3 = this.shmCacheFile;
            if (file3 != null) {
                file3.delete();
                this.shmCacheFile = null;
            }
        }
    }

    public void cleanup(final boolean isLogin) {
        if (!isLogin) {
            this.storageQueue.cleanupQueue();
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$RWVuOor1AqUpyLTOwvxgErzt8Lw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$cleanup$4$MessagesStorage(isLogin);
            }
        });
    }

    public /* synthetic */ void lambda$cleanup$4$MessagesStorage(boolean isLogin) {
        cleanupInternal(true);
        openDatabase(1);
        if (isLogin) {
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$54z6NnCcuavarNLgxPpZ63z7Yk0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$2$MessagesStorage();
                }
            });
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$vt9eQ_mN9eIcd7F0fkaAYKiwiKs
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$3$MessagesStorage();
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$2$MessagesStorage() {
        getMessagesController().getDifference();
    }

    public /* synthetic */ void lambda$null$3$MessagesStorage() {
        getMessagesController().getContactsApplyDifferenceV2(true, false);
    }

    public void saveSecretParams(final int lsv, final int sg, final byte[] pbytes) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$TnEGganFiDPcO8VPNM5kfMcNusM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$saveSecretParams$5$MessagesStorage(lsv, sg, pbytes);
            }
        });
    }

    public /* synthetic */ void lambda$saveSecretParams$5$MessagesStorage(int lsv, int sg, byte[] pbytes) {
        SQLitePreparedStatement state = null;
        NativeByteBuffer data = null;
        try {
            try {
                SQLitePreparedStatement state2 = this.database.executeFast("UPDATE params SET lsv = ?, sg = ?, pbytes = ? WHERE id = 1");
                state2.bindInteger(1, lsv);
                state2.bindInteger(2, sg);
                data = new NativeByteBuffer(pbytes != null ? pbytes.length : 1);
                if (pbytes != null) {
                    data.writeBytes(pbytes);
                }
                state2.bindByteBuffer(3, data);
                state2.step();
                state2.dispose();
                state = null;
                data.reuse();
                data = null;
                if (0 != 0) {
                    state.dispose();
                }
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("saveSecretParams ---> exception ", e);
                if (state != null) {
                    state.dispose();
                }
                if (data == null) {
                    return;
                }
            }
            data.reuse();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            if (data != null) {
                data.reuse();
            }
            throw th;
        }
    }

    private void fixNotificationSettings() {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$UUnBdjX6zlfdFpiib25fh7q2NRQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$fixNotificationSettings$6$MessagesStorage();
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:42:0x00de A[Catch: all -> 0x00e8, PHI: r0
      0x00de: PHI (r0v5 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement) = 
      (r0v4 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement)
      (r0v7 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement)
     binds: [B:41:0x00dc, B:37:0x00d3] A[DONT_GENERATE, DONT_INLINE], TRY_ENTER, TryCatch #2 {all -> 0x00e8, blocks: (B:3:0x0002, B:4:0x0019, B:6:0x0020, B:8:0x0032, B:10:0x003e, B:12:0x0045, B:20:0x007c, B:23:0x0089, B:15:0x0055, B:17:0x006e, B:42:0x00de, B:45:0x00e4, B:46:0x00e7, B:26:0x008e, B:32:0x009c, B:33:0x00a6, B:35:0x00ac, B:36:0x00ca, B:31:0x0097, B:40:0x00d7), top: B:53:0x0002, inners: #0, #1 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$fixNotificationSettings$6$MessagesStorage() {
        /*
            Method dump skipped, instruction units count: 239
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$fixNotificationSettings$6$MessagesStorage():void");
    }

    public long createPendingTask(final NativeByteBuffer data) {
        if (data == null) {
            return 0L;
        }
        final long id = this.lastTaskId.getAndAdd(1L);
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$E9KAxmXjjQ4ELwEIoFKeJ6bu0EQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$createPendingTask$7$MessagesStorage(id, data);
            }
        });
        return id;
    }

    public /* synthetic */ void lambda$createPendingTask$7$MessagesStorage(long id, NativeByteBuffer data) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast("REPLACE INTO pending_tasks VALUES(?, ?)");
                state.bindLong(1, id);
                state.bindByteBuffer(2, data);
                state.step();
                state.dispose();
                state = null;
                data.reuse();
            } catch (Exception e) {
                FileLog.e("createPendingTask ---> exception ", e);
                data.reuse();
                if (state != null) {
                }
            }
            if (0 != 0) {
                state.dispose();
            }
        } catch (Throwable th) {
            data.reuse();
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void removePendingTask(final long id) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$JYZ8g7kj6_TZ7B6UwCRBtjgFpow
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$removePendingTask$8$MessagesStorage(id);
            }
        });
    }

    public /* synthetic */ void lambda$removePendingTask$8$MessagesStorage(long id) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast("DELETE FROM pending_tasks WHERE id = " + id);
                state.stepThis().dispose();
                state = null;
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("removePendingTask ---> exception ", e);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    private void loadPendingTasks() {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$uYQ_cvfyN4AuKhhUqF6waFh0xQQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$loadPendingTasks$23$MessagesStorage();
            }
        });
    }

    /*  JADX ERROR: Type inference failed with stack overflow
        jadx.core.utils.exceptions.JadxOverflowException
        	at jadx.core.utils.ErrorsCounter.addError(ErrorsCounter.java:59)
        	at jadx.core.utils.ErrorsCounter.error(ErrorsCounter.java:31)
        	at jadx.core.dex.attributes.nodes.NotificationAttrNode.addError(NotificationAttrNode.java:19)
        	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.visit(TypeInferenceVisitor.java:77)
        */
    public /* synthetic */ void lambda$loadPendingTasks$23$MessagesStorage() {
        /*
            Method dump skipped, instruction units count: 1168
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$loadPendingTasks$23$MessagesStorage():void");
    }

    public /* synthetic */ void lambda$null$9$MessagesStorage(TLRPC.Chat chat, long taskId) {
        getMessagesController().loadUnknownChannel(chat, taskId);
    }

    public /* synthetic */ void lambda$null$10$MessagesStorage(int channelId, int newDialogType, long taskId) {
        getMessagesController().getChannelDifference(channelId, newDialogType, taskId, null);
    }

    public /* synthetic */ void lambda$null$11$MessagesStorage(TLRPC.Dialog dialog, TLRPC.InputPeer peer, long taskId) {
        getMessagesController().checkLastDialogMessage(dialog, peer, taskId);
    }

    public /* synthetic */ void lambda$null$12$MessagesStorage(long did, boolean pin, TLRPC.InputPeer peer, long taskId) {
        getMessagesController().pinDialog(did, pin, peer, taskId);
    }

    public /* synthetic */ void lambda$null$13$MessagesStorage(int channelId, int newDialogType, long taskId, TLRPC.InputChannel inputChannel) {
        getMessagesController().getChannelDifference(channelId, newDialogType, taskId, inputChannel);
    }

    public /* synthetic */ void lambda$null$14$MessagesStorage(int channelId, long taskId, TLObject finalRequest) {
        getMessagesController().deleteMessages(null, null, null, 0L, channelId, true, false, taskId, finalRequest);
    }

    public /* synthetic */ void lambda$null$15$MessagesStorage(long did, TLRPC.InputPeer peer, long taskId) {
        getMessagesController().markDialogAsUnread(did, peer, taskId);
    }

    public /* synthetic */ void lambda$null$16$MessagesStorage(int mid, int channelId, TLRPC.InputChannel inputChannel, int ttl, long taskId) {
        getMessagesController().markMessageAsRead(mid, channelId, inputChannel, ttl, taskId);
    }

    public /* synthetic */ void lambda$null$17$MessagesStorage(long wallPaperId, String slug, long accessHash, boolean isBlurred, boolean isMotion, int backgroundColor, float intesity, boolean install, long taskId) {
        getMessagesController().saveWallpaperToServer(null, wallPaperId, slug, accessHash, isBlurred, isMotion, backgroundColor, intesity, install, taskId);
    }

    public /* synthetic */ void lambda$null$18$MessagesStorage(long did, boolean first, int onlyHistory, int maxIdDelete, boolean revoke, TLRPC.InputPeer inputPeer, long taskId) {
        getMessagesController().deleteDialog(did, first, onlyHistory, maxIdDelete, revoke, inputPeer, taskId);
    }

    public /* synthetic */ void lambda$null$19$MessagesStorage(TLRPC.InputPeer inputPeer, long taskId) {
        getMessagesController().loadUnknownDialog(inputPeer, taskId);
    }

    public /* synthetic */ void lambda$null$20$MessagesStorage(int folderId, ArrayList peers, long taskId) throws Exception {
        getMessagesController().reorderPinnedDialogs(folderId, peers, taskId);
    }

    public /* synthetic */ void lambda$null$21$MessagesStorage(int folderId, ArrayList peers, long taskId) {
        getMessagesController().addDialogToFolder(null, folderId, -1, peers, taskId);
    }

    public /* synthetic */ void lambda$null$22$MessagesStorage(long dialogId, int channelId, long taskId, TLObject finalRequest) {
        MessagesController.getInstance(this.currentAccount).deleteMessages(null, null, null, dialogId, channelId, true, true, taskId, finalRequest);
    }

    public void saveChannelPts(final int channelId, final int pts) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$0E4CaF5aG-fy4ASCKQ7M_uPPkQI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$saveChannelPts$24$MessagesStorage(pts, channelId);
            }
        });
    }

    public /* synthetic */ void lambda$saveChannelPts$24$MessagesStorage(int pts, int channelId) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast("UPDATE dialogs SET pts = ? WHERE did = ?");
                state.bindInteger(1, pts);
                state.bindInteger(2, -channelId);
                state.step();
                state.dispose();
                state = null;
            } catch (Exception e) {
                FileLog.e("saveChannelPts ---> exception ", e);
                if (state != null) {
                }
            }
            if (0 != 0) {
                state.dispose();
            }
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: saveDiffParamsInternal, reason: merged with bridge method [inline-methods] */
    public void lambda$saveDiffParams$25$MessagesStorage(int seq, int pts, int date, int qts) {
        if (this.lastSavedSeq == seq && this.lastSavedPts == pts && this.lastSavedDate == date && this.lastQtsValue == qts) {
            return;
        }
        SQLitePreparedStatement state = null;
        try {
            try {
                SQLitePreparedStatement state2 = this.database.executeFast("UPDATE params SET seq = ?, pts = ?, date = ?, qts = ? WHERE id = 1");
                state2.bindInteger(1, seq);
                state2.bindInteger(2, pts);
                state2.bindInteger(3, date);
                state2.bindInteger(4, qts);
                state2.step();
                state2.dispose();
                state = null;
                this.lastSavedSeq = seq;
                this.lastSavedPts = pts;
                this.lastSavedDate = date;
                this.lastSavedQts = qts;
            } catch (Exception e) {
                FileLog.e("saveDiffParamsInternal ---> exception ", e);
                if (state != null) {
                }
            }
            if (0 != 0) {
                state.dispose();
            }
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void saveDiffParams(final int seq, final int pts, final int date, final int qts) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$EdIFCxIsPXFEAI6GsmEwg2LuqZ0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$saveDiffParams$25$MessagesStorage(seq, pts, date, qts);
            }
        });
    }

    public void setDialogFlags(final long did, final long flags) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$NuvGO_TvuOJ2oqlbmH8zx0TZ5Fw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$setDialogFlags$26$MessagesStorage(did, flags);
            }
        });
    }

    public /* synthetic */ void lambda$setDialogFlags$26$MessagesStorage(long did, long flags) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast(String.format(Locale.US, "REPLACE INTO dialog_settings VALUES(%d, %d)", Long.valueOf(did), Long.valueOf(flags)));
                state.stepThis().dispose();
                state = null;
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("setDialogFlags ---> exception ", e);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void putPushMessage(final MessageObject message) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$YJi8jeK45ue2KqnlDQWjojS72YE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putPushMessage$27$MessagesStorage(message);
            }
        });
    }

    public /* synthetic */ void lambda$putPushMessage$27$MessagesStorage(MessageObject message) {
        NativeByteBuffer data = null;
        SQLitePreparedStatement state = null;
        try {
            try {
                NativeByteBuffer data2 = new NativeByteBuffer(message.messageOwner.getObjectSize());
                message.messageOwner.serializeToStream(data2);
                long messageId = message.getId();
                if (message.messageOwner.to_id.channel_id != 0) {
                    messageId |= ((long) message.messageOwner.to_id.channel_id) << 32;
                }
                int flags = message.localType == 2 ? 0 | 1 : 0;
                if (message.localChannel) {
                    flags |= 2;
                }
                state = this.database.executeFast("REPLACE INTO unread_push_messages VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)");
                state.requery();
                state.bindLong(1, message.getDialogId());
                state.bindLong(2, messageId);
                state.bindLong(3, message.messageOwner.random_id);
                state.bindInteger(4, message.messageOwner.date);
                state.bindByteBuffer(5, data2);
                if (message.messageText == null) {
                    state.bindNull(6);
                } else {
                    state.bindString(6, message.messageText.toString());
                }
                if (message.localName == null) {
                    state.bindNull(7);
                } else {
                    state.bindString(7, message.localName);
                }
                if (message.localUserName == null) {
                    state.bindNull(8);
                } else {
                    state.bindString(8, message.localUserName);
                }
                state.bindInteger(9, flags);
                state.step();
                data2.reuse();
                data = null;
                state.dispose();
                state = null;
                if (0 != 0) {
                    data.reuse();
                }
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("putPushMessage ---> exception ", e);
                if (data != null) {
                    data.reuse();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    private static class ReadDialog {
        public int date;
        public int lastMid;
        public int unreadCount;

        private ReadDialog() {
        }
    }

    public void readAllDialogs() {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$-yo0SSquN3QKoGGkZGuFxoqKaIA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$readAllDialogs$29$MessagesStorage();
            }
        });
    }

    public /* synthetic */ void lambda$readAllDialogs$29$MessagesStorage() {
        SQLiteCursor cursor = null;
        try {
            try {
                ArrayList<Integer> usersToLoad = new ArrayList<>();
                ArrayList<Integer> chatsToLoad = new ArrayList<>();
                ArrayList<Integer> encryptedChatIds = new ArrayList<>();
                final LongSparseArray<ReadDialog> dialogs = new LongSparseArray<>();
                SQLiteCursor cursor2 = this.database.queryFinalized("SELECT did, last_mid, unread_count, date FROM dialogs WHERE unread_count != 0", new Object[0]);
                while (cursor2.next()) {
                    long did = cursor2.longValue(0);
                    if (!DialogObject.isFolderDialogId(did)) {
                        ReadDialog dialog = new ReadDialog();
                        dialog.lastMid = cursor2.intValue(1);
                        dialog.unreadCount = cursor2.intValue(2);
                        dialog.date = cursor2.intValue(3);
                        dialogs.put(did, dialog);
                        int lower_id = (int) did;
                        int high_id = (int) (did >> 32);
                        if (lower_id != 0) {
                            if (lower_id < 0) {
                                if (!chatsToLoad.contains(Integer.valueOf(-lower_id))) {
                                    chatsToLoad.add(Integer.valueOf(-lower_id));
                                }
                            } else if (!usersToLoad.contains(Integer.valueOf(lower_id))) {
                                usersToLoad.add(Integer.valueOf(lower_id));
                            }
                        } else if (!encryptedChatIds.contains(Integer.valueOf(high_id))) {
                            encryptedChatIds.add(Integer.valueOf(high_id));
                        }
                    }
                }
                cursor2.dispose();
                cursor = null;
                final ArrayList<TLRPC.User> users = new ArrayList<>();
                final ArrayList<TLRPC.Chat> chats = new ArrayList<>();
                final ArrayList<TLRPC.EncryptedChat> encryptedChats = new ArrayList<>();
                if (!encryptedChatIds.isEmpty()) {
                    getEncryptedChatsInternal(TextUtils.join(",", encryptedChatIds), encryptedChats, usersToLoad);
                }
                if (!usersToLoad.isEmpty()) {
                    getUsersInternal(TextUtils.join(",", usersToLoad), users);
                }
                if (!chatsToLoad.isEmpty()) {
                    getChatsInternal(TextUtils.join(",", chatsToLoad), chats);
                }
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$MJFgolLQOzpOJaazSViabbYj7PY
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$28$MessagesStorage(users, chats, encryptedChats, dialogs);
                    }
                });
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("readAllDialogs ---> exception ", e);
                if (cursor == null) {
                    return;
                }
            }
            cursor.dispose();
        } catch (Throwable th) {
            if (cursor != null) {
                cursor.dispose();
            }
            throw th;
        }
    }

    public /* synthetic */ void lambda$null$28$MessagesStorage(ArrayList users, ArrayList chats, ArrayList encryptedChats, LongSparseArray dialogs) {
        getMessagesController().putUsers(users, true);
        getMessagesController().putChats(chats, true);
        getMessagesController().putEncryptedChats(encryptedChats, true);
        for (int a = 0; a < dialogs.size(); a++) {
            long did = dialogs.keyAt(a);
            ReadDialog dialog = (ReadDialog) dialogs.valueAt(a);
            getMessagesController().markDialogAsRead(did, dialog.lastMid, dialog.lastMid, dialog.date, false, dialog.unreadCount, true, 0);
        }
    }

    public void loadUnreadMessages() {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$TXDfwBHoWQ746av508UUdkEIEHk
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$loadUnreadMessages$31$MessagesStorage();
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:105:0x026c  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x0274 A[Catch: all -> 0x02e4, Exception -> 0x02ee, TRY_LEAVE, TryCatch #60 {Exception -> 0x02ee, all -> 0x02e4, blocks: (B:106:0x0270, B:108:0x0274), top: B:433:0x0270 }] */
    /* JADX WARN: Removed duplicated region for block: B:129:0x02d9  */
    /* JADX WARN: Removed duplicated region for block: B:296:0x0621 A[Catch: all -> 0x0733, Exception -> 0x073d, TRY_ENTER, TRY_LEAVE, TryCatch #54 {Exception -> 0x073d, all -> 0x0733, blocks: (B:269:0x05b4, B:278:0x05d6, B:283:0x05e8, B:285:0x05ee, B:286:0x05f8, B:288:0x05fe, B:290:0x0606, B:296:0x0621), top: B:445:0x05b4 }] */
    /* JADX WARN: Removed duplicated region for block: B:395:0x0855  */
    /* JADX WARN: Removed duplicated region for block: B:397:0x085a  */
    /* JADX WARN: Removed duplicated region for block: B:399:0x085f  */
    /* JADX WARN: Removed duplicated region for block: B:413:0x0216 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$loadUnreadMessages$31$MessagesStorage() throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 2169
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$loadUnreadMessages$31$MessagesStorage():void");
    }

    public /* synthetic */ void lambda$null$30$MessagesStorage(LongSparseArray pushDialogs, ArrayList messages, ArrayList pushMessages, ArrayList users, ArrayList chats, ArrayList encryptedChats) {
        getNotificationsController().processLoadedUnreadMessages(pushDialogs, messages, pushMessages, users, chats, encryptedChats);
    }

    public void putWallpapers(final ArrayList<TLRPC.WallPaper> wallPapers, final int action) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$Z3IyELkG2Wmd23G607wgCg2OrnA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putWallpapers$32$MessagesStorage(action, wallPapers);
            }
        });
    }

    public /* synthetic */ void lambda$putWallpapers$32$MessagesStorage(int action, ArrayList wallPapers) {
        SQLitePreparedStatement state = null;
        NativeByteBuffer data = null;
        try {
            if (action == 1) {
                try {
                    this.database.executeFast("DELETE FROM wallpapers2 WHERE 1").stepThis().dispose();
                } catch (Exception e) {
                    FileLog.e("putWallpapers ---> exception 2 ", e);
                    if (data != null) {
                        data.reuse();
                    }
                    if (state == null) {
                        return;
                    }
                }
            }
            try {
                this.database.beginTransaction();
            } catch (Exception e2) {
                FileLog.e("putWallpapers ---> exception 1 ", e2);
            }
            SQLitePreparedStatement state2 = action != 0 ? this.database.executeFast("REPLACE INTO wallpapers2 VALUES(?, ?, ?)") : this.database.executeFast("UPDATE wallpapers2 SET data = ? WHERE uid = ?");
            int N = wallPapers.size();
            for (int a = 0; a < N; a++) {
                TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) wallPapers.get(a);
                state2.requery();
                NativeByteBuffer data2 = new NativeByteBuffer(wallPaper.getObjectSize());
                wallPaper.serializeToStream(data2);
                if (action != 0) {
                    state2.bindLong(1, wallPaper.id);
                    state2.bindByteBuffer(2, data2);
                    state2.bindInteger(3, action == 2 ? -1 : a);
                } else {
                    state2.bindByteBuffer(1, data2);
                    state2.bindLong(2, wallPaper.id);
                }
                state2.step();
                data2.reuse();
                data = null;
            }
            state2.dispose();
            state = null;
            this.database.commitTransaction();
            if (data != null) {
                data.reuse();
            }
            if (0 == 0) {
                return;
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void getWallpapers() {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$PHeZrLdi5z7JRQ5ybEpsbsE7K-A
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getWallpapers$34$MessagesStorage();
            }
        });
    }

    public /* synthetic */ void lambda$getWallpapers$34$MessagesStorage() {
        SQLiteCursor cursor = null;
        NativeByteBuffer data = null;
        try {
            try {
                SQLiteCursor cursor2 = this.database.queryFinalized("SELECT data FROM wallpapers2 WHERE 1 ORDER BY num ASC", new Object[0]);
                final ArrayList<TLRPC.TL_wallPaper> wallPapers = new ArrayList<>();
                while (cursor2.next()) {
                    data = cursor2.byteBufferValue(0);
                    if (data != null) {
                        TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) TLRPC.WallPaper.TLdeserialize(data, data.readInt32(false), false);
                        data.reuse();
                        data = null;
                        if (wallPaper != null) {
                            wallPapers.add(wallPaper);
                        }
                    }
                }
                cursor2.dispose();
                cursor = null;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$7jEyo5OYYwbXqGmCFUYK0bUZmFc
                    @Override // java.lang.Runnable
                    public final void run() {
                        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.wallpapersDidLoad, wallPapers);
                    }
                });
                if (data != null) {
                    data.reuse();
                }
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("getWallpapers ---> exception ", e);
                if (data != null) {
                    data.reuse();
                }
                if (cursor == null) {
                    return;
                }
            }
            cursor.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (cursor != null) {
                cursor.dispose();
            }
            throw th;
        }
    }

    public void loadWebRecent(final int type) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$GJIPMzbFIgwz5A8bnosc3Xon5GQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$loadWebRecent$36$MessagesStorage(type);
            }
        });
    }

    public /* synthetic */ void lambda$loadWebRecent$36$MessagesStorage(final int type) {
        try {
            final ArrayList<MediaController.SearchImage> arrayList = new ArrayList<>();
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$2bd_IiGV4nnq1JWWV8kYuZo657g
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$35$MessagesStorage(type, arrayList);
                }
            });
        } catch (Throwable e) {
            FileLog.e("loadWebRecent ---> exception ", e);
        }
    }

    public /* synthetic */ void lambda$null$35$MessagesStorage(int type, ArrayList arrayList) {
        getNotificationCenter().postNotificationName(NotificationCenter.recentImagesDidLoad, Integer.valueOf(type), arrayList);
    }

    public void addRecentLocalFile(final String imageUrl, final String localUrl, final TLRPC.Document document) {
        if (imageUrl == null || imageUrl.length() == 0) {
            return;
        }
        if ((localUrl == null || localUrl.length() == 0) && document == null) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$rie7SRyN6LW9rfaYZH-7ug7HaSY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$addRecentLocalFile$37$MessagesStorage(document, imageUrl, localUrl);
            }
        });
    }

    public /* synthetic */ void lambda$addRecentLocalFile$37$MessagesStorage(TLRPC.Document document, String imageUrl, String localUrl) {
        SQLitePreparedStatement state = null;
        NativeByteBuffer data = null;
        try {
            try {
                if (document != null) {
                    SQLitePreparedStatement state2 = this.database.executeFast("UPDATE web_recent_v3 SET document = ? WHERE image_url = ?");
                    state2.requery();
                    NativeByteBuffer data2 = new NativeByteBuffer(document.getObjectSize());
                    document.serializeToStream(data2);
                    state2.bindByteBuffer(1, data2);
                    state2.bindString(2, imageUrl);
                    state2.step();
                    state2.dispose();
                    state = null;
                    data2.reuse();
                    data = null;
                } else {
                    SQLitePreparedStatement state3 = this.database.executeFast("UPDATE web_recent_v3 SET local_url = ? WHERE image_url = ?");
                    state3.requery();
                    state3.bindString(1, localUrl);
                    state3.bindString(2, imageUrl);
                    state3.step();
                    state3.dispose();
                    state = null;
                }
                if (data != null) {
                    data.reuse();
                }
                if (state == null) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("addRecentLocalFile ---> exception ", e);
                if (data != null) {
                    data.reuse();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void clearWebRecent(final int type) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$ybLfQ6Ax2J-3XaqaVeYfnxce1ds
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$clearWebRecent$38$MessagesStorage(type);
            }
        });
    }

    public /* synthetic */ void lambda$clearWebRecent$38$MessagesStorage(int type) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast("DELETE FROM web_recent_v3 WHERE type = " + type);
                state.stepThis().dispose();
                state = null;
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("clearWebRecent ---> exception ", e);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void putWebRecent(final ArrayList<MediaController.SearchImage> arrayList) {
        if (arrayList.isEmpty() || !arrayList.isEmpty()) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$r7EMoUlsdGXOIszPq9uyEk4n2VU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putWebRecent$39$MessagesStorage(arrayList);
            }
        });
    }

    public /* synthetic */ void lambda$putWebRecent$39$MessagesStorage(ArrayList arrayList) {
        SQLitePreparedStatement state = null;
        NativeByteBuffer data = null;
        try {
            try {
                this.database.beginTransaction();
            } catch (Exception e) {
                try {
                    FileLog.e("putWebRecent ---> exception 1 ", e);
                } catch (Exception e2) {
                    FileLog.e("putWebRecent ---> exception 3 ", e2);
                    if (data != null) {
                        data.reuse();
                    }
                    if (state == null) {
                        return;
                    }
                }
            }
            SQLitePreparedStatement state2 = this.database.executeFast("REPLACE INTO web_recent_v3 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            for (int a = 0; a < arrayList.size() && a != 200; a++) {
                MediaController.SearchImage searchImage = (MediaController.SearchImage) arrayList.get(a);
                state2.requery();
                state2.bindString(1, searchImage.id);
                state2.bindInteger(2, searchImage.type);
                state2.bindString(3, searchImage.imageUrl != null ? searchImage.imageUrl : "");
                state2.bindString(4, searchImage.thumbUrl != null ? searchImage.thumbUrl : "");
                state2.bindString(5, "");
                state2.bindInteger(6, searchImage.width);
                state2.bindInteger(7, searchImage.height);
                state2.bindInteger(8, searchImage.size);
                state2.bindInteger(9, searchImage.date);
                if (searchImage.photo != null) {
                    data = new NativeByteBuffer(searchImage.photo.getObjectSize());
                    searchImage.photo.serializeToStream(data);
                    state2.bindByteBuffer(10, data);
                } else if (searchImage.document != null) {
                    data = new NativeByteBuffer(searchImage.document.getObjectSize());
                    searchImage.document.serializeToStream(data);
                    state2.bindByteBuffer(10, data);
                } else {
                    state2.bindNull(10);
                }
                state2.step();
                if (data != null) {
                    data.reuse();
                    data = null;
                }
            }
            state2.dispose();
            state = null;
            this.database.commitTransaction();
            if (arrayList.size() >= 200) {
                try {
                    this.database.beginTransaction();
                } catch (Exception e3) {
                    FileLog.e("putWebRecent ---> exception 2 ", e3);
                }
                for (int a2 = ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION; a2 < arrayList.size(); a2++) {
                    this.database.executeFast("DELETE FROM web_recent_v3 WHERE id = '" + ((MediaController.SearchImage) arrayList.get(a2)).id + "'").stepThis().dispose();
                    state = null;
                }
                this.database.commitTransaction();
            }
            if (data != null) {
                data.reuse();
            }
            if (state == null) {
                return;
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void deleteUserChannelHistory(final int channelId, final int uid) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$7K0k0mh7mCrBKT7CZUA-a_XrVtQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$deleteUserChannelHistory$42$MessagesStorage(channelId, uid);
            }
        });
    }

    public /* synthetic */ void lambda$deleteUserChannelHistory$42$MessagesStorage(final int channelId, int uid) {
        SQLiteCursor cursor = null;
        NativeByteBuffer data = null;
        long did = -channelId;
        try {
            try {
                final ArrayList<Integer> mids = new ArrayList<>();
                SQLiteCursor cursor2 = this.database.queryFinalized("SELECT data FROM messages WHERE uid = " + did, new Object[0]);
                ArrayList<File> filesToDelete = new ArrayList<>();
                while (cursor2.next()) {
                    try {
                        data = cursor2.byteBufferValue(0);
                        if (data != null) {
                            TLRPC.Message message = TLRPC.Message.TLdeserialize(data, data.readInt32(false), false);
                            message.readAttachPath(data, getUserConfig().clientUserId);
                            data.reuse();
                            data = null;
                            if (message != null && message.from_id == uid && message.id != 1) {
                                mids.add(Integer.valueOf(message.id));
                                addFilesToDelete(message, filesToDelete, false);
                            }
                        }
                    } catch (Exception e) {
                        FileLog.e("deleteUserChannelHistory ---> exception 1 ", e);
                    }
                }
                cursor2.dispose();
                cursor = null;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$xgeCBggq4hwNzLCV57Go5ZWn6I4
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$40$MessagesStorage(mids, channelId);
                    }
                });
                lambda$markMessagesAsDeleted$135$MessagesStorage(mids, channelId, false, false);
                lambda$updateDialogsWithDeletedMessages$134$MessagesStorage(mids, null, channelId);
                getFileLoader().deleteFiles(filesToDelete, 0);
                if (!mids.isEmpty()) {
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$jX8TOiw3r3-qUMLGGls8vmlrve0
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$null$41$MessagesStorage(mids, channelId);
                        }
                    });
                }
                if (data != null) {
                    data.reuse();
                }
                if (0 == 0) {
                    return;
                }
            } catch (Exception e2) {
                FileLog.e("deleteUserChannelHistory ---> exception 2 ", e2);
                if (data != null) {
                    data.reuse();
                }
                if (cursor == null) {
                    return;
                }
            }
            cursor.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (cursor != null) {
                cursor.dispose();
            }
            throw th;
        }
    }

    public /* synthetic */ void lambda$null$40$MessagesStorage(ArrayList mids, int channelId) {
        getMessagesController().markChannelDialogMessageAsDeleted(mids, channelId);
    }

    public /* synthetic */ void lambda$null$41$MessagesStorage(ArrayList mids, int channelId) {
        getNotificationCenter().postNotificationName(NotificationCenter.messagesDeleted, mids, Integer.valueOf(channelId), false);
    }

    private boolean addFilesToDelete(TLRPC.Message message, ArrayList<File> filesToDelete, boolean forceCache) {
        if (message == null) {
            return false;
        }
        if ((message.media instanceof TLRPC.TL_messageMediaPhoto) && message.media.photo != null) {
            int N = message.media.photo.sizes.size();
            for (int a = 0; a < N; a++) {
                TLRPC.PhotoSize photoSize = message.media.photo.sizes.get(a);
                File file = FileLoader.getPathToAttach(photoSize);
                if (file != null && file.toString().length() > 0) {
                    filesToDelete.add(file);
                }
            }
            return true;
        }
        if (!(message.media instanceof TLRPC.TL_messageMediaDocument) || message.media.document == null) {
            return false;
        }
        File file2 = FileLoader.getPathToAttach(message.media.document, forceCache);
        if (file2 != null && file2.toString().length() > 0) {
            filesToDelete.add(file2);
        }
        int N2 = message.media.document.thumbs.size();
        for (int a2 = 0; a2 < N2; a2++) {
            TLRPC.PhotoSize photoSize2 = message.media.document.thumbs.get(a2);
            File file3 = FileLoader.getPathToAttach(photoSize2);
            if (file3 != null && file3.toString().length() > 0) {
                filesToDelete.add(file3);
            }
        }
        return true;
    }

    public void deleteDialog(final long did, final int messagesOnly) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$TO4r50MlPwnzYD9ecjNRsgCcAQI
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$deleteDialog$44$MessagesStorage(messagesOnly, did);
            }
        });
    }

    /* JADX WARN: Can't wrap try/catch for region: R(18:0|2|(7:4|228|5|(1:7)|8|9|(5:(1:12)|(1:14)|(1:16)|(1:18)|(2:20|21)(1:275)))|26|(5:230|29|(5:32|(3:270|34|274)(1:273)|272|224|30)|271|40)|41|(1:247)|(12:(2:43|(1:45)(2:46|(18:259|48|49|236|50|51|52|53|240|54|(22:56|57|249|58|59|(6:62|63|(5:265|65|255|66|(4:264|68|69|269)(3:262|70|268))(3:261|76|267)|266|242|60)|263|77|(1:79)|88|251|89|90|238|91|92|232|93|94|(2:253|96)|97|98)(1:125)|126|127|(1:129)|(1:131)|(1:133)|(1:135)|(2:137|138)(1:277))(17:155|164|165|166|234|167|257|168|169|(1:171)|(1:173)|(1:175)|(1:177)|(1:179)|180|246|212)))(1:156)|257|168|169|(0)|(0)|(0)|(0)|(0)|180|246|212)|157|244|158|(1:160)(2:161|162)|163|164|165|166|234|167) */
    /* JADX WARN: Code restructure failed: missing block: B:185:0x059d, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:186:0x059e, code lost:
    
        r2 = r0;
        r6 = r16;
        r7 = r17;
        r10 = null;
        r9 = r20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:187:0x05a9, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:188:0x05aa, code lost:
    
        r2 = r0;
        r6 = r16;
        r7 = r17;
        r10 = null;
        r9 = r20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:189:0x05b4, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:190:0x05b5, code lost:
    
        r2 = r0;
        r8 = r6;
        r6 = r16;
        r7 = r17;
        r10 = null;
        r9 = r20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:191:0x05c1, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:192:0x05c2, code lost:
    
        r2 = r0;
        r8 = r6;
        r6 = r16;
        r7 = r17;
        r10 = null;
        r9 = r20;
     */
    /* JADX WARN: Removed duplicated region for block: B:118:0x02f8 A[Catch: all -> 0x02da, Exception -> 0x02e6, TRY_ENTER, TryCatch #27 {Exception -> 0x02e6, all -> 0x02da, blocks: (B:118:0x02f8, B:120:0x02fc, B:88:0x01a8, B:79:0x0194), top: B:242:0x0155 }] */
    /* JADX WARN: Removed duplicated region for block: B:129:0x032b  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x0330  */
    /* JADX WARN: Removed duplicated region for block: B:133:0x0335  */
    /* JADX WARN: Removed duplicated region for block: B:135:0x033a  */
    /* JADX WARN: Removed duplicated region for block: B:137:0x033f  */
    /* JADX WARN: Removed duplicated region for block: B:171:0x0564  */
    /* JADX WARN: Removed duplicated region for block: B:173:0x0569  */
    /* JADX WARN: Removed duplicated region for block: B:175:0x056e  */
    /* JADX WARN: Removed duplicated region for block: B:177:0x0573  */
    /* JADX WARN: Removed duplicated region for block: B:179:0x0578  */
    /* JADX WARN: Removed duplicated region for block: B:203:0x05ff  */
    /* JADX WARN: Removed duplicated region for block: B:205:0x0604  */
    /* JADX WARN: Removed duplicated region for block: B:207:0x0609  */
    /* JADX WARN: Removed duplicated region for block: B:209:0x060e  */
    /* JADX WARN: Removed duplicated region for block: B:211:0x0613  */
    /* JADX WARN: Removed duplicated region for block: B:214:0x0619  */
    /* JADX WARN: Removed duplicated region for block: B:216:0x061e  */
    /* JADX WARN: Removed duplicated region for block: B:218:0x0623  */
    /* JADX WARN: Removed duplicated region for block: B:220:0x0628  */
    /* JADX WARN: Removed duplicated region for block: B:222:0x062d  */
    /* JADX WARN: Removed duplicated region for block: B:253:0x0290 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:276:? A[Catch: all -> 0x02da, Exception -> 0x02e6, SYNTHETIC, TRY_LEAVE, TryCatch #27 {Exception -> 0x02e6, all -> 0x02da, blocks: (B:118:0x02f8, B:120:0x02fc, B:88:0x01a8, B:79:0x0194), top: B:242:0x0155 }] */
    /* JADX WARN: Removed duplicated region for block: B:277:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:279:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:280:? A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:79:0x0194 A[Catch: all -> 0x02da, Exception -> 0x02e6, PHI: r7 r16
      0x0194: PHI (r7v60 'data' im.uwrkaxlmjj.tgnet.NativeByteBuffer) = (r7v62 'data' im.uwrkaxlmjj.tgnet.NativeByteBuffer), (r7v58 'data' im.uwrkaxlmjj.tgnet.NativeByteBuffer) binds: [B:86:0x01a5, B:78:0x0192] A[DONT_GENERATE, DONT_INLINE]
      0x0194: PHI (r16v13 'messageId' int) = (r16v15 'messageId' int), (r16v16 'messageId' int) binds: [B:86:0x01a5, B:78:0x0192] A[DONT_GENERATE, DONT_INLINE], TRY_ENTER, TRY_LEAVE, TryCatch #27 {Exception -> 0x02e6, all -> 0x02da, blocks: (B:118:0x02f8, B:120:0x02fc, B:88:0x01a8, B:79:0x0194), top: B:242:0x0155 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$deleteDialog$44$MessagesStorage(int r28, long r29) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 1585
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$deleteDialog$44$MessagesStorage(int, long):void");
    }

    public /* synthetic */ void lambda$null$43$MessagesStorage() {
        getNotificationCenter().postNotificationName(NotificationCenter.needReloadRecentDialogsSearch, new Object[0]);
    }

    public void onDeleteQueryComplete(final long did) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$l-s7tOFumFIUhGKcr2G2VMJsa6E
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onDeleteQueryComplete$45$MessagesStorage(did);
            }
        });
    }

    public /* synthetic */ void lambda$onDeleteQueryComplete$45$MessagesStorage(long did) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast("DELETE FROM media_counts_v2 WHERE uid = " + did);
                state.stepThis().dispose();
                state = null;
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("onDeleteQueryComplete ---> exception ", e);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void getDialogPhotos(final int did, final int count, final long max_id, final int classGuid) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$Nw_jIEUMV-WOxn_eNP6fXP2fsWE
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$getDialogPhotos$47$MessagesStorage(max_id, did, count, classGuid);
            }
        });
    }

    public /* synthetic */ void lambda$getDialogPhotos$47$MessagesStorage(final long max_id, final int did, final int count, final int classGuid) throws Throwable {
        final TLRPC.photos_Photos res;
        NativeByteBuffer data;
        SQLiteCursor cursor;
        SQLiteCursor cursor2 = null;
        NativeByteBuffer data2 = null;
        try {
            try {
                cursor2 = max_id != 0 ? this.database.queryFinalized(String.format(Locale.US, "SELECT data FROM user_photos WHERE uid = %d AND id < %d ORDER BY rowid ASC LIMIT %d", Integer.valueOf(did), Long.valueOf(max_id), Integer.valueOf(count)), new Object[0]) : this.database.queryFinalized(String.format(Locale.US, "SELECT data FROM user_photos WHERE uid = %d ORDER BY rowid ASC LIMIT %d", Integer.valueOf(did), Integer.valueOf(count)), new Object[0]);
                res = new TLRPC.TL_photos_photos();
                data = null;
                while (cursor2.next()) {
                    try {
                        data = cursor2.byteBufferValue(0);
                        if (data != null) {
                            TLRPC.Photo photo = TLRPC.Photo.TLdeserialize(data, data.readInt32(false), false);
                            data.reuse();
                            data = null;
                            res.photos.add(photo);
                        }
                    } catch (Exception e) {
                        e = e;
                        data2 = data;
                    } catch (Throwable th) {
                        th = th;
                        data2 = data;
                    }
                }
                cursor2.dispose();
                cursor = null;
            } catch (Exception e2) {
                e = e2;
            }
        } catch (Throwable th2) {
            th = th2;
        }
        try {
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$WoSuwwCzMV86nnb5QW9CDOjuJkU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$46$MessagesStorage(res, did, count, max_id, classGuid);
                }
            });
            if (data != null) {
                data.reuse();
            }
            if (0 != 0) {
                cursor.dispose();
            }
        } catch (Exception e3) {
            e = e3;
            data2 = data;
            cursor2 = null;
            FileLog.e("getDialogPhotos ---> exception ", e);
            if (data2 != null) {
                data2.reuse();
            }
            if (cursor2 != null) {
                cursor2.dispose();
            }
        } catch (Throwable th3) {
            th = th3;
            data2 = data;
            cursor2 = null;
            if (data2 != null) {
                data2.reuse();
            }
            if (cursor2 != null) {
                cursor2.dispose();
            }
            throw th;
        }
    }

    public /* synthetic */ void lambda$null$46$MessagesStorage(TLRPC.photos_Photos res, int did, int count, long max_id, int classGuid) {
        getMessagesController().processLoadedUserPhotos(res, did, count, max_id, true, classGuid);
    }

    public void clearUserPhotos(final int uid) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$HGD1KZl86djyRpYobEven10yjHc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$clearUserPhotos$48$MessagesStorage(uid);
            }
        });
    }

    public /* synthetic */ void lambda$clearUserPhotos$48$MessagesStorage(int uid) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast("DELETE FROM user_photos WHERE uid = " + uid);
                state.stepThis().dispose();
                state = null;
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("clearUserPhotos ---> exception 1 ", e);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void clearUserPhoto(final int uid, final long pid) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$SCWtDIUT21V4NrtyWJwH1gY7iJc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$clearUserPhoto$49$MessagesStorage(uid, pid);
            }
        });
    }

    public /* synthetic */ void lambda$clearUserPhoto$49$MessagesStorage(int uid, long pid) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast("DELETE FROM user_photos WHERE uid = " + uid + " AND id = " + pid);
                state.stepThis().dispose();
                state = null;
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("clearUserPhotos ---> exception 2 ", e);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void resetDialogs(final TLRPC.messages_Dialogs dialogsRes, final int messagesCount, final int seq, final int newPts, final int date, final int qts, final LongSparseArray<TLRPC.Dialog> new_dialogs_dict, final LongSparseArray<MessageObject> new_dialogMessage, final TLRPC.Message lastMessage, final int dialogsCount) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$JIkTgnkW7tRG0s1kHqU1ynnQClQ
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$resetDialogs$51$MessagesStorage(dialogsRes, dialogsCount, seq, newPts, date, qts, lastMessage, messagesCount, new_dialogs_dict, new_dialogMessage);
            }
        });
    }

    public /* synthetic */ void lambda$resetDialogs$51$MessagesStorage(TLRPC.messages_Dialogs dialogsRes, int dialogsCount, int seq, int newPts, int date, int qts, TLRPC.Message lastMessage, int messagesCount, LongSparseArray new_dialogs_dict, LongSparseArray new_dialogMessage) throws Throwable {
        int totalPinnedCount;
        final LongSparseArray<Integer> oldPinnedDialogNums;
        ArrayList<Long> oldPinnedOrder;
        ArrayList<Long> orderArrayList;
        int maxPinnedNum;
        SQLiteCursor cursor;
        SQLitePreparedStatement state;
        int a;
        int dialogsLoadOffsetUserId;
        int dialogsLoadOffsetChatId;
        int dialogsLoadOffsetChannelId;
        SQLiteCursor cursor2 = null;
        SQLitePreparedStatement state2 = null;
        try {
            try {
                ArrayList<Integer> dids = new ArrayList<>();
                totalPinnedCount = dialogsRes.dialogs.size() - dialogsCount;
                oldPinnedDialogNums = new LongSparseArray<>();
                oldPinnedOrder = new ArrayList<>();
                orderArrayList = new ArrayList<>();
                for (int a2 = dialogsCount; a2 < dialogsRes.dialogs.size(); a2++) {
                    orderArrayList.add(Long.valueOf(dialogsRes.dialogs.get(a2).id));
                }
                int maxPinnedNum2 = 0;
                cursor2 = this.database.queryFinalized("SELECT did, pinned FROM dialogs WHERE 1", new Object[0]);
                maxPinnedNum = 0;
                while (cursor2.next()) {
                    long did = cursor2.longValue(maxPinnedNum2);
                    int pinnedNum = cursor2.intValue(1);
                    int lower_id = (int) did;
                    if (lower_id != 0) {
                        dids.add(Integer.valueOf(lower_id));
                        if (pinnedNum > 0) {
                            int maxPinnedNum3 = Math.max(pinnedNum, maxPinnedNum);
                            oldPinnedDialogNums.put(did, Integer.valueOf(pinnedNum));
                            oldPinnedOrder.add(Long.valueOf(did));
                            maxPinnedNum = maxPinnedNum3;
                        }
                    }
                    maxPinnedNum2 = 0;
                }
                Collections.sort(oldPinnedOrder, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$-LFZ-LWo4p2dYpRA4CC67uTdWwA
                    @Override // java.util.Comparator
                    public final int compare(Object obj, Object obj2) {
                        return MessagesStorage.lambda$null$50(oldPinnedDialogNums, (Long) obj, (Long) obj2);
                    }
                });
                while (oldPinnedOrder.size() < totalPinnedCount) {
                    oldPinnedOrder.add(0, 0L);
                }
                cursor2.dispose();
                cursor = null;
                try {
                    try {
                        String ids = SQLBuilder.PARENTHESES_LEFT + TextUtils.join(",", dids) + SQLBuilder.PARENTHESES_RIGHT;
                        try {
                            this.database.beginTransaction();
                        } catch (Exception e) {
                            FileLog.e("resetDialogs ---> exception 1 ", e);
                        }
                        this.database.executeFast("DELETE FROM dialogs WHERE did IN " + ids).stepThis().dispose();
                        this.database.executeFast("DELETE FROM messages WHERE uid IN " + ids).stepThis().dispose();
                        this.database.executeFast("DELETE FROM polls WHERE 1").stepThis().dispose();
                        this.database.executeFast("DELETE FROM bot_keyboard WHERE uid IN " + ids).stepThis().dispose();
                        this.database.executeFast("DELETE FROM media_v2 WHERE uid IN " + ids).stepThis().dispose();
                        this.database.executeFast("DELETE FROM messages_holes WHERE uid IN " + ids).stepThis().dispose();
                        state2 = this.database.executeFast("DELETE FROM media_holes_v2 WHERE uid IN " + ids);
                        state2.stepThis().dispose();
                        state = null;
                    } catch (Exception e2) {
                        e = e2;
                        cursor2 = null;
                    }
                } catch (Throwable th) {
                    th = th;
                    cursor2 = null;
                }
            } catch (Throwable th2) {
                th = th2;
            }
        } catch (Exception e3) {
            e = e3;
        }
        try {
            this.database.commitTransaction();
            for (int a3 = 0; a3 < totalPinnedCount; a3++) {
                TLRPC.Dialog dialog = dialogsRes.dialogs.get(dialogsCount + a3);
                if (!(dialog instanceof TLRPC.TL_dialog) || dialog.pinned) {
                    int oldIdx = oldPinnedOrder.indexOf(Long.valueOf(dialog.id));
                    int newIdx = orderArrayList.indexOf(Long.valueOf(dialog.id));
                    if (oldIdx != -1 && newIdx != -1) {
                        if (oldIdx == newIdx) {
                            Integer oldNum = oldPinnedDialogNums.get(dialog.id);
                            if (oldNum != null) {
                                dialog.pinnedNum = oldNum.intValue();
                            }
                        } else {
                            long oldDid = oldPinnedOrder.get(newIdx).longValue();
                            Integer oldNum2 = oldPinnedDialogNums.get(oldDid);
                            if (oldNum2 != null) {
                                dialog.pinnedNum = oldNum2.intValue();
                            }
                        }
                    }
                    if (dialog.pinnedNum == 0) {
                        dialog.pinnedNum = (totalPinnedCount - a3) + maxPinnedNum;
                    }
                }
            }
            putDialogsInternal(dialogsRes, 0);
            lambda$saveDiffParams$25$MessagesStorage(seq, newPts, date, qts);
            int totalDialogsLoadCount = getUserConfig().getTotalDialogsCount(0);
            getUserConfig().getDialogLoadOffsets(0);
            int dialogsLoadOffsetChatId2 = 0;
            long dialogsLoadOffsetAccess = 0;
            int totalDialogsLoadCount2 = totalDialogsLoadCount + dialogsRes.dialogs.size();
            int dialogsLoadOffsetId = lastMessage.id;
            int dialogsLoadOffsetDate = lastMessage.date;
            if (lastMessage.to_id.channel_id != 0) {
                int dialogsLoadOffsetChannelId2 = lastMessage.to_id.channel_id;
                dialogsLoadOffsetChatId2 = 0;
                int a4 = 0;
                while (true) {
                    if (a4 >= dialogsRes.chats.size()) {
                        break;
                    }
                    TLRPC.Chat chat = dialogsRes.chats.get(a4);
                    if (chat.id == dialogsLoadOffsetChannelId2) {
                        dialogsLoadOffsetAccess = chat.access_hash;
                        break;
                    }
                    a4++;
                }
                a = 0;
                dialogsLoadOffsetUserId = dialogsLoadOffsetChannelId2;
            } else if (lastMessage.to_id.chat_id != 0) {
                int dialogsLoadOffsetChatId3 = lastMessage.to_id.chat_id;
                int a5 = 0;
                while (true) {
                    if (a5 >= dialogsRes.chats.size()) {
                        dialogsLoadOffsetChatId = dialogsLoadOffsetChatId3;
                        dialogsLoadOffsetChannelId = 0;
                        break;
                    }
                    TLRPC.Chat chat2 = dialogsRes.chats.get(a5);
                    if (chat2.id == dialogsLoadOffsetChatId3) {
                        dialogsLoadOffsetChatId = dialogsLoadOffsetChatId3;
                        dialogsLoadOffsetChannelId = 0;
                        dialogsLoadOffsetAccess = chat2.access_hash;
                        break;
                    }
                    a5++;
                }
                a = 0;
                dialogsLoadOffsetUserId = dialogsLoadOffsetChannelId;
                dialogsLoadOffsetChatId2 = dialogsLoadOffsetChatId;
            } else if (lastMessage.to_id.user_id != 0) {
                a = lastMessage.to_id.user_id;
                dialogsLoadOffsetChatId2 = 0;
                int a6 = 0;
                while (true) {
                    if (a6 >= dialogsRes.users.size()) {
                        dialogsLoadOffsetUserId = 0;
                        break;
                    }
                    TLRPC.User user = dialogsRes.users.get(a6);
                    if (user.id == a) {
                        dialogsLoadOffsetUserId = 0;
                        dialogsLoadOffsetAccess = user.access_hash;
                        a = a;
                        break;
                    }
                    a6++;
                }
            } else {
                a = 0;
                dialogsLoadOffsetUserId = 0;
            }
            for (int a7 = 0; a7 < 2; a7++) {
                getUserConfig().setDialogsLoadOffset(a7, dialogsLoadOffsetId, dialogsLoadOffsetDate, a, dialogsLoadOffsetChatId2, dialogsLoadOffsetUserId, dialogsLoadOffsetAccess);
                getUserConfig().setTotalDialogsCount(a7, totalDialogsLoadCount2);
            }
            getUserConfig().draftsLoaded = false;
            getUserConfig().saveConfig(false);
            getMessagesController().completeDialogsReset(dialogsRes, messagesCount, seq, newPts, date, qts, new_dialogs_dict, new_dialogMessage, lastMessage);
            if (0 != 0) {
                cursor.dispose();
            }
            if (0 != 0) {
                state.dispose();
            }
        } catch (Exception e4) {
            e = e4;
            cursor2 = null;
            state2 = null;
            FileLog.e("resetDialogs ---> exception 2 ", e);
            if (cursor2 != null) {
                cursor2.dispose();
            }
            if (state2 != null) {
                state2.dispose();
            }
        } catch (Throwable th3) {
            th = th3;
            cursor2 = null;
            state2 = null;
            if (cursor2 != null) {
                cursor2.dispose();
            }
            if (state2 != null) {
                state2.dispose();
            }
            throw th;
        }
    }

    static /* synthetic */ int lambda$null$50(LongSparseArray oldPinnedDialogNums, Long o1, Long o2) {
        Integer val1 = (Integer) oldPinnedDialogNums.get(o1.longValue());
        Integer val2 = (Integer) oldPinnedDialogNums.get(o2.longValue());
        if (val1.intValue() < val2.intValue()) {
            return 1;
        }
        if (val1.intValue() > val2.intValue()) {
            return -1;
        }
        return 0;
    }

    public void putDialogPhotos(final int did, final TLRPC.photos_Photos photos) {
        if (photos == null || photos.photos.isEmpty()) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$LOxAXOe0cAsNe5rSkzJ_hoOPcp0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putDialogPhotos$52$MessagesStorage(did, photos);
            }
        });
    }

    public /* synthetic */ void lambda$putDialogPhotos$52$MessagesStorage(int did, TLRPC.photos_Photos photos) {
        NativeByteBuffer data = null;
        SQLitePreparedStatement state = null;
        try {
            try {
                this.database.executeFast("DELETE FROM user_photos WHERE uid = " + did).stepThis().dispose();
                state = this.database.executeFast("REPLACE INTO user_photos VALUES(?, ?, ?)");
                int N = photos.photos.size();
                for (int a = 0; a < N; a++) {
                    TLRPC.Photo photo = photos.photos.get(a);
                    if (!(photo instanceof TLRPC.TL_photoEmpty)) {
                        state.requery();
                        NativeByteBuffer data2 = new NativeByteBuffer(photo.getObjectSize());
                        photo.serializeToStream(data2);
                        state.bindInteger(1, did);
                        state.bindLong(2, photo.id);
                        state.bindByteBuffer(3, data2);
                        state.step();
                        data2.reuse();
                        data = null;
                    }
                }
                state.dispose();
                state = null;
                if (data != null) {
                    data.reuse();
                }
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("putDialogPhotos ---> exception ", e);
                if (data != null) {
                    data.reuse();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void emptyMessagesMedia(final ArrayList<Integer> mids) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$WU0HcsL3TXarVYKqlspB6-mmbW4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$emptyMessagesMedia$54$MessagesStorage(mids);
            }
        });
    }

    public /* synthetic */ void lambda$emptyMessagesMedia$54$MessagesStorage(ArrayList mids) {
        SQLiteCursor cursor = null;
        NativeByteBuffer data = null;
        SQLitePreparedStatement state = null;
        try {
            try {
                ArrayList<File> filesToDelete = new ArrayList<>();
                final ArrayList<TLRPC.Message> messages = new ArrayList<>();
                SQLiteCursor cursor2 = this.database.queryFinalized(String.format(Locale.US, "SELECT data, mid, date, uid FROM messages WHERE mid IN (%s)", TextUtils.join(",", mids)), new Object[0]);
                while (cursor2.next()) {
                    data = cursor2.byteBufferValue(0);
                    if (data != null) {
                        TLRPC.Message message = TLRPC.Message.TLdeserialize(data, data.readInt32(false), false);
                        message.readAttachPath(data, getUserConfig().clientUserId);
                        data.reuse();
                        data = null;
                        if (message.media != null) {
                            if (addFilesToDelete(message, filesToDelete, true)) {
                                if (message.media.document != null) {
                                    message.media.document = new TLRPC.TL_documentEmpty();
                                } else if (message.media.photo != null) {
                                    message.media.photo = new TLRPC.TL_photoEmpty();
                                }
                                message.media.flags &= -2;
                                message.id = cursor2.intValue(1);
                                message.date = cursor2.intValue(2);
                                message.dialog_id = cursor2.longValue(3);
                                messages.add(message);
                            }
                        }
                    }
                }
                cursor2.dispose();
                cursor = null;
                if (!messages.isEmpty()) {
                    SQLitePreparedStatement state2 = this.database.executeFast("REPLACE INTO messages VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?,?)");
                    for (int a = 0; a < messages.size(); a++) {
                        TLRPC.Message message2 = messages.get(a);
                        NativeByteBuffer data2 = new NativeByteBuffer(message2.getObjectSize());
                        message2.serializeToStream(data2);
                        state2.requery();
                        state2.bindLong(1, message2.id);
                        state2.bindLong(2, message2.dialog_id);
                        state2.bindInteger(3, MessageObject.getUnreadFlags(message2));
                        state2.bindInteger(4, message2.send_state);
                        state2.bindInteger(5, message2.date);
                        state2.bindByteBuffer(6, data2);
                        state2.bindInteger(7, (MessageObject.isOut(message2) || message2.from_scheduled) ? 1 : 0);
                        state2.bindInteger(8, message2.ttl);
                        if ((message2.flags & 1024) != 0) {
                            state2.bindInteger(9, message2.views);
                        } else {
                            state2.bindInteger(9, getMessageMediaType(message2));
                        }
                        state2.bindInteger(10, 0);
                        state2.bindInteger(11, message2.mentioned ? 1 : 0);
                        state2.step();
                        data2.reuse();
                        data = null;
                    }
                    state2.dispose();
                    state = null;
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$whtHoPnOTsO4I8bl3BFX7371B6U
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$null$53$MessagesStorage(messages);
                        }
                    });
                }
                getFileLoader().deleteFiles(filesToDelete, 0);
                if (data != null) {
                    data.reuse();
                }
                if (0 != 0) {
                    cursor.dispose();
                }
                if (state == null) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("emptyMessagesMedia ---> exception ", e);
                if (data != null) {
                    data.reuse();
                }
                if (cursor != null) {
                    cursor.dispose();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (cursor != null) {
                cursor.dispose();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public /* synthetic */ void lambda$null$53$MessagesStorage(ArrayList messages) {
        for (int a = 0; a < messages.size(); a++) {
            getNotificationCenter().postNotificationName(NotificationCenter.updateMessageMedia, messages.get(a));
        }
    }

    public void updateMessagePollResults(final long pollId, final TLRPC.TL_poll poll, final TLRPC.TL_pollResults results) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$fs0niV0EiZBUOMMxHMAOcByrWY8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateMessagePollResults$55$MessagesStorage(pollId, poll, results);
            }
        });
    }

    public /* synthetic */ void lambda$updateMessagePollResults$55$MessagesStorage(long pollId, TLRPC.TL_poll poll, TLRPC.TL_pollResults results) {
        SQLiteCursor cursor = null;
        NativeByteBuffer data = null;
        SQLitePreparedStatement state = null;
        try {
            try {
                int i = 1;
                SQLiteCursor cursor2 = this.database.queryFinalized(String.format(Locale.US, "SELECT mid FROM polls WHERE id = %d", Long.valueOf(pollId)), new Object[0]);
                ArrayList<Long> mids = null;
                while (cursor2.next()) {
                    if (mids == null) {
                        mids = new ArrayList<>();
                    }
                    mids.add(Long.valueOf(cursor2.longValue(0)));
                }
                cursor2.dispose();
                cursor = null;
                if (mids != null) {
                    try {
                        this.database.beginTransaction();
                    } catch (Exception e) {
                        FileLog.e("updateMessagePollResults ---> exception 1 ", e);
                    }
                    int a = 0;
                    int N = mids.size();
                    while (a < N) {
                        Long mid = mids.get(a);
                        SQLiteDatabase sQLiteDatabase = this.database;
                        Locale locale = Locale.US;
                        Object[] objArr = new Object[i];
                        objArr[0] = mid;
                        SQLiteCursor cursor3 = sQLiteDatabase.queryFinalized(String.format(locale, "SELECT data FROM messages WHERE mid = %d", objArr), new Object[0]);
                        if (cursor3.next()) {
                            data = cursor3.byteBufferValue(0);
                            if (data != null) {
                                TLRPC.Message message = TLRPC.Message.TLdeserialize(data, data.readInt32(false), false);
                                message.readAttachPath(data, getUserConfig().clientUserId);
                                data.reuse();
                                data = null;
                                if (message.media instanceof TLRPC.TL_messageMediaPoll) {
                                    TLRPC.TL_messageMediaPoll media = (TLRPC.TL_messageMediaPoll) message.media;
                                    if (poll != null) {
                                        media.poll = poll;
                                    }
                                    if (results != null) {
                                        MessageObject.updatePollResults(media, results);
                                    }
                                    SQLitePreparedStatement state2 = this.database.executeFast("UPDATE messages SET data = ? WHERE mid = ?");
                                    NativeByteBuffer data2 = new NativeByteBuffer(message.getObjectSize());
                                    message.serializeToStream(data2);
                                    state2.requery();
                                    state2.bindByteBuffer(i, data2);
                                    state2.bindLong(2, mid.longValue());
                                    state2.step();
                                    data2.reuse();
                                    data = null;
                                    state2.dispose();
                                    state = null;
                                }
                            }
                        } else {
                            this.database.executeFast(String.format(Locale.US, "DELETE FROM polls WHERE mid = %d", mid)).stepThis().dispose();
                            state = null;
                        }
                        cursor3.dispose();
                        cursor = null;
                        a++;
                        i = 1;
                    }
                    this.database.commitTransaction();
                }
                if (data != null) {
                    data.reuse();
                }
                if (cursor != null) {
                    cursor.dispose();
                }
                if (state == null) {
                    return;
                }
            } catch (Exception e2) {
                FileLog.e("updateMessagePollResults ---> exception 2 ", e2);
                if (data != null) {
                    data.reuse();
                }
                if (cursor != null) {
                    cursor.dispose();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (cursor != null) {
                cursor.dispose();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void updateMessageReactions(long dialogId, final int msgId, final int channelId, final TLRPC.TL_messageReactions reactions) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$p5pYYQfcv5Z-Ol6wIICGN84U-3s
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateMessageReactions$56$MessagesStorage(msgId, channelId, reactions);
            }
        });
    }

    public /* synthetic */ void lambda$updateMessageReactions$56$MessagesStorage(int msgId, int channelId, TLRPC.TL_messageReactions reactions) {
        SQLiteCursor cursor = null;
        NativeByteBuffer data = null;
        SQLitePreparedStatement state = null;
        try {
            try {
                this.database.beginTransaction();
            } catch (Exception e) {
                try {
                    FileLog.e("updateMessageReactions ---> exception 1 ", e);
                } catch (Exception e2) {
                    FileLog.e("updateMessageReactions ---> exception 2 ", e2);
                    if (data != null) {
                        data.reuse();
                    }
                    if (cursor != null) {
                        cursor.dispose();
                    }
                    if (state == null) {
                        return;
                    }
                }
            }
            long mid = msgId;
            if (channelId != 0) {
                mid |= ((long) channelId) << 32;
            }
            SQLiteCursor cursor2 = this.database.queryFinalized(String.format(Locale.US, "SELECT data FROM messages WHERE mid = %d", Long.valueOf(mid)), new Object[0]);
            if (cursor2.next() && (data = cursor2.byteBufferValue(0)) != null) {
                TLRPC.Message message = TLRPC.Message.TLdeserialize(data, data.readInt32(false), false);
                message.readAttachPath(data, getUserConfig().clientUserId);
                data.reuse();
                if (message != null) {
                    MessageObject.updateReactions(message, reactions);
                    SQLitePreparedStatement state2 = this.database.executeFast("UPDATE messages SET data = ? WHERE mid = ?");
                    NativeByteBuffer data2 = new NativeByteBuffer(message.getObjectSize());
                    message.serializeToStream(data2);
                    state2.requery();
                    state2.bindByteBuffer(1, data2);
                    state2.bindLong(2, mid);
                    state2.step();
                    data2.reuse();
                    data = null;
                    state2.dispose();
                    state = null;
                }
            }
            cursor2.dispose();
            cursor = null;
            this.database.commitTransaction();
            if (data != null) {
                data.reuse();
            }
            if (0 != 0) {
                cursor.dispose();
            }
            if (state == null) {
                return;
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (cursor != null) {
                cursor.dispose();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void getNewTask(final ArrayList<Integer> oldTask, int channelId) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$kdiGffuWsRs2db0ngW8TGIdC9Z4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getNewTask$57$MessagesStorage(oldTask);
            }
        });
    }

    public /* synthetic */ void lambda$getNewTask$57$MessagesStorage(ArrayList oldTask) {
        SQLiteCursor cursor = null;
        SQLitePreparedStatement state = null;
        if (oldTask != null) {
            try {
                try {
                    String ids = TextUtils.join(",", oldTask);
                    this.database.executeFast(String.format(Locale.US, "DELETE FROM enc_tasks_v2 WHERE mid IN(%s)", ids)).stepThis().dispose();
                    state = null;
                } catch (Exception e) {
                    FileLog.e("getNewTask ---> exception ", e);
                    if (cursor != null) {
                        cursor.dispose();
                    }
                    if (state == null) {
                        return;
                    }
                }
            } catch (Throwable th) {
                if (cursor != null) {
                    cursor.dispose();
                }
                if (state != null) {
                    state.dispose();
                }
                throw th;
            }
        }
        int date = 0;
        int channelId1 = -1;
        ArrayList<Integer> arr = null;
        SQLiteCursor cursor2 = this.database.queryFinalized("SELECT mid, date FROM enc_tasks_v2 WHERE date = (SELECT min(date) FROM enc_tasks_v2)", new Object[0]);
        while (cursor2.next()) {
            long mid = cursor2.longValue(0);
            if (channelId1 == -1 && (channelId1 = (int) (mid >> 32)) < 0) {
                channelId1 = 0;
            }
            date = cursor2.intValue(1);
            if (arr == null) {
                arr = new ArrayList<>();
            }
            arr.add(Integer.valueOf((int) mid));
        }
        cursor2.dispose();
        cursor = null;
        getMessagesController().processLoadedDeleteTask(date, arr, channelId1);
        if (0 != 0) {
            cursor.dispose();
        }
        if (state == null) {
            return;
        }
        state.dispose();
    }

    public void markMentionMessageAsRead(final int messageId, final int channelId, final long did) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$5_TqdNq9ddkFmGxnegfPlch7C4w
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$markMentionMessageAsRead$58$MessagesStorage(messageId, channelId, did);
            }
        });
    }

    public /* synthetic */ void lambda$markMentionMessageAsRead$58$MessagesStorage(int messageId, int channelId, long did) {
        SQLiteCursor cursor = null;
        SQLitePreparedStatement state = null;
        long mid = messageId;
        if (channelId != 0) {
            mid |= ((long) channelId) << 32;
        }
        try {
            try {
                this.database.executeFast(String.format(Locale.US, "UPDATE messages SET read_state = read_state | 2 WHERE mid = %d", Long.valueOf(mid))).stepThis().dispose();
                SQLiteCursor cursor2 = this.database.queryFinalized("SELECT unread_count_i FROM dialogs WHERE did = " + did, new Object[0]);
                int old_mentions_count = cursor2.next() ? Math.max(0, cursor2.intValue(0) - 1) : 0;
                cursor2.dispose();
                cursor = null;
                this.database.executeFast(String.format(Locale.US, "UPDATE dialogs SET unread_count_i = %d WHERE did = %d", Integer.valueOf(old_mentions_count), Long.valueOf(did))).stepThis().dispose();
                state = null;
                LongSparseArray<Integer> sparseArray = new LongSparseArray<>(1);
                sparseArray.put(did, Integer.valueOf(old_mentions_count));
                getMessagesController().processDialogsUpdateRead(null, sparseArray);
                if (0 != 0) {
                    cursor.dispose();
                }
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("markMentionMessageAsRead ---> exception ", e);
                if (cursor != null) {
                    cursor.dispose();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (cursor != null) {
                cursor.dispose();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void markMessageAsMention(final long mid) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$TeVyD3c5OpRd-I4-YJUT2gQSBgE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$markMessageAsMention$59$MessagesStorage(mid);
            }
        });
    }

    public /* synthetic */ void lambda$markMessageAsMention$59$MessagesStorage(long mid) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast(String.format(Locale.US, "UPDATE messages SET mention = 1, read_state = read_state & ~2 WHERE mid = %d", Long.valueOf(mid)));
                state.stepThis().dispose();
                state = null;
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("markMessageAsMention ---> exception ", e);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void resetMentionsCount(final long did, final int count) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$fviNZ6Oo0DwcpfA8uOVLZbITdn4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$resetMentionsCount$60$MessagesStorage(count, did);
            }
        });
    }

    public /* synthetic */ void lambda$resetMentionsCount$60$MessagesStorage(int count, long did) {
        SQLitePreparedStatement state = null;
        try {
            if (count == 0) {
                try {
                    this.database.executeFast(String.format(Locale.US, "UPDATE messages SET read_state = read_state | 2 WHERE uid = %d AND mention = 1 AND read_state IN(0, 1)", Long.valueOf(did))).stepThis().dispose();
                } catch (Exception e) {
                    FileLog.e("resetMentionsCount ---> exception ", e);
                    if (state == null) {
                        return;
                    }
                }
            }
            this.database.executeFast(String.format(Locale.US, "UPDATE dialogs SET unread_count_i = %d WHERE did = %d", Integer.valueOf(count), Long.valueOf(did))).stepThis().dispose();
            state = null;
            LongSparseArray<Integer> sparseArray = new LongSparseArray<>(1);
            sparseArray.put(did, Integer.valueOf(count));
            getMessagesController().processDialogsUpdateRead(null, sparseArray);
            if (0 == 0) {
                return;
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void createTaskForMid(final int messageId, final int channelId, final int time, final int readTime, final int ttl, final boolean inner) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$xB68mooXiG18tPOBRkz0ihvwDOc
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$createTaskForMid$62$MessagesStorage(time, readTime, ttl, messageId, channelId, inner);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:42:0x00d5  */
    /* JADX WARN: Removed duplicated region for block: B:53:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$createTaskForMid$62$MessagesStorage(int r18, int r19, int r20, int r21, int r22, final boolean r23) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 217
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$createTaskForMid$62$MessagesStorage(int, int, int, int, int, boolean):void");
    }

    public /* synthetic */ void lambda$null$61$MessagesStorage(boolean inner, ArrayList midsArray) {
        if (!inner) {
            markMessagesContentAsRead(midsArray, 0);
        }
        getNotificationCenter().postNotificationName(NotificationCenter.messagesReadContent, midsArray);
    }

    public void createTaskForSecretChat(final int chatId, final int time, final int readTime, final int isOut, final ArrayList<Long> random_ids) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$xI6zLra6r6whoSeeF0OLlrqOQtE
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$createTaskForSecretChat$64$MessagesStorage(random_ids, chatId, isOut, time, readTime);
            }
        });
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:75:0x01a4  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x01a9  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x01b1  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x01b6  */
    /* JADX WARN: Type inference failed for: r3v13 */
    /* JADX WARN: Type inference failed for: r3v16 */
    /* JADX WARN: Type inference failed for: r3v21 */
    /* JADX WARN: Type inference failed for: r3v8, types: [int] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$createTaskForSecretChat$64$MessagesStorage(java.util.ArrayList r20, int r21, int r22, int r23, int r24) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 442
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$createTaskForSecretChat$64$MessagesStorage(java.util.ArrayList, int, int, int, int):void");
    }

    public /* synthetic */ void lambda$null$63$MessagesStorage(ArrayList midsArray) {
        markMessagesContentAsRead(midsArray, 0);
        getNotificationCenter().postNotificationName(NotificationCenter.messagesReadContent, midsArray);
    }

    private void updateDialogsWithReadMessagesInternal(ArrayList<Integer> messages, SparseLongArray inbox, SparseLongArray outbox, ArrayList<Long> mentions) throws Throwable {
        SQLitePreparedStatement state;
        SQLiteCursor cursor;
        SparseLongArray sparseLongArray = inbox;
        LongSparseArray<Integer> dialogsToUpdate = new LongSparseArray<>();
        LongSparseArray<Integer> dialogsToUpdateMentions = new LongSparseArray<>();
        ArrayList<Integer> channelMentionsToReload = new ArrayList<>();
        int i = 0;
        if (isEmpty(messages)) {
            if (!isEmpty(inbox)) {
                int b = 0;
                while (b < inbox.size()) {
                    int key = sparseLongArray.keyAt(b);
                    long messageId = sparseLongArray.get(key);
                    SQLiteCursor cursor2 = null;
                    try {
                        try {
                            cursor = this.database.queryFinalized(String.format(Locale.US, "SELECT COUNT(mid) FROM messages WHERE uid = %d AND mid > %d AND read_state IN(0,2) AND out = 0", Integer.valueOf(key), Long.valueOf(messageId)), new Object[0]);
                        } catch (Exception e) {
                            e = e;
                        }
                    } catch (Throwable th) {
                        th = th;
                    }
                    try {
                        if (cursor.next()) {
                            dialogsToUpdate.put(key, Integer.valueOf(cursor.intValue(0)));
                        }
                        cursor.dispose();
                        SQLiteCursor cursor3 = null;
                        if (0 != 0) {
                            cursor3.dispose();
                        }
                    } catch (Exception e2) {
                        e = e2;
                        cursor2 = cursor;
                        FileLog.e("updateDialogsWithReadMessagesInternal ---> exception 2 ", e);
                        if (cursor2 != null) {
                            cursor2.dispose();
                        }
                    } catch (Throwable th2) {
                        th = th2;
                        cursor2 = cursor;
                        if (cursor2 != null) {
                            cursor2.dispose();
                        }
                        throw th;
                    }
                    SQLitePreparedStatement state2 = null;
                    try {
                        try {
                            state2 = this.database.executeFast("UPDATE dialogs SET inbox_max = max((SELECT inbox_max FROM dialogs WHERE did = ?), ?) WHERE did = ?");
                            state2.requery();
                            state2.bindLong(1, key);
                            state2.bindInteger(2, (int) messageId);
                            state2.bindLong(3, key);
                            state2.step();
                            state2.dispose();
                            SQLitePreparedStatement state3 = null;
                            if (0 != 0) {
                                state3.dispose();
                            }
                        } catch (Exception e3) {
                            FileLog.e("updateDialogsWithReadMessagesInternal ---> exception 3 ", e3);
                            if (state2 != null) {
                                state2.dispose();
                            }
                        }
                        b++;
                        sparseLongArray = inbox;
                    } catch (Throwable th3) {
                        if (state2 != null) {
                            state2.dispose();
                        }
                        throw th3;
                    }
                }
            }
            if (!isEmpty(mentions)) {
                ArrayList<Long> notFoundMentions = new ArrayList<>(mentions);
                String ids = TextUtils.join(",", mentions);
                SQLiteCursor cursor4 = null;
                try {
                    try {
                        cursor4 = this.database.queryFinalized(String.format(Locale.US, "SELECT uid, read_state, out, mention, mid FROM messages WHERE mid IN(%s)", ids), new Object[0]);
                        while (cursor4.next()) {
                            long did = cursor4.longValue(0);
                            notFoundMentions.remove(Long.valueOf(cursor4.longValue(4)));
                            if (cursor4.intValue(1) < 2 && cursor4.intValue(2) == 0 && cursor4.intValue(3) == 1) {
                                Integer unread_count = dialogsToUpdateMentions.get(did);
                                if (unread_count == null) {
                                    SQLiteCursor cursor22 = this.database.queryFinalized("SELECT unread_count_i FROM dialogs WHERE did = " + did, new Object[0]);
                                    int old_mentions_count = cursor22.next() ? cursor22.intValue(0) : 0;
                                    cursor22.dispose();
                                    dialogsToUpdateMentions.put(did, Integer.valueOf(Math.max(0, old_mentions_count - 1)));
                                } else {
                                    dialogsToUpdateMentions.put(did, Integer.valueOf(Math.max(0, unread_count.intValue() - 1)));
                                }
                            }
                        }
                        cursor4.dispose();
                        SQLiteCursor cursor5 = null;
                        if (0 != 0) {
                            cursor5.dispose();
                        }
                    } catch (Exception e4) {
                        FileLog.e("updateDialogsWithReadMessagesInternal ---> exception 4 ", e4);
                        if (cursor4 != null) {
                            cursor4.dispose();
                        }
                    }
                    for (int a = 0; a < notFoundMentions.size(); a++) {
                        int channelId = (int) (notFoundMentions.get(a).longValue() >> 32);
                        if (channelId > 0 && !channelMentionsToReload.contains(Integer.valueOf(channelId))) {
                            channelMentionsToReload.add(Integer.valueOf(channelId));
                        }
                    }
                } catch (Throwable th4) {
                    if (cursor4 != null) {
                        cursor4.dispose();
                    }
                    throw th4;
                }
            }
            if (!isEmpty(outbox)) {
                for (int b2 = 0; b2 < outbox.size(); b2++) {
                    int key2 = outbox.keyAt(b2);
                    long messageId2 = outbox.get(key2);
                    state = null;
                    try {
                        try {
                            state = this.database.executeFast("UPDATE dialogs SET outbox_max = max((SELECT outbox_max FROM dialogs WHERE did = ?), ?) WHERE did = ?");
                            state.requery();
                            state.bindLong(1, key2);
                            state.bindInteger(2, (int) messageId2);
                        } catch (Exception e5) {
                            e = e5;
                        }
                        try {
                            state.bindLong(3, key2);
                            state.step();
                            state.dispose();
                            SQLitePreparedStatement state4 = null;
                            if (0 != 0) {
                                state4.dispose();
                            }
                        } catch (Exception e6) {
                            e = e6;
                            FileLog.e("updateDialogsWithReadMessagesInternal ---> exception 5 ", e);
                            if (state != null) {
                                state.dispose();
                            }
                        }
                    } finally {
                        if (state != null) {
                            state.dispose();
                        }
                    }
                }
            }
        } else {
            String ids2 = TextUtils.join(",", messages);
            SQLiteCursor cursor6 = null;
            try {
                try {
                    cursor6 = this.database.queryFinalized(String.format(Locale.US, "SELECT uid, read_state, out FROM messages WHERE mid IN(%s)", ids2), new Object[0]);
                    while (cursor6.next()) {
                        int out = cursor6.intValue(2);
                        if (out == 0) {
                            int read_state = cursor6.intValue(1);
                            if (read_state == 0) {
                                long uid = cursor6.longValue(i);
                                Integer currentCount = dialogsToUpdate.get(uid);
                                if (currentCount == null) {
                                    dialogsToUpdate.put(uid, 1);
                                } else {
                                    dialogsToUpdate.put(uid, Integer.valueOf(currentCount.intValue() + 1));
                                }
                                i = 0;
                            }
                        }
                    }
                    cursor6.dispose();
                    SQLiteCursor cursor7 = null;
                    if (0 != 0) {
                        cursor7.dispose();
                    }
                } catch (Throwable th5) {
                    if (cursor6 != null) {
                        cursor6.dispose();
                    }
                    throw th5;
                }
            } catch (Exception e7) {
                FileLog.e("updateDialogsWithReadMessagesInternal ---> exception 1 ", e7);
                if (cursor6 != null) {
                    cursor6.dispose();
                }
            }
        }
        if (dialogsToUpdate.size() > 0 || dialogsToUpdateMentions.size() > 0) {
            try {
                this.database.beginTransaction();
            } catch (Exception e8) {
                FileLog.e("updateDialogsWithReadMessagesInternal ---> exception 6 ", e8);
            }
            if (dialogsToUpdate.size() > 0) {
                SQLitePreparedStatement state5 = null;
                try {
                    try {
                        state5 = this.database.executeFast("UPDATE dialogs SET unread_count = ? WHERE did = ?");
                        for (int a2 = 0; a2 < dialogsToUpdate.size(); a2++) {
                            state5.requery();
                            state5.bindInteger(1, dialogsToUpdate.valueAt(a2).intValue());
                            state5.bindLong(2, dialogsToUpdate.keyAt(a2));
                            state5.step();
                        }
                        state5.dispose();
                        SQLitePreparedStatement state6 = null;
                        if (0 != 0) {
                            state6.dispose();
                        }
                    } catch (Exception e9) {
                        FileLog.e("updateDialogsWithReadMessagesInternal ---> exception 7 ", e9);
                        if (state5 != null) {
                            state5.dispose();
                        }
                    }
                } catch (Throwable th6) {
                    if (state5 != null) {
                        state5.dispose();
                    }
                    throw th6;
                }
            }
            if (dialogsToUpdateMentions.size() > 0) {
                SQLitePreparedStatement state7 = null;
                try {
                    try {
                        state7 = this.database.executeFast("UPDATE dialogs SET unread_count_i = ? WHERE did = ?");
                        for (int a3 = 0; a3 < dialogsToUpdateMentions.size(); a3++) {
                            state7.requery();
                            state7.bindInteger(1, dialogsToUpdateMentions.valueAt(a3).intValue());
                            state7.bindLong(2, dialogsToUpdateMentions.keyAt(a3));
                            state7.step();
                        }
                        state7.dispose();
                        state = null;
                    } catch (Exception e10) {
                        FileLog.e("updateDialogsWithReadMessagesInternal ---> exception 8 ", e10);
                        if (state7 != null) {
                            state7.dispose();
                        }
                    }
                } catch (Throwable th7) {
                    if (state7 != null) {
                        state7.dispose();
                    }
                    throw th7;
                }
            }
            this.database.commitTransaction();
        }
        getMessagesController().processDialogsUpdateRead(dialogsToUpdate, dialogsToUpdateMentions);
        if (channelMentionsToReload.isEmpty()) {
            return;
        }
        getMessagesController().reloadMentionsCountForChannels(channelMentionsToReload);
    }

    private static boolean isEmpty(SparseArray<?> array) {
        return array == null || array.size() == 0;
    }

    private static boolean isEmpty(SparseLongArray array) {
        return array == null || array.size() == 0;
    }

    private static boolean isEmpty(List<?> array) {
        return array == null || array.isEmpty();
    }

    private static boolean isEmpty(SparseIntArray array) {
        return array == null || array.size() == 0;
    }

    private static boolean isEmpty(LongSparseArray<?> array) {
        return array == null || array.size() == 0;
    }

    public void updateDialogsWithReadMessages(final SparseLongArray inbox, final SparseLongArray outbox, final ArrayList<Long> mentions, boolean useQueue) {
        if (isEmpty(inbox) && isEmpty(mentions)) {
            return;
        }
        if (useQueue) {
            this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$jGoBS2NzXnaYzez1N5DBRUNu1AI
                @Override // java.lang.Runnable
                public final void run() throws Throwable {
                    this.f$0.lambda$updateDialogsWithReadMessages$65$MessagesStorage(inbox, outbox, mentions);
                }
            });
        } else {
            updateDialogsWithReadMessagesInternal(null, inbox, outbox, mentions);
        }
    }

    public /* synthetic */ void lambda$updateDialogsWithReadMessages$65$MessagesStorage(SparseLongArray inbox, SparseLongArray outbox, ArrayList mentions) throws Throwable {
        updateDialogsWithReadMessagesInternal(null, inbox, outbox, mentions);
    }

    public void updateChatParticipants(final TLRPC.ChatParticipants participants) {
        if (participants == null) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$aRXIuN46gj-Xusmt5n14GMGd-5Y
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateChatParticipants$67$MessagesStorage(participants);
            }
        });
    }

    public /* synthetic */ void lambda$updateChatParticipants$67$MessagesStorage(TLRPC.ChatParticipants participants) {
        SQLiteCursor cursor = null;
        NativeByteBuffer data = null;
        SQLitePreparedStatement state = null;
        try {
            try {
                SQLiteCursor cursor2 = this.database.queryFinalized("SELECT info, pinned, online FROM chat_settings_v2 WHERE uid = " + participants.chat_id, new Object[0]);
                TLRPC.ChatFull info = null;
                new ArrayList();
                if (cursor2.next() && (data = cursor2.byteBufferValue(0)) != null) {
                    info = TLRPC.ChatFull.TLdeserialize(data, data.readInt32(false), false);
                    data.reuse();
                    data = null;
                    info.pinned_msg_id = cursor2.intValue(1);
                    info.online_count = cursor2.intValue(2);
                }
                cursor2.dispose();
                cursor = null;
                if (info instanceof TLRPC.TL_chatFull) {
                    info.participants = participants;
                    final TLRPC.ChatFull finalInfo = info;
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$3-xuy8HBKI9TM2aIq0GZBKwLEB8
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$null$66$MessagesStorage(finalInfo);
                        }
                    });
                    SQLitePreparedStatement state2 = this.database.executeFast("REPLACE INTO chat_settings_v2 VALUES(?, ?, ?, ?)");
                    data = new NativeByteBuffer(info.getObjectSize());
                    info.serializeToStream(data);
                    state2.bindInteger(1, info.id);
                    state2.bindByteBuffer(2, data);
                    state2.bindInteger(3, info.pinned_msg_id);
                    state2.bindInteger(4, info.online_count);
                    state2.step();
                    state2.dispose();
                    state = null;
                    data.reuse();
                    data = null;
                }
                if (data != null) {
                    data.reuse();
                }
                if (0 != 0) {
                    cursor.dispose();
                }
                if (state == null) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("updateChatParticipants ---> exception ", e);
                if (data != null) {
                    data.reuse();
                }
                if (cursor != null) {
                    cursor.dispose();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (cursor != null) {
                cursor.dispose();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public /* synthetic */ void lambda$null$66$MessagesStorage(TLRPC.ChatFull finalInfo) {
        getNotificationCenter().postNotificationName(NotificationCenter.chatInfoDidLoad, finalInfo, 0, false, null);
    }

    public void loadChannelAdmins(final int chatId) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$r_qLlXfickTnEiKL9CGxPDCBXwI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$loadChannelAdmins$68$MessagesStorage(chatId);
            }
        });
    }

    public /* synthetic */ void lambda$loadChannelAdmins$68$MessagesStorage(int chatId) {
        SQLiteCursor cursor = null;
        try {
            try {
                SQLiteCursor cursor2 = this.database.queryFinalized("SELECT uid, rank FROM channel_admins_v2 WHERE did = " + chatId, new Object[0]);
                SparseArray<String> ids = new SparseArray<>();
                while (cursor2.next()) {
                    ids.put(cursor2.intValue(0), cursor2.stringValue(1));
                }
                cursor2.dispose();
                cursor = null;
                getMessagesController().processLoadedChannelAdmins(ids, chatId, true);
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("loadChannelAdmins ---> exception ", e);
                if (cursor == null) {
                    return;
                }
            }
            cursor.dispose();
        } catch (Throwable th) {
            if (cursor != null) {
                cursor.dispose();
            }
            throw th;
        }
    }

    public void putChannelAdmins(final int chatId, final SparseArray<String> ids) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$k8zqorFN988l9TGVtUvfOTCphrI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putChannelAdmins$69$MessagesStorage(chatId, ids);
            }
        });
    }

    public /* synthetic */ void lambda$putChannelAdmins$69$MessagesStorage(int chatId, SparseArray ids) {
        SQLitePreparedStatement state = null;
        try {
            try {
                this.database.executeFast("DELETE FROM channel_admins_v2 WHERE did = " + chatId).stepThis().dispose();
                try {
                    this.database.beginTransaction();
                } catch (Exception e) {
                    FileLog.e("putChannelAdmins ---> exception 1 ", e);
                }
                SQLitePreparedStatement state2 = this.database.executeFast("REPLACE INTO channel_admins_v2 VALUES(?, ?, ?)");
                for (int a = 0; a < ids.size(); a++) {
                    state2.requery();
                    state2.bindInteger(1, chatId);
                    state2.bindInteger(2, ids.keyAt(a));
                    state2.bindString(3, (String) ids.valueAt(a));
                    state2.step();
                }
                state2.dispose();
                state = null;
                this.database.commitTransaction();
                if (0 == 0) {
                    return;
                }
            } catch (Throwable th) {
                if (state != null) {
                    state.dispose();
                }
                throw th;
            }
        } catch (Exception e2) {
            FileLog.e("putChannelAdmins ---> exception 2 ", e2);
            if (state == null) {
                return;
            }
        }
        state.dispose();
    }

    public void updateChannelUsers(final int channel_id, final ArrayList<TLRPC.ChannelParticipant> participants) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$gYRwN394BJhu6Ajp9FNCzBkisHY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateChannelUsers$70$MessagesStorage(channel_id, participants);
            }
        });
    }

    public /* synthetic */ void lambda$updateChannelUsers$70$MessagesStorage(int channel_id, ArrayList participants) {
        NativeByteBuffer data = null;
        SQLitePreparedStatement state = null;
        long did = -channel_id;
        try {
            try {
                this.database.executeFast("DELETE FROM channel_users_v2 WHERE did = " + did).stepThis().dispose();
                try {
                    this.database.beginTransaction();
                } catch (Exception e) {
                    FileLog.e("updateChannelUsers ---> exception 1 ", e);
                }
                SQLitePreparedStatement state2 = this.database.executeFast("REPLACE INTO channel_users_v2 VALUES(?, ?, ?, ?)");
                int date = (int) (System.currentTimeMillis() / 1000);
                for (int a = 0; a < participants.size(); a++) {
                    TLRPC.ChannelParticipant participant = (TLRPC.ChannelParticipant) participants.get(a);
                    state2.requery();
                    state2.bindLong(1, did);
                    state2.bindInteger(2, participant.user_id);
                    state2.bindInteger(3, date);
                    NativeByteBuffer data2 = new NativeByteBuffer(participant.getObjectSize());
                    participant.serializeToStream(data2);
                    state2.bindByteBuffer(4, data2);
                    data2.reuse();
                    data = null;
                    state2.step();
                    date--;
                }
                state2.dispose();
                state = null;
                this.database.commitTransaction();
                loadChatInfo(channel_id, null, false, true);
                if (data != null) {
                    data.reuse();
                }
                if (0 == 0) {
                    return;
                }
            } catch (Exception e2) {
                FileLog.e("updateChannelUsers ---> exception 2 ", e2);
                if (data != null) {
                    data.reuse();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void saveBotCache(final String key, final TLObject result) {
        if (result == null || TextUtils.isEmpty(key)) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$HlWQ22T10vlduaZFTiKdN4GOLmM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$saveBotCache$71$MessagesStorage(result, key);
            }
        });
    }

    public /* synthetic */ void lambda$saveBotCache$71$MessagesStorage(TLObject result, String key) {
        NativeByteBuffer data = null;
        SQLitePreparedStatement state = null;
        try {
            try {
                int currentDate = getConnectionsManager().getCurrentTime();
                if (result instanceof TLRPC.TL_messages_botCallbackAnswer) {
                    currentDate += ((TLRPC.TL_messages_botCallbackAnswer) result).cache_time;
                } else if (result instanceof TLRPC.TL_messages_botResults) {
                    currentDate += ((TLRPC.TL_messages_botResults) result).cache_time;
                }
                SQLitePreparedStatement state2 = this.database.executeFast("REPLACE INTO botcache VALUES(?, ?, ?)");
                data = new NativeByteBuffer(result.getObjectSize());
                result.serializeToStream(data);
                state2.bindString(1, key);
                state2.bindInteger(2, currentDate);
                state2.bindByteBuffer(3, data);
                state2.step();
                state2.dispose();
                state = null;
                data.reuse();
                NativeByteBuffer data2 = null;
                if (0 != 0) {
                    data2.reuse();
                }
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("saveBotCache ---> exception ", e);
                if (data != null) {
                    data.reuse();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void getBotCache(final String key, final RequestDelegate requestDelegate) {
        if (key == null || requestDelegate == null) {
            return;
        }
        final int currentDate = getConnectionsManager().getCurrentTime();
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$2rHW29bSGRO3lhZqyKUmf-Xlxok
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getBotCache$72$MessagesStorage(currentDate, key, requestDelegate);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x0084 A[PHI: r0 r3
      0x0084: PHI (r0v3 'result' im.uwrkaxlmjj.tgnet.TLObject) = (r0v1 'result' im.uwrkaxlmjj.tgnet.TLObject), (r0v9 'result' im.uwrkaxlmjj.tgnet.TLObject) binds: [B:32:0x0082, B:22:0x006d] A[DONT_GENERATE, DONT_INLINE]
      0x0084: PHI (r3v3 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement) = 
      (r3v1 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement)
      (r3v5 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement)
     binds: [B:32:0x0082, B:22:0x006d] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$getBotCache$72$MessagesStorage(int r10, java.lang.String r11, im.uwrkaxlmjj.tgnet.RequestDelegate r12) {
        /*
            r9 = this;
            r0 = 0
            r1 = 0
            r2 = 0
            r3 = 0
            r4 = 0
            im.uwrkaxlmjj.sqlite.SQLiteDatabase r5 = r9.database     // Catch: java.lang.Throwable -> L70 java.lang.Exception -> L72
            java.lang.StringBuilder r6 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L70 java.lang.Exception -> L72
            r6.<init>()     // Catch: java.lang.Throwable -> L70 java.lang.Exception -> L72
            java.lang.String r7 = "DELETE FROM botcache WHERE date < "
            r6.append(r7)     // Catch: java.lang.Throwable -> L70 java.lang.Exception -> L72
            r6.append(r10)     // Catch: java.lang.Throwable -> L70 java.lang.Exception -> L72
            java.lang.String r6 = r6.toString()     // Catch: java.lang.Throwable -> L70 java.lang.Exception -> L72
            im.uwrkaxlmjj.sqlite.SQLitePreparedStatement r5 = r5.executeFast(r6)     // Catch: java.lang.Throwable -> L70 java.lang.Exception -> L72
            r3 = r5
            im.uwrkaxlmjj.sqlite.SQLitePreparedStatement r5 = r3.stepThis()     // Catch: java.lang.Throwable -> L70 java.lang.Exception -> L72
            r5.dispose()     // Catch: java.lang.Throwable -> L70 java.lang.Exception -> L72
            r3 = 0
            im.uwrkaxlmjj.sqlite.SQLiteDatabase r5 = r9.database     // Catch: java.lang.Throwable -> L70 java.lang.Exception -> L72
            java.lang.String r6 = "SELECT data FROM botcache WHERE id = ?"
            r7 = 1
            java.lang.Object[] r7 = new java.lang.Object[r7]     // Catch: java.lang.Throwable -> L70 java.lang.Exception -> L72
            r8 = 0
            r7[r8] = r11     // Catch: java.lang.Throwable -> L70 java.lang.Exception -> L72
            im.uwrkaxlmjj.sqlite.SQLiteCursor r5 = r5.queryFinalized(r6, r7)     // Catch: java.lang.Throwable -> L70 java.lang.Exception -> L72
            r1 = r5
            boolean r5 = r1.next()     // Catch: java.lang.Throwable -> L70 java.lang.Exception -> L72
            if (r5 == 0) goto L5f
            im.uwrkaxlmjj.tgnet.NativeByteBuffer r5 = r1.byteBufferValue(r8)     // Catch: java.lang.Exception -> L59 java.lang.Throwable -> L70
            r2 = r5
            if (r2 == 0) goto L58
            int r5 = r2.readInt32(r8)     // Catch: java.lang.Exception -> L59 java.lang.Throwable -> L70
            int r6 = im.uwrkaxlmjj.tgnet.TLRPC.TL_messages_botCallbackAnswer.constructor     // Catch: java.lang.Exception -> L59 java.lang.Throwable -> L70
            if (r5 != r6) goto L4f
            im.uwrkaxlmjj.tgnet.TLRPC$TL_messages_botCallbackAnswer r6 = im.uwrkaxlmjj.tgnet.TLRPC.TL_messages_botCallbackAnswer.TLdeserialize(r2, r5, r8)     // Catch: java.lang.Exception -> L59 java.lang.Throwable -> L70
            r0 = r6
            goto L54
        L4f:
            im.uwrkaxlmjj.tgnet.TLRPC$messages_BotResults r6 = im.uwrkaxlmjj.tgnet.TLRPC.messages_BotResults.TLdeserialize(r2, r5, r8)     // Catch: java.lang.Exception -> L59 java.lang.Throwable -> L70
            r0 = r6
        L54:
            r2.reuse()     // Catch: java.lang.Exception -> L59 java.lang.Throwable -> L70
            r2 = 0
        L58:
            goto L5f
        L59:
            r5 = move-exception
            java.lang.String r6 = "getBotCache ---> exception 1 "
            im.uwrkaxlmjj.messenger.FileLog.e(r6, r5)     // Catch: java.lang.Throwable -> L70 java.lang.Exception -> L72
        L5f:
            r1.dispose()     // Catch: java.lang.Throwable -> L70 java.lang.Exception -> L72
            r1 = 0
            if (r2 == 0) goto L68
            r2.reuse()
        L68:
            if (r1 == 0) goto L6d
            r1.dispose()
        L6d:
            if (r3 == 0) goto L87
            goto L84
        L70:
            r5 = move-exception
            goto L8c
        L72:
            r5 = move-exception
            java.lang.String r6 = "getBotCache ---> exception 2 "
            im.uwrkaxlmjj.messenger.FileLog.e(r6, r5)     // Catch: java.lang.Throwable -> L70
            if (r2 == 0) goto L7d
            r2.reuse()
        L7d:
            if (r1 == 0) goto L82
            r1.dispose()
        L82:
            if (r3 == 0) goto L87
        L84:
            r3.dispose()
        L87:
            r12.run(r0, r4)
            return
        L8c:
            if (r2 == 0) goto L91
            r2.reuse()
        L91:
            if (r1 == 0) goto L96
            r1.dispose()
        L96:
            if (r3 == 0) goto L9b
            r3.dispose()
        L9b:
            r12.run(r0, r4)
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$getBotCache$72$MessagesStorage(int, java.lang.String, im.uwrkaxlmjj.tgnet.RequestDelegate):void");
    }

    public void loadUserInfo(final TLRPC.User user, final boolean force, final int classGuid) {
        if (user == null) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$p6BZDFalEteaeYf_T2orjoaeiU0
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$loadUserInfo$73$MessagesStorage(user, force, classGuid);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x008c A[PHI: r9 r11 r13
      0x008c: PHI (r9v1 'pinnedMessageObject' im.uwrkaxlmjj.messenger.MessageObject) = 
      (r9v0 'pinnedMessageObject' im.uwrkaxlmjj.messenger.MessageObject)
      (r9v4 'pinnedMessageObject' im.uwrkaxlmjj.messenger.MessageObject)
     binds: [B:35:0x008a, B:22:0x006e] A[DONT_GENERATE, DONT_INLINE]
      0x008c: PHI (r11v4 'info' im.uwrkaxlmjj.tgnet.TLRPC$UserFull) = (r11v3 'info' im.uwrkaxlmjj.tgnet.TLRPC$UserFull), (r11v7 'info' im.uwrkaxlmjj.tgnet.TLRPC$UserFull) binds: [B:35:0x008a, B:22:0x006e] A[DONT_GENERATE, DONT_INLINE]
      0x008c: PHI (r13v4 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor) = (r13v3 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor), (r13v7 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor) binds: [B:35:0x008a, B:22:0x006e] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$loadUserInfo$73$MessagesStorage(im.uwrkaxlmjj.tgnet.TLRPC.User r15, boolean r16, int r17) throws java.lang.Throwable {
        /*
            r14 = this;
            r8 = r15
            r9 = 0
            r1 = 0
            r2 = 0
            r3 = 0
            r10 = r14
            im.uwrkaxlmjj.sqlite.SQLiteDatabase r0 = r10.database     // Catch: java.lang.Throwable -> L77 java.lang.Exception -> L7c
            java.lang.StringBuilder r4 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L77 java.lang.Exception -> L7c
            r4.<init>()     // Catch: java.lang.Throwable -> L77 java.lang.Exception -> L7c
            java.lang.String r5 = "SELECT info, pinned FROM user_settings WHERE uid = "
            r4.append(r5)     // Catch: java.lang.Throwable -> L77 java.lang.Exception -> L7c
            int r5 = r8.id     // Catch: java.lang.Throwable -> L77 java.lang.Exception -> L7c
            r4.append(r5)     // Catch: java.lang.Throwable -> L77 java.lang.Exception -> L7c
            java.lang.String r4 = r4.toString()     // Catch: java.lang.Throwable -> L77 java.lang.Exception -> L7c
            r5 = 0
            java.lang.Object[] r6 = new java.lang.Object[r5]     // Catch: java.lang.Throwable -> L77 java.lang.Exception -> L7c
            im.uwrkaxlmjj.sqlite.SQLiteCursor r0 = r0.queryFinalized(r4, r6)     // Catch: java.lang.Throwable -> L77 java.lang.Exception -> L7c
            r2 = r0
            boolean r0 = r2.next()     // Catch: java.lang.Throwable -> L77 java.lang.Exception -> L7c
            if (r0 == 0) goto L4a
            im.uwrkaxlmjj.tgnet.NativeByteBuffer r0 = r2.byteBufferValue(r5)     // Catch: java.lang.Throwable -> L77 java.lang.Exception -> L7c
            r3 = r0
            if (r3 == 0) goto L47
            int r0 = r3.readInt32(r5)     // Catch: java.lang.Throwable -> L77 java.lang.Exception -> L7c
            im.uwrkaxlmjj.tgnet.TLRPC$UserFull r0 = im.uwrkaxlmjj.tgnet.TLRPC.UserFull.TLdeserialize(r3, r0, r5)     // Catch: java.lang.Throwable -> L77 java.lang.Exception -> L7c
            r1 = r0
            r3.reuse()     // Catch: java.lang.Throwable -> L77 java.lang.Exception -> L7c
            r3 = 0
            r0 = 1
            int r0 = r2.intValue(r0)     // Catch: java.lang.Throwable -> L77 java.lang.Exception -> L7c
            r1.pinned_msg_id = r0     // Catch: java.lang.Throwable -> L77 java.lang.Exception -> L7c
            r11 = r1
            r12 = r3
            goto L4c
        L47:
            r11 = r1
            r12 = r3
            goto L4c
        L4a:
            r11 = r1
            r12 = r3
        L4c:
            r2.dispose()     // Catch: java.lang.Throwable -> L71 java.lang.Exception -> L74
            r13 = 0
            if (r11 == 0) goto L69
            int r0 = r11.pinned_msg_id     // Catch: java.lang.Exception -> L67 java.lang.Throwable -> La0
            if (r0 == 0) goto L69
            im.uwrkaxlmjj.messenger.MediaDataController r1 = r14.getMediaDataController()     // Catch: java.lang.Exception -> L67 java.lang.Throwable -> La0
            int r0 = r8.id     // Catch: java.lang.Exception -> L67 java.lang.Throwable -> La0
            long r2 = (long) r0     // Catch: java.lang.Exception -> L67 java.lang.Throwable -> La0
            r4 = 0
            int r5 = r11.pinned_msg_id     // Catch: java.lang.Exception -> L67 java.lang.Throwable -> La0
            r6 = 0
            im.uwrkaxlmjj.messenger.MessageObject r0 = r1.loadPinnedMessage(r2, r4, r5, r6)     // Catch: java.lang.Exception -> L67 java.lang.Throwable -> La0
            r9 = r0
            goto L69
        L67:
            r0 = move-exception
            goto L80
        L69:
            if (r12 == 0) goto L6e
            r12.reuse()
        L6e:
            if (r13 == 0) goto L8f
            goto L8c
        L71:
            r0 = move-exception
            r13 = r2
            goto La1
        L74:
            r0 = move-exception
            r13 = r2
            goto L80
        L77:
            r0 = move-exception
            r11 = r1
            r13 = r2
            r12 = r3
            goto La1
        L7c:
            r0 = move-exception
            r11 = r1
            r13 = r2
            r12 = r3
        L80:
            java.lang.String r1 = "loadUserInfo ---> exception "
            im.uwrkaxlmjj.messenger.FileLog.e(r1, r0)     // Catch: java.lang.Throwable -> La0
            if (r12 == 0) goto L8a
            r12.reuse()
        L8a:
            if (r13 == 0) goto L8f
        L8c:
            r13.dispose()
        L8f:
            im.uwrkaxlmjj.messenger.MessagesController r1 = r14.getMessagesController()
            r4 = 1
            r2 = r15
            r3 = r11
            r5 = r16
            r6 = r9
            r7 = r17
            r1.processUserInfo(r2, r3, r4, r5, r6, r7)
            return
        La0:
            r0 = move-exception
        La1:
            if (r12 == 0) goto La6
            r12.reuse()
        La6:
            if (r13 == 0) goto Lab
            r13.dispose()
        Lab:
            im.uwrkaxlmjj.messenger.MessagesController r1 = r14.getMessagesController()
            r4 = 1
            r2 = r15
            r3 = r11
            r5 = r16
            r6 = r9
            r7 = r17
            r1.processUserInfo(r2, r3, r4, r5, r6, r7)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$loadUserInfo$73$MessagesStorage(im.uwrkaxlmjj.tgnet.TLRPC$User, boolean, int):void");
    }

    public void updateUserInfo(final TLRPC.UserFull info, final boolean ifExist) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$hnQTPKec8jYVtZ01sAC7pi5-uzs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateUserInfo$74$MessagesStorage(ifExist, info);
            }
        });
    }

    public /* synthetic */ void lambda$updateUserInfo$74$MessagesStorage(boolean ifExist, TLRPC.UserFull info) {
        SQLiteCursor cursor = null;
        SQLitePreparedStatement state = null;
        NativeByteBuffer data = null;
        try {
            if (ifExist) {
                try {
                    SQLiteCursor cursor2 = this.database.queryFinalized("SELECT uid FROM user_settings WHERE uid = " + info.user.id, new Object[0]);
                    boolean exist = cursor2.next();
                    cursor2.dispose();
                    cursor = null;
                    if (!exist) {
                        if (0 != 0) {
                            data.reuse();
                        }
                        if (0 != 0) {
                            cursor.dispose();
                        }
                        if (0 != 0) {
                            state.dispose();
                            return;
                        }
                        return;
                    }
                } catch (Exception e) {
                    FileLog.e("updateUserInfo ---> exception ", e);
                    if (data != null) {
                        data.reuse();
                    }
                    if (cursor != null) {
                        cursor.dispose();
                    }
                    if (state == null) {
                        return;
                    }
                }
            }
            SQLitePreparedStatement state2 = this.database.executeFast("REPLACE INTO user_settings VALUES(?, ?, ?)");
            data = new NativeByteBuffer(info.getObjectSize());
            info.serializeToStream(data);
            state2.bindInteger(1, info.user.id);
            state2.bindByteBuffer(2, data);
            state2.bindInteger(3, info.pinned_msg_id);
            state2.step();
            state2.dispose();
            state = null;
            data.reuse();
            NativeByteBuffer data2 = null;
            if (0 != 0) {
                data2.reuse();
            }
            if (cursor != null) {
                cursor.dispose();
            }
            if (0 == 0) {
                return;
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (cursor != null) {
                cursor.dispose();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void updateChatInfo(final TLRPC.ChatFull info, final boolean ifExist) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$idWzv3hiRWGCfiIWf3FZyla5HFc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateChatInfo$75$MessagesStorage(info, ifExist);
            }
        });
    }

    public /* synthetic */ void lambda$updateChatInfo$75$MessagesStorage(TLRPC.ChatFull info, boolean ifExist) {
        SQLiteCursor cursor = null;
        SQLitePreparedStatement state = null;
        NativeByteBuffer data = null;
        try {
            try {
                SQLiteCursor cursor2 = this.database.queryFinalized("SELECT online FROM chat_settings_v2 WHERE uid = " + info.id, new Object[0]);
                int currentOnline = cursor2.next() ? cursor2.intValue(0) : -1;
                cursor2.dispose();
                SQLiteCursor cursor3 = null;
                if (ifExist && currentOnline == -1) {
                    if (0 != 0) {
                        data.reuse();
                    }
                    if (0 != 0) {
                        cursor3.dispose();
                    }
                    if (0 != 0) {
                        state.dispose();
                        return;
                    }
                    return;
                }
                if (currentOnline >= 0 && (info.flags & 8192) == 0) {
                    info.online_count = currentOnline;
                }
                SQLitePreparedStatement state2 = this.database.executeFast("REPLACE INTO chat_settings_v2 VALUES(?, ?, ?, ?)");
                NativeByteBuffer data2 = new NativeByteBuffer(info.getObjectSize());
                info.serializeToStream(data2);
                state2.bindInteger(1, info.id);
                state2.bindByteBuffer(2, data2);
                state2.bindInteger(3, info.pinned_msg_id);
                state2.bindInteger(4, info.online_count);
                state2.step();
                state2.dispose();
                state = null;
                data2.reuse();
                data = null;
                if (info instanceof TLRPC.TL_channelFull) {
                    cursor = this.database.queryFinalized("SELECT inbox_max, outbox_max FROM dialogs WHERE did = " + (-info.id), new Object[0]);
                    if (cursor.next()) {
                        int inbox_max = cursor.intValue(0);
                        if (inbox_max < info.read_inbox_max_id) {
                            int outbox_max = cursor.intValue(1);
                            SQLitePreparedStatement state3 = this.database.executeFast("UPDATE dialogs SET unread_count = ?, inbox_max = ?, outbox_max = ? WHERE did = ?");
                            state3.bindInteger(1, info.unread_count);
                            state3.bindInteger(2, info.read_inbox_max_id);
                            state3.bindInteger(3, Math.max(outbox_max, info.read_outbox_max_id));
                            state3.bindLong(4, -info.id);
                            state3.step();
                            state3.dispose();
                            state = null;
                        }
                    }
                    cursor.dispose();
                    cursor3 = null;
                }
                if (0 != 0) {
                    data.reuse();
                }
                if (cursor3 != null) {
                    cursor3.dispose();
                }
                if (state == null) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("updateChatInfo ---> exception ", e);
                if (data != null) {
                    data.reuse();
                }
                if (cursor != null) {
                    cursor.dispose();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (cursor != null) {
                cursor.dispose();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void updateUserPinnedMessage(final int userId, final int messageId) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$DqTMUC6ma8c5JOuQVShpkrCGKvw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateUserPinnedMessage$77$MessagesStorage(userId, messageId);
            }
        });
    }

    public /* synthetic */ void lambda$updateUserPinnedMessage$77$MessagesStorage(final int userId, int messageId) {
        SQLiteCursor cursor = null;
        SQLitePreparedStatement state = null;
        NativeByteBuffer data = null;
        try {
            try {
                SQLiteCursor cursor2 = this.database.queryFinalized("SELECT info, pinned FROM user_settings WHERE uid = " + userId, new Object[0]);
                TLRPC.UserFull info = null;
                if (cursor2.next() && (data = cursor2.byteBufferValue(0)) != null) {
                    info = TLRPC.UserFull.TLdeserialize(data, data.readInt32(false), false);
                    data.reuse();
                    data = null;
                    info.pinned_msg_id = cursor2.intValue(1);
                }
                cursor2.dispose();
                cursor = null;
                if (info instanceof TLRPC.UserFull) {
                    info.pinned_msg_id = messageId;
                    info.flags |= 64;
                    final TLRPC.UserFull finalInfo = info;
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$Ey5lP_C5w9Hd4ao5IBGgfi8H7Os
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$null$76$MessagesStorage(userId, finalInfo);
                        }
                    });
                    SQLitePreparedStatement state2 = this.database.executeFast("REPLACE INTO user_settings VALUES(?, ?, ?)");
                    data = new NativeByteBuffer(info.getObjectSize());
                    info.serializeToStream(data);
                    state2.bindInteger(1, userId);
                    state2.bindByteBuffer(2, data);
                    state2.bindInteger(3, info.pinned_msg_id);
                    state2.step();
                    state2.dispose();
                    state = null;
                    data.reuse();
                    data = null;
                }
                if (data != null) {
                    data.reuse();
                }
                if (0 != 0) {
                    cursor.dispose();
                }
                if (state == null) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("updateUserPinnedMessage ---> exception ", e);
                if (data != null) {
                    data.reuse();
                }
                if (cursor != null) {
                    cursor.dispose();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (cursor != null) {
                cursor.dispose();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public /* synthetic */ void lambda$null$76$MessagesStorage(int userId, TLRPC.UserFull finalInfo) {
        getNotificationCenter().postNotificationName(NotificationCenter.userFullInfoDidLoad, Integer.valueOf(userId), finalInfo, null);
    }

    public void updateChatOnlineCount(final int channelId, final int onlineCount) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$WEOinFupzYra55EsBgYh7NLMmss
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateChatOnlineCount$78$MessagesStorage(onlineCount, channelId);
            }
        });
    }

    public /* synthetic */ void lambda$updateChatOnlineCount$78$MessagesStorage(int onlineCount, int channelId) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast("UPDATE chat_settings_v2 SET online = ? WHERE uid = ?");
                state.requery();
                state.bindInteger(1, onlineCount);
                state.bindInteger(2, channelId);
                state.step();
                state.dispose();
                state = null;
            } catch (Exception e) {
                FileLog.e("updateChatOnlineCount ---> exception ", e);
                if (state != null) {
                }
            }
            if (0 != 0) {
                state.dispose();
            }
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void updateChatPinnedMessage(final int channelId, final int messageId) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$8HCsVf94ps9tJskPqS0VinIQbIw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateChatPinnedMessage$80$MessagesStorage(channelId, messageId);
            }
        });
    }

    public /* synthetic */ void lambda$updateChatPinnedMessage$80$MessagesStorage(int channelId, int messageId) {
        SQLiteCursor cursor = null;
        SQLitePreparedStatement state = null;
        NativeByteBuffer data = null;
        try {
            try {
                cursor = this.database.queryFinalized("SELECT info, pinned, online FROM chat_settings_v2 WHERE uid = " + channelId, new Object[0]);
                TLRPC.ChatFull info = null;
                if (cursor.next() && (data = cursor.byteBufferValue(0)) != null) {
                    info = TLRPC.ChatFull.TLdeserialize(data, data.readInt32(false), false);
                    data.reuse();
                    data = null;
                    info.pinned_msg_id = cursor.intValue(1);
                    info.online_count = cursor.intValue(2);
                }
                cursor.dispose();
                if (info != null) {
                    if (info instanceof TLRPC.TL_channelFull) {
                        info.pinned_msg_id = messageId;
                        info.flags |= 32;
                    } else if (info instanceof TLRPC.TL_chatFull) {
                        info.pinned_msg_id = messageId;
                        info.flags |= 64;
                    }
                    final TLRPC.ChatFull finalInfo = info;
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$YJeYOxTiSNX9UT7Wigq0l0nT0bs
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$null$79$MessagesStorage(finalInfo);
                        }
                    });
                    SQLitePreparedStatement state2 = this.database.executeFast("REPLACE INTO chat_settings_v2 VALUES(?, ?, ?, ?)");
                    data = new NativeByteBuffer(info.getObjectSize());
                    info.serializeToStream(data);
                    state2.bindInteger(1, channelId);
                    state2.bindByteBuffer(2, data);
                    state2.bindInteger(3, info.pinned_msg_id);
                    state2.bindInteger(4, info.online_count);
                    state2.step();
                    state2.dispose();
                    state = null;
                    data.reuse();
                    data = null;
                }
                if (data != null) {
                    data.reuse();
                }
                if (cursor != null) {
                    cursor.dispose();
                }
                if (state == null) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("updateChatPinnedMessage ---> exception ", e);
                if (data != null) {
                    data.reuse();
                }
                if (cursor != null) {
                    cursor.dispose();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (cursor != null) {
                cursor.dispose();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public /* synthetic */ void lambda$null$79$MessagesStorage(TLRPC.ChatFull finalInfo) {
        getNotificationCenter().postNotificationName(NotificationCenter.chatInfoDidLoad, finalInfo, 0, false, null);
    }

    public void updateChatInfo(final int chat_id, final int user_id, final int what, final int invited_id, final int version) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$1SZF3xqFnH9xUxSs9oxnTb5dz6M
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$updateChatInfo$82$MessagesStorage(chat_id, what, user_id, invited_id, version);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:72:0x018c  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0191  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x0196  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$updateChatInfo$82$MessagesStorage(int r17, int r18, int r19, int r20, int r21) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 410
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$updateChatInfo$82$MessagesStorage(int, int, int, int, int):void");
    }

    public /* synthetic */ void lambda$null$81$MessagesStorage(TLRPC.ChatFull finalInfo) {
        getNotificationCenter().postNotificationName(NotificationCenter.chatInfoDidLoad, finalInfo, 0, false, null);
    }

    public boolean isMigratedChat(final int chat_id) {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final boolean[] result = new boolean[1];
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$sYyHM53zrZtPMObTydqLne3fui4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$isMigratedChat$83$MessagesStorage(chat_id, result, countDownLatch);
            }
        });
        try {
            countDownLatch.await();
        } catch (Exception e) {
            FileLog.e("isMigratedChat ---> exception 3 ", e);
        }
        return result[0];
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0068 A[Catch: all -> 0x0076, Exception -> 0x0078, TRY_LEAVE, TryCatch #2 {Exception -> 0x0078, blocks: (B:3:0x0001, B:11:0x003f, B:20:0x0050, B:22:0x0054, B:23:0x0055, B:25:0x005d, B:29:0x0064, B:31:0x0068), top: B:51:0x0001, outer: #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:33:0x006d  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0086 A[ORIG_RETURN, RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$isMigratedChat$83$MessagesStorage(int r8, boolean[] r9, java.util.concurrent.CountDownLatch r10) {
        /*
            r7 = this;
            r0 = 0
            im.uwrkaxlmjj.sqlite.SQLiteDatabase r1 = r7.database     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
            java.lang.StringBuilder r2 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
            r2.<init>()     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
            java.lang.String r3 = "SELECT info FROM chat_settings_v2 WHERE uid = "
            r2.append(r3)     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
            r2.append(r8)     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
            java.lang.String r2 = r2.toString()     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
            r3 = 0
            java.lang.Object[] r4 = new java.lang.Object[r3]     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
            im.uwrkaxlmjj.sqlite.SQLiteCursor r1 = r1.queryFinalized(r2, r4)     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
            r0 = r1
            r1 = 0
            java.util.ArrayList r2 = new java.util.ArrayList     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
            r2.<init>()     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
            boolean r4 = r0.next()     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
            if (r4 == 0) goto L55
            r4 = 0
            im.uwrkaxlmjj.tgnet.NativeByteBuffer r5 = r0.byteBufferValue(r3)     // Catch: java.lang.Throwable -> L43 java.lang.Exception -> L45
            r4 = r5
            if (r4 == 0) goto L3d
            int r5 = r4.readInt32(r3)     // Catch: java.lang.Throwable -> L43 java.lang.Exception -> L45
            im.uwrkaxlmjj.tgnet.TLRPC$ChatFull r5 = im.uwrkaxlmjj.tgnet.TLRPC.ChatFull.TLdeserialize(r4, r5, r3)     // Catch: java.lang.Throwable -> L43 java.lang.Exception -> L45
            r1 = r5
            r4.reuse()     // Catch: java.lang.Throwable -> L43 java.lang.Exception -> L45
            r4 = 0
        L3d:
            if (r4 == 0) goto L55
        L3f:
            r4.reuse()     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
            goto L55
        L43:
            r3 = move-exception
            goto L4e
        L45:
            r5 = move-exception
            java.lang.String r6 = "isMigratedChat ---> exception 1 "
            im.uwrkaxlmjj.messenger.FileLog.e(r6, r5)     // Catch: java.lang.Throwable -> L43
            if (r4 == 0) goto L55
            goto L3f
        L4e:
            if (r4 == 0) goto L53
            r4.reuse()     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
        L53:
            throw r3     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
        L55:
            r0.dispose()     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
            r0 = 0
            boolean r4 = r1 instanceof im.uwrkaxlmjj.tgnet.TLRPC.TL_channelFull     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
            if (r4 == 0) goto L63
            int r4 = r1.migrated_from_chat_id     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
            if (r4 == 0) goto L63
            r4 = 1
            goto L64
        L63:
            r4 = 0
        L64:
            r9[r3] = r4     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
            if (r10 == 0) goto L6b
            r10.countDown()     // Catch: java.lang.Throwable -> L76 java.lang.Exception -> L78
        L6b:
            if (r0 == 0) goto L70
            r0.dispose()
        L70:
            if (r10 == 0) goto L86
        L72:
            r10.countDown()
            goto L86
        L76:
            r1 = move-exception
            goto L87
        L78:
            r1 = move-exception
            java.lang.String r2 = "isMigratedChat ---> exception 2 "
            im.uwrkaxlmjj.messenger.FileLog.e(r2, r1)     // Catch: java.lang.Throwable -> L76
            if (r0 == 0) goto L83
            r0.dispose()
        L83:
            if (r10 == 0) goto L86
            goto L72
        L86:
            return
        L87:
            if (r0 == 0) goto L8c
            r0.dispose()
        L8c:
            if (r10 == 0) goto L91
            r10.countDown()
        L91:
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$isMigratedChat$83$MessagesStorage(int, boolean[], java.util.concurrent.CountDownLatch):void");
    }

    public TLRPC.ChatFull loadChatInfo(final int chat_id, final CountDownLatch countDownLatch, final boolean force, final boolean byChannelUsers) {
        final TLRPC.ChatFull[] result = new TLRPC.ChatFull[1];
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$5Hu8edkC-HioQpGSwmXVKMqzwIA
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$loadChatInfo$84$MessagesStorage(chat_id, result, force, byChannelUsers, countDownLatch);
            }
        });
        if (countDownLatch != null) {
            try {
                countDownLatch.await();
            } catch (Throwable th) {
            }
        }
        return result[0];
    }

    /* JADX WARN: Removed duplicated region for block: B:132:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:97:0x01dd  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$loadChatInfo$84$MessagesStorage(int r23, im.uwrkaxlmjj.tgnet.TLRPC.ChatFull[] r24, boolean r25, boolean r26, java.util.concurrent.CountDownLatch r27) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 532
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$loadChatInfo$84$MessagesStorage(int, im.uwrkaxlmjj.tgnet.TLRPC$ChatFull[], boolean, boolean, java.util.concurrent.CountDownLatch):void");
    }

    public void processPendingRead(final long dialog_id, final long maxPositiveId, final long maxNegativeId, final boolean isChannel, final int scheduledCount) {
        final int maxDate = this.lastSavedDate;
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$ETScgPDovU3iUUPANkqhJ0OpHcE
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$processPendingRead$85$MessagesStorage(dialog_id, maxPositiveId, isChannel, scheduledCount, maxDate, maxNegativeId);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:138:0x026a  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x0275  */
    /* JADX WARN: Removed duplicated region for block: B:146:0x027a  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x01c3  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x01c8 A[PHI: r4 r5
      0x01c8: PHI (r4v5 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement) = 
      (r4v3 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement)
      (r4v31 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement)
     binds: [B:139:0x026d, B:82:0x01c6] A[DONT_GENERATE, DONT_INLINE]
      0x01c8: PHI (r5v7 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor) = (r5v5 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor), (r5v29 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor) binds: [B:139:0x026d, B:82:0x01c6] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$processPendingRead$85$MessagesStorage(long r24, long r26, boolean r28, int r29, int r30, long r31) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 638
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$processPendingRead$85$MessagesStorage(long, long, boolean, int, int, long):void");
    }

    public void putContacts(ArrayList<TLRPC.Contact> contacts, final boolean deleteAll) {
        if (contacts.isEmpty() && !deleteAll) {
            return;
        }
        final ArrayList<TLRPC.Contact> contactsCopy = new ArrayList<>(contacts);
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$sVCy6y5YAANkw7qVfgKYBtrieGU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putContacts$86$MessagesStorage(deleteAll, contactsCopy);
            }
        });
    }

    public /* synthetic */ void lambda$putContacts$86$MessagesStorage(boolean deleteAll, ArrayList contactsCopy) {
        SQLitePreparedStatement state = null;
        if (deleteAll) {
            try {
                try {
                    this.database.executeFast("DELETE FROM contacts WHERE 1").stepThis().dispose();
                } catch (Exception e) {
                    FileLog.e("putContacts ---> exception 2 ", e);
                    if (state == null) {
                        return;
                    }
                }
            } catch (Throwable th) {
                if (state != null) {
                    state.dispose();
                }
                throw th;
            }
        }
        try {
            this.database.beginTransaction();
        } catch (Exception e2) {
            FileLog.e("putContacts ---> exception 1 ", e2);
        }
        SQLitePreparedStatement state2 = this.database.executeFast("REPLACE INTO contacts VALUES(?, ?)");
        for (int a = 0; a < contactsCopy.size(); a++) {
            TLRPC.Contact contact = (TLRPC.Contact) contactsCopy.get(a);
            state2.requery();
            int i = 1;
            state2.bindInteger(1, contact.user_id);
            if (!contact.mutual) {
                i = 0;
            }
            state2.bindInteger(2, i);
            state2.step();
        }
        state2.dispose();
        state = null;
        this.database.commitTransaction();
        if (0 == 0) {
            return;
        }
        state.dispose();
    }

    public void deleteContacts(final ArrayList<Integer> uids) {
        if (uids == null || uids.isEmpty()) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$raxbaAcJP3Nla90ufOXMh03jUdI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$deleteContacts$87$MessagesStorage(uids);
            }
        });
    }

    public /* synthetic */ void lambda$deleteContacts$87$MessagesStorage(ArrayList uids) {
        SQLitePreparedStatement state = null;
        try {
            try {
                String ids = TextUtils.join(",", uids);
                state = this.database.executeFast("DELETE FROM contacts WHERE uid IN(" + ids + SQLBuilder.PARENTHESES_RIGHT);
                state.stepThis().dispose();
                state = null;
            } catch (Exception e) {
                FileLog.e("deleteContacts ---> exception ", e);
                if (state != null) {
                }
            }
            if (0 != 0) {
                state.dispose();
            }
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void applyPhoneBookUpdates(final String adds, final String deletes) {
        if (TextUtils.isEmpty(adds)) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$J687_0Q3sUGAm0qGNSM5vSPVgcE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$applyPhoneBookUpdates$88$MessagesStorage(adds, deletes);
            }
        });
    }

    public /* synthetic */ void lambda$applyPhoneBookUpdates$88$MessagesStorage(String adds, String deletes) {
        SQLitePreparedStatement state = null;
        try {
            try {
                if (adds.length() != 0) {
                    this.database.executeFast(String.format(Locale.US, "UPDATE user_phones_v7 SET deleted = 0 WHERE sphone IN(%s)", adds)).stepThis().dispose();
                    state = null;
                }
                if (deletes.length() != 0) {
                    state = this.database.executeFast(String.format(Locale.US, "UPDATE user_phones_v7 SET deleted = 1 WHERE sphone IN(%s)", deletes));
                    state.stepThis().dispose();
                    state = null;
                }
                if (state == null) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("applyPhoneBookUpdates ---> exception ", e);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void putCachedPhoneBook(final HashMap<String, ContactsController.Contact> contactHashMap, final boolean migrate, boolean delete) {
        if (contactHashMap != null) {
            if (contactHashMap.isEmpty() && !migrate && !delete) {
                return;
            }
            this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$8IhXk7c5d-DmPB4OgXZbyh8LrBk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$putCachedPhoneBook$89$MessagesStorage(contactHashMap, migrate);
                }
            });
        }
    }

    public /* synthetic */ void lambda$putCachedPhoneBook$89$MessagesStorage(HashMap contactHashMap, boolean migrate) {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d(this.currentAccount + " save contacts to db " + contactHashMap.size());
        }
        SQLitePreparedStatement state = null;
        SQLitePreparedStatement state2 = null;
        try {
            try {
                this.database.executeFast("DELETE FROM user_contacts_v7 WHERE 1").stepThis().dispose();
                this.database.executeFast("DELETE FROM user_phones_v7 WHERE 1").stepThis().dispose();
                try {
                    this.database.beginTransaction();
                } catch (Exception e) {
                    FileLog.e("putCachedPhoneBook ---> exception 1 ", e);
                }
                SQLitePreparedStatement state3 = this.database.executeFast("REPLACE INTO user_contacts_v7 VALUES(?, ?, ?, ?, ?)");
                SQLitePreparedStatement state22 = this.database.executeFast("REPLACE INTO user_phones_v7 VALUES(?, ?, ?, ?)");
                for (Map.Entry<String, ContactsController.Contact> entry : contactHashMap.entrySet()) {
                    ContactsController.Contact contact = entry.getValue();
                    if (!contact.phones.isEmpty() && !contact.shortPhones.isEmpty()) {
                        state3.requery();
                        state3.bindString(1, contact.key);
                        state3.bindInteger(2, contact.contact_id);
                        state3.bindString(3, contact.first_name);
                        state3.bindString(4, contact.last_name);
                        state3.bindInteger(5, contact.imported);
                        state3.step();
                        for (int a = 0; a < contact.phones.size(); a++) {
                            state22.requery();
                            state22.bindString(1, contact.key);
                            state22.bindString(2, contact.phones.get(a));
                            state22.bindString(3, contact.shortPhones.get(a));
                            state22.bindInteger(4, contact.phoneDeleted.get(a).intValue());
                            state22.step();
                        }
                    }
                }
                state3.dispose();
                state = null;
                state22.dispose();
                state2 = null;
                if (migrate) {
                    this.database.executeFast("DROP TABLE IF EXISTS user_contacts_v6;").stepThis().dispose();
                    this.database.executeFast("DROP TABLE IF EXISTS user_phones_v6;").stepThis().dispose();
                    state = null;
                    getCachedPhoneBook(false);
                }
                this.database.commitTransaction();
                if (state != null) {
                    state.dispose();
                }
                if (0 == 0) {
                    return;
                }
            } catch (Throwable th) {
                if (state != null) {
                    state.dispose();
                }
                if (state2 != null) {
                    state2.dispose();
                }
                throw th;
            }
        } catch (Exception e2) {
            FileLog.e("putCachedPhoneBook ---> exception 2 ", e2);
            if (state != null) {
                state.dispose();
            }
            if (state2 == null) {
                return;
            }
        }
        state2.dispose();
    }

    public void getCachedPhoneBook(final boolean byError) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$Y-O9bdrMjKwRUZkAaOXHXsgTcZM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getCachedPhoneBook$90$MessagesStorage(byError);
            }
        });
    }

    /* JADX WARN: Can't wrap try/catch for region: R(26:0|2|121|3|(7:5|(1:7)|8|(6:11|(5:13|(1:15)|16|(1:18)|19)|20|(3:131|22|138)(3:130|23|(3:133|25|137)(5:132|26|(1:30)|31|(2:134|33)(2:34|136)))|135|9)|129|35|(2:37|38)(1:145))(20:(0)|45|126|46|(4:48|(1:50)|51|(1:53))|54|55|(1:57)|58|63|123|(1:65)(1:66)|144|(6:69|(5:71|(1:73)|74|(1:76)|77)|78|(2:80|141)(2:81|(4:84|(1:89)(1:88)|90|(2:140|92)(1:143))(2:83|142))|94|67)|139|95|96|(1:98)|106|107)|40|45|126|46|(0)|54|55|(0)|58|63|123|(0)(0)|144|(1:67)|139|95|96|(0)|106|107|(1:(0))) */
    /* JADX WARN: Code restructure failed: missing block: B:101:0x0225, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:102:0x0226, code lost:
    
        r0.clear();
        im.uwrkaxlmjj.messenger.FileLog.e("getCachedPhoneBook ---> exception 3 ", r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:103:0x022e, code lost:
    
        if (r3 != null) goto L104;
     */
    /* JADX WARN: Code restructure failed: missing block: B:104:0x0230, code lost:
    
        r3.dispose();
     */
    /* JADX WARN: Code restructure failed: missing block: B:111:0x0250, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:112:0x0251, code lost:
    
        if (r3 != null) goto L113;
     */
    /* JADX WARN: Code restructure failed: missing block: B:113:0x0253, code lost:
    
        r3.dispose();
     */
    /* JADX WARN: Code restructure failed: missing block: B:114:0x0256, code lost:
    
        throw r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x0148, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x0149, code lost:
    
        im.uwrkaxlmjj.messenger.FileLog.e("getCachedPhoneBook ---> exception 2 ", r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x014e, code lost:
    
        if (r3 != null) goto L62;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x0150, code lost:
    
        r3.dispose();
     */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0110 A[Catch: all -> 0x0148, TryCatch #4 {all -> 0x0148, blocks: (B:46:0x00ff, B:48:0x0110, B:50:0x011e, B:51:0x0120, B:53:0x0124, B:54:0x013d), top: B:126:0x00ff }] */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0143  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x015b A[Catch: all -> 0x0223, Exception -> 0x0225, TRY_ENTER, TryCatch #5 {Exception -> 0x0225, blocks: (B:65:0x015b, B:67:0x0181, B:69:0x0187, B:71:0x0193, B:73:0x01b6, B:74:0x01b8, B:76:0x01bc, B:77:0x01be, B:78:0x01c1, B:81:0x01cc, B:84:0x01db, B:86:0x01e3, B:88:0x01e9, B:90:0x01f2, B:95:0x0219, B:66:0x0176), top: B:123:0x0159, outer: #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0176 A[Catch: all -> 0x0223, Exception -> 0x0225, TryCatch #5 {Exception -> 0x0225, blocks: (B:65:0x015b, B:67:0x0181, B:69:0x0187, B:71:0x0193, B:73:0x01b6, B:74:0x01b8, B:76:0x01bc, B:77:0x01be, B:78:0x01c1, B:81:0x01cc, B:84:0x01db, B:86:0x01e3, B:88:0x01e9, B:90:0x01f2, B:95:0x0219, B:66:0x0176), top: B:123:0x0159, outer: #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:69:0x0187 A[Catch: all -> 0x0223, Exception -> 0x0225, TryCatch #5 {Exception -> 0x0225, blocks: (B:65:0x015b, B:67:0x0181, B:69:0x0187, B:71:0x0193, B:73:0x01b6, B:74:0x01b8, B:76:0x01bc, B:77:0x01be, B:78:0x01c1, B:81:0x01cc, B:84:0x01db, B:86:0x01e3, B:88:0x01e9, B:90:0x01f2, B:95:0x0219, B:66:0x0176), top: B:123:0x0159, outer: #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:98:0x021f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$getCachedPhoneBook$90$MessagesStorage(boolean r27) {
        /*
            Method dump skipped, instruction units count: 606
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$getCachedPhoneBook$90$MessagesStorage(boolean):void");
    }

    public void getContacts() {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$lq3Bbc3r33hmxpvXzOI6-VeuZ9w
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getContacts$91$MessagesStorage();
            }
        });
    }

    public /* synthetic */ void lambda$getContacts$91$MessagesStorage() {
        ArrayList<TLRPC.Contact> contacts = new ArrayList<>();
        ArrayList<TLRPC.User> users = new ArrayList<>();
        SQLiteCursor cursor = null;
        try {
            try {
                SQLiteCursor cursor2 = this.database.queryFinalized("SELECT * FROM contacts WHERE 1", new Object[0]);
                StringBuilder uids = new StringBuilder();
                while (cursor2.next()) {
                    int user_id = cursor2.intValue(0);
                    TLRPC.Contact contact = new TLRPC.Contact();
                    contact.user_id = user_id;
                    contact.mutual = cursor2.intValue(1) == 1;
                    if (uids.length() != 0) {
                        uids.append(",");
                    }
                    contacts.add(contact);
                    uids.append(contact.user_id);
                }
                cursor2.dispose();
                cursor = null;
                if (uids.length() != 0) {
                    getUsersInternal(uids.toString(), users);
                }
            } catch (Exception e) {
                contacts.clear();
                users.clear();
                FileLog.e("getContacts ---> exception ", e);
                if (cursor != null) {
                }
            }
            getContactsController().processLoadedContacts(contacts, users, 1);
        } finally {
            if (cursor != null) {
                cursor.dispose();
            }
        }
    }

    public void getUnsentMessages(final int count) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$rlt9mcZBKvApzXkR0zLmDQkE0X8
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$getUnsentMessages$92$MessagesStorage(count);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:172:0x0346  */
    /* JADX WARN: Removed duplicated region for block: B:177:0x0351  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$getUnsentMessages$92$MessagesStorage(int r20) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 853
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$getUnsentMessages$92$MessagesStorage(int):void");
    }

    public boolean checkMessageByRandomId(final long random_id) {
        final boolean[] result = new boolean[1];
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$lTPPNhZONoDfM2hMMUxInEa_Ywk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$checkMessageByRandomId$93$MessagesStorage(random_id, result, countDownLatch);
            }
        });
        try {
            countDownLatch.await();
        } catch (Exception e) {
            FileLog.e("checkMessageByRandomId ---> exception 2 ", e);
        }
        return result[0];
    }

    public /* synthetic */ void lambda$checkMessageByRandomId$93$MessagesStorage(long random_id, boolean[] result, CountDownLatch countDownLatch) {
        SQLiteCursor cursor = null;
        try {
            try {
                cursor = this.database.queryFinalized(String.format(Locale.US, "SELECT random_id FROM randoms WHERE random_id = %d", Long.valueOf(random_id)), new Object[0]);
                if (cursor.next()) {
                    result[0] = true;
                }
                cursor.dispose();
                cursor = null;
            } catch (Exception e) {
                FileLog.e("checkMessageByRandomId ---> exception 1 ", e);
                if (cursor != null) {
                }
            }
            countDownLatch.countDown();
        } finally {
            if (cursor != null) {
                cursor.dispose();
            }
        }
    }

    public boolean checkMessageId(final long dialog_id, final int mid) {
        final boolean[] result = new boolean[1];
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$oP27FQjBCsTzNBnoQ7ImTdz5O0E
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$checkMessageId$94$MessagesStorage(dialog_id, mid, result, countDownLatch);
            }
        });
        try {
            countDownLatch.await();
        } catch (Exception e) {
            FileLog.e("checkMessageId ---> exception 2 ", e);
        }
        return result[0];
    }

    public /* synthetic */ void lambda$checkMessageId$94$MessagesStorage(long dialog_id, int mid, boolean[] result, CountDownLatch countDownLatch) {
        SQLiteCursor cursor = null;
        try {
            try {
                cursor = this.database.queryFinalized(String.format(Locale.US, "SELECT mid FROM messages WHERE uid = %d AND mid = %d", Long.valueOf(dialog_id), Integer.valueOf(mid)), new Object[0]);
                if (cursor.next()) {
                    result[0] = true;
                }
                cursor.dispose();
                cursor = null;
            } catch (Exception e) {
                FileLog.e("checkMessageId ---> exception 1 ", e);
                if (cursor != null) {
                }
            }
            countDownLatch.countDown();
        } finally {
            if (cursor != null) {
                cursor.dispose();
            }
        }
    }

    public void getUnreadMention(final long dialog_id, final IntCallback callback) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$47DklnX10ntJQRolrC7MAHlwmTc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getUnreadMention$96$MessagesStorage(dialog_id, callback);
            }
        });
    }

    public /* synthetic */ void lambda$getUnreadMention$96$MessagesStorage(long dialog_id, final IntCallback callback) {
        SQLiteCursor cursor = null;
        try {
            try {
                SQLiteCursor cursor2 = this.database.queryFinalized(String.format(Locale.US, "SELECT MIN(mid) FROM messages WHERE uid = %d AND mention = 1 AND read_state IN(0, 1)", Long.valueOf(dialog_id)), new Object[0]);
                final int result = cursor2.next() ? cursor2.intValue(0) : 0;
                cursor2.dispose();
                cursor = null;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$9sDAEHmYbJJz6mD9YdTDtR3lW2U
                    @Override // java.lang.Runnable
                    public final void run() {
                        callback.run(result);
                    }
                });
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("getUnreadMention ---> exception ", e);
                if (cursor == null) {
                    return;
                }
            }
            cursor.dispose();
        } catch (Throwable th) {
            if (cursor != null) {
                cursor.dispose();
            }
            throw th;
        }
    }

    public void getMessagesCount(final long dialog_id, final IntCallback callback) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$87p69J4OEXH--zHI4XaEhGo5kvc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getMessagesCount$98$MessagesStorage(dialog_id, callback);
            }
        });
    }

    public /* synthetic */ void lambda$getMessagesCount$98$MessagesStorage(long dialog_id, final IntCallback callback) {
        SQLiteCursor cursor = null;
        try {
            try {
                SQLiteCursor cursor2 = this.database.queryFinalized(String.format(Locale.US, "SELECT COUNT(mid) FROM messages WHERE uid = %d", Long.valueOf(dialog_id)), new Object[0]);
                final int result = cursor2.next() ? cursor2.intValue(0) : 0;
                cursor2.dispose();
                cursor = null;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$tzXAfJVhwAHkJzuReg6nWVYclpI
                    @Override // java.lang.Runnable
                    public final void run() {
                        callback.run(result);
                    }
                });
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("getMessagesCount ---> exception ", e);
                if (cursor == null) {
                    return;
                }
            }
            cursor.dispose();
        } catch (Throwable th) {
            if (cursor != null) {
                cursor.dispose();
            }
            throw th;
        }
    }

    public void getMessages(final long dialog_id, final int count, final int max_id, final int offset_date, final int minDate, final int classGuid, final int load_type, final boolean isChannel, final boolean scheduled, final int loadIndex) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$NE5UdsHKZAho20mLLJrmOr2zSe0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getMessages$100$MessagesStorage(count, max_id, isChannel, dialog_id, scheduled, load_type, minDate, offset_date, classGuid, loadIndex);
            }
        });
    }

    /* JADX WARN: Unreachable blocks removed: 2, instructions: 21 */
    /*  JADX ERROR: JadxRuntimeException in pass: BlockProcessor
        jadx.core.utils.exceptions.JadxRuntimeException: Unreachable block: B:743:0x21e5
        	at jadx.core.dex.visitors.blocks.BlockProcessor.checkForUnreachableBlocks(BlockProcessor.java:132)
        	at jadx.core.dex.visitors.blocks.BlockProcessor.processBlocksTree(BlockProcessor.java:58)
        	at jadx.core.dex.visitors.blocks.BlockProcessor.visit(BlockProcessor.java:50)
        */
    public /* synthetic */ void lambda$getMessages$100$MessagesStorage(int r58, int r59, boolean r60, long r61, boolean r63, int r64, int r65, int r66, int r67, int r68) {
        /*
            Method dump skipped, instruction units count: 15655
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$getMessages$100$MessagesStorage(int, int, boolean, long, boolean, int, int, int, int, int):void");
    }

    static /* synthetic */ int lambda$null$99(TLRPC.Message lhs, TLRPC.Message rhs) {
        if (lhs.id > 0 && rhs.id > 0) {
            if (lhs.id > rhs.id) {
                return -1;
            }
            return lhs.id < rhs.id ? 1 : 0;
        }
        if (lhs.id < 0 && rhs.id < 0) {
            if (lhs.id < rhs.id) {
                return -1;
            }
            return lhs.id > rhs.id ? 1 : 0;
        }
        if (lhs.date > rhs.date) {
            return -1;
        }
        return lhs.date < rhs.date ? 1 : 0;
    }

    public void clearSentMedia() {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$D1W3evW6HHFDZRpun0QL-XTJRno
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$clearSentMedia$101$MessagesStorage();
            }
        });
    }

    public /* synthetic */ void lambda$clearSentMedia$101$MessagesStorage() {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast("DELETE FROM sent_files_v2 WHERE 1");
                state.stepThis().dispose();
                state = null;
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("clearSentMedia ---> exception ", e);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public Object[] getSentFile(final String path, final int type) {
        if (path == null || path.toLowerCase().endsWith("attheme")) {
            return null;
        }
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final Object[] result = new Object[2];
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$mgLwO0C04jLTRbloxv3XoaKlidw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getSentFile$102$MessagesStorage(path, type, result, countDownLatch);
            }
        });
        try {
            countDownLatch.await();
        } catch (Exception e) {
            FileLog.e("getSentFile ---> exception 2 ", e);
        }
        if (result[0] != null) {
            return result;
        }
        return null;
    }

    public /* synthetic */ void lambda$getSentFile$102$MessagesStorage(String path, int type, Object[] result, CountDownLatch countDownLatch) {
        SQLiteCursor cursor = null;
        NativeByteBuffer data = null;
        try {
            try {
                String id = Utilities.MD5(path);
                if (id != null) {
                    cursor = this.database.queryFinalized(String.format(Locale.US, "SELECT data, parent FROM sent_files_v2 WHERE uid = '%s' AND type = %d", id, Integer.valueOf(type)), new Object[0]);
                    if (cursor.next() && (data = cursor.byteBufferValue(0)) != null) {
                        TLObject file = TLRPC.MessageMedia.TLdeserialize(data, data.readInt32(false), false);
                        data.reuse();
                        data = null;
                        if (file instanceof TLRPC.TL_messageMediaDocument) {
                            result[0] = ((TLRPC.TL_messageMediaDocument) file).document;
                        } else if (file instanceof TLRPC.TL_messageMediaPhoto) {
                            result[0] = ((TLRPC.TL_messageMediaPhoto) file).photo;
                        }
                        if (result[0] != null) {
                            result[1] = cursor.stringValue(1);
                        }
                    }
                    cursor.dispose();
                    cursor = null;
                }
            } catch (Exception e) {
                FileLog.e("getSentFile ---> exception 1 ", e);
                if (data != null) {
                    data.reuse();
                }
                if (cursor != null) {
                }
            }
        } finally {
            if (data != null) {
                data.reuse();
            }
            if (cursor != null) {
                cursor.dispose();
            }
            countDownLatch.countDown();
        }
    }

    public void putSentFile(final String path, final TLObject file, final int type, final String parent) {
        if (path == null || file == null || parent == null) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$3qyXmjdEdwN1uQDpwEGaW4t2WEo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putSentFile$103$MessagesStorage(path, file, type, parent);
            }
        });
    }

    public /* synthetic */ void lambda$putSentFile$103$MessagesStorage(String path, TLObject file, int type, String parent) {
        String id;
        NativeByteBuffer data = null;
        SQLitePreparedStatement state = null;
        try {
            try {
                id = Utilities.MD5(path);
            } catch (Exception e) {
                FileLog.e("putSentFile ---> exception ", e);
                if (data != null) {
                    data.reuse();
                }
                if (state == null) {
                    return;
                }
            }
            if (id != null) {
                TLRPC.MessageMedia messageMedia = null;
                if (file instanceof TLRPC.Photo) {
                    messageMedia = new TLRPC.TL_messageMediaPhoto();
                    messageMedia.photo = (TLRPC.Photo) file;
                    messageMedia.flags |= 1;
                } else if (file instanceof TLRPC.Document) {
                    messageMedia = new TLRPC.TL_messageMediaDocument();
                    messageMedia.document = (TLRPC.Document) file;
                    messageMedia.flags |= 1;
                }
                if (messageMedia == null) {
                    if (0 != 0) {
                        data.reuse();
                    }
                    if (0 != 0) {
                        state.dispose();
                        return;
                    }
                    return;
                }
                state = this.database.executeFast("REPLACE INTO sent_files_v2 VALUES(?, ?, ?, ?)");
                state.requery();
                NativeByteBuffer data2 = new NativeByteBuffer(messageMedia.getObjectSize());
                messageMedia.serializeToStream(data2);
                state.bindString(1, id);
                state.bindInteger(2, type);
                state.bindByteBuffer(3, data2);
                state.bindString(4, parent);
                state.step();
                data2.reuse();
                data = null;
                state.dispose();
                state = null;
                state.dispose();
            }
            if (data != null) {
                data.reuse();
            }
            if (state == null) {
                return;
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void updateEncryptedChatSeq(final TLRPC.EncryptedChat chat, final boolean cleanup) {
        if (chat == null) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$6I1QJQhnfegrMI-gACJ7BYvnlls
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateEncryptedChatSeq$104$MessagesStorage(chat, cleanup);
            }
        });
    }

    public /* synthetic */ void lambda$updateEncryptedChatSeq$104$MessagesStorage(TLRPC.EncryptedChat chat, boolean cleanup) {
        SQLitePreparedStatement state = null;
        SQLitePreparedStatement state2 = null;
        try {
            try {
                state = this.database.executeFast("UPDATE enc_chats SET seq_in = ?, seq_out = ?, use_count = ?, in_seq_no = ?, mtproto_seq = ? WHERE uid = ?");
                state.bindInteger(1, chat.seq_in);
                state.bindInteger(2, chat.seq_out);
                state.bindInteger(3, (chat.key_use_count_in << 16) | chat.key_use_count_out);
                state.bindInteger(4, chat.in_seq_no);
                state.bindInteger(5, chat.mtproto_seq);
                state.bindInteger(6, chat.id);
                state.step();
                if (cleanup && chat.in_seq_no != 0) {
                    long did = ((long) chat.id) << 32;
                    this.database.executeFast(String.format(Locale.US, "DELETE FROM messages WHERE mid IN (SELECT m.mid FROM messages as m LEFT JOIN messages_seq as s ON m.mid = s.mid WHERE m.uid = %d AND m.date = 0 AND m.mid < 0 AND s.seq_out <= %d)", Long.valueOf(did), Integer.valueOf(chat.in_seq_no))).stepThis().dispose();
                    state2 = null;
                }
                state.dispose();
                SQLitePreparedStatement state3 = null;
                if (0 != 0) {
                    state3.dispose();
                }
                if (state2 == null) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("updateEncryptedChatSeq ---> exception ", e);
                if (state != null) {
                    state.dispose();
                }
                if (state2 == null) {
                    return;
                }
            }
            state2.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            if (state2 != null) {
                state2.dispose();
            }
            throw th;
        }
    }

    public void updateEncryptedChatTTL(final TLRPC.EncryptedChat chat) {
        if (chat == null) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$F7c1p-EctgQ6wExTl2_FYwkZ_hg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateEncryptedChatTTL$105$MessagesStorage(chat);
            }
        });
    }

    public /* synthetic */ void lambda$updateEncryptedChatTTL$105$MessagesStorage(TLRPC.EncryptedChat chat) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast("UPDATE enc_chats SET ttl = ? WHERE uid = ?");
                state.bindInteger(1, chat.ttl);
                state.bindInteger(2, chat.id);
                state.step();
                state.dispose();
                state = null;
            } catch (Exception e) {
                FileLog.e("updateEncryptedChatTTL ---> exception ", e);
                if (state != null) {
                }
            }
            if (0 != 0) {
                state.dispose();
            }
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void updateEncryptedChatLayer(final TLRPC.EncryptedChat chat) {
        if (chat == null) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$XYe52lIpyU2LpOpdC30UVU8B7fU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateEncryptedChatLayer$106$MessagesStorage(chat);
            }
        });
    }

    public /* synthetic */ void lambda$updateEncryptedChatLayer$106$MessagesStorage(TLRPC.EncryptedChat chat) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast("UPDATE enc_chats SET layer = ? WHERE uid = ?");
                state.bindInteger(1, chat.layer);
                state.bindInteger(2, chat.id);
                state.step();
                state.dispose();
                state = null;
            } catch (Exception e) {
                FileLog.e("updateEncryptedChatLayer ---> exception ", e);
                if (state != null) {
                }
            }
            if (0 != 0) {
                state.dispose();
            }
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void updateEncryptedChat(final TLRPC.EncryptedChat chat) {
        if (chat == null) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$Ov-EUI4Q3ufwbf_nlF8oD0Gos5E
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateEncryptedChat$107$MessagesStorage(chat);
            }
        });
    }

    public /* synthetic */ void lambda$updateEncryptedChat$107$MessagesStorage(TLRPC.EncryptedChat chat) {
        NativeByteBuffer data = null;
        NativeByteBuffer data2 = null;
        NativeByteBuffer data3 = null;
        NativeByteBuffer data4 = null;
        NativeByteBuffer data5 = null;
        SQLitePreparedStatement state = null;
        try {
            try {
                if ((chat.key_hash == null || chat.key_hash.length < 16) && chat.auth_key != null) {
                    chat.key_hash = AndroidUtilities.calcAuthKeyHash(chat.auth_key);
                }
                state = this.database.executeFast("UPDATE enc_chats SET data = ?, g = ?, authkey = ?, ttl = ?, layer = ?, seq_in = ?, seq_out = ?, use_count = ?, exchange_id = ?, key_date = ?, fprint = ?, fauthkey = ?, khash = ?, in_seq_no = ?, admin_id = ?, mtproto_seq = ? WHERE uid = ?");
                NativeByteBuffer data6 = new NativeByteBuffer(chat.getObjectSize());
                NativeByteBuffer data22 = new NativeByteBuffer(chat.a_or_b != null ? chat.a_or_b.length : 1);
                NativeByteBuffer data32 = new NativeByteBuffer(chat.auth_key != null ? chat.auth_key.length : 1);
                NativeByteBuffer data42 = new NativeByteBuffer(chat.future_auth_key != null ? chat.future_auth_key.length : 1);
                NativeByteBuffer data52 = new NativeByteBuffer(chat.key_hash != null ? chat.key_hash.length : 1);
                chat.serializeToStream(data6);
                state.bindByteBuffer(1, data6);
                if (chat.a_or_b != null) {
                    data22.writeBytes(chat.a_or_b);
                }
                if (chat.auth_key != null) {
                    data32.writeBytes(chat.auth_key);
                }
                if (chat.future_auth_key != null) {
                    data42.writeBytes(chat.future_auth_key);
                }
                if (chat.key_hash != null) {
                    data52.writeBytes(chat.key_hash);
                }
                state.bindByteBuffer(2, data22);
                state.bindByteBuffer(3, data32);
                state.bindInteger(4, chat.ttl);
                state.bindInteger(5, chat.layer);
                state.bindInteger(6, chat.seq_in);
                state.bindInteger(7, chat.seq_out);
                state.bindInteger(8, (chat.key_use_count_in << 16) | chat.key_use_count_out);
                state.bindLong(9, chat.exchange_id);
                state.bindInteger(10, chat.key_create_date);
                state.bindLong(11, chat.future_key_fingerprint);
                state.bindByteBuffer(12, data42);
                state.bindByteBuffer(13, data52);
                state.bindInteger(14, chat.in_seq_no);
                state.bindInteger(15, chat.admin_id);
                state.bindInteger(16, chat.mtproto_seq);
                state.bindInteger(17, chat.id);
                state.step();
                data6.reuse();
                data = null;
                data22.reuse();
                data2 = null;
                data32.reuse();
                data3 = null;
                data42.reuse();
                data4 = null;
                data52.reuse();
                data5 = null;
                state.dispose();
                state = null;
                if (0 != 0) {
                    data.reuse();
                }
                if (0 != 0) {
                    data2.reuse();
                }
                if (0 != 0) {
                    data3.reuse();
                }
                if (0 != 0) {
                    data4.reuse();
                }
                if (0 != 0) {
                    data5.reuse();
                }
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("updateEncryptedChat ---> exception ", e);
                if (data != null) {
                    data.reuse();
                }
                if (data2 != null) {
                    data2.reuse();
                }
                if (data3 != null) {
                    data3.reuse();
                }
                if (data4 != null) {
                    data4.reuse();
                }
                if (data5 != null) {
                    data5.reuse();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (data2 != null) {
                data2.reuse();
            }
            if (data3 != null) {
                data3.reuse();
            }
            if (data4 != null) {
                data4.reuse();
            }
            if (data5 != null) {
                data5.reuse();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public boolean isDialogHasMessages(final long did) {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final boolean[] result = new boolean[1];
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$6faNYTYRPzWiqRmINV7TP8JxKas
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$isDialogHasMessages$108$MessagesStorage(did, result, countDownLatch);
            }
        });
        try {
            countDownLatch.await();
        } catch (Exception e) {
            FileLog.e("isDialogHasMessages ---> exception 2 ", e);
        }
        return result[0];
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0033 A[PHI: r0
      0x0033: PHI (r0v3 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor) = (r0v2 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor), (r0v5 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor) binds: [B:11:0x0031, B:5:0x0026] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$isDialogHasMessages$108$MessagesStorage(long r8, boolean[] r10, java.util.concurrent.CountDownLatch r11) {
        /*
            r7 = this;
            r0 = 0
            im.uwrkaxlmjj.sqlite.SQLiteDatabase r1 = r7.database     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            java.util.Locale r2 = java.util.Locale.US     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            java.lang.String r3 = "SELECT mid FROM messages WHERE uid = %d LIMIT 1"
            r4 = 1
            java.lang.Object[] r4 = new java.lang.Object[r4]     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            java.lang.Long r5 = java.lang.Long.valueOf(r8)     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            r6 = 0
            r4[r6] = r5     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            java.lang.String r2 = java.lang.String.format(r2, r3, r4)     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            java.lang.Object[] r3 = new java.lang.Object[r6]     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            im.uwrkaxlmjj.sqlite.SQLiteCursor r1 = r1.queryFinalized(r2, r3)     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            r0 = r1
            boolean r1 = r0.next()     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            r10[r6] = r1     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            r0.dispose()     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            r0 = 0
            if (r0 == 0) goto L36
            goto L33
        L29:
            r1 = move-exception
            goto L3b
        L2b:
            r1 = move-exception
            java.lang.String r2 = "isDialogHasMessages ---> exception 1 "
            im.uwrkaxlmjj.messenger.FileLog.e(r2, r1)     // Catch: java.lang.Throwable -> L29
            if (r0 == 0) goto L36
        L33:
            r0.dispose()
        L36:
            r11.countDown()
            return
        L3b:
            if (r0 == 0) goto L40
            r0.dispose()
        L40:
            r11.countDown()
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$isDialogHasMessages$108$MessagesStorage(long, boolean[], java.util.concurrent.CountDownLatch):void");
    }

    public boolean hasAuthMessage(final int date) {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final boolean[] result = new boolean[1];
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$J7f1Lh3OCvKBfwyGO-rK5MA55TU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$hasAuthMessage$109$MessagesStorage(date, result, countDownLatch);
            }
        });
        try {
            countDownLatch.await();
        } catch (Exception e) {
            FileLog.e("hasAuthMessage ---> exception 2 ", e);
        }
        return result[0];
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0033 A[PHI: r0
      0x0033: PHI (r0v3 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor) = (r0v2 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor), (r0v5 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor) binds: [B:11:0x0031, B:5:0x0026] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$hasAuthMessage$109$MessagesStorage(int r8, boolean[] r9, java.util.concurrent.CountDownLatch r10) {
        /*
            r7 = this;
            r0 = 0
            im.uwrkaxlmjj.sqlite.SQLiteDatabase r1 = r7.database     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            java.util.Locale r2 = java.util.Locale.US     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            java.lang.String r3 = "SELECT mid FROM messages WHERE uid = 777000 AND date = %d AND mid < 0 LIMIT 1"
            r4 = 1
            java.lang.Object[] r4 = new java.lang.Object[r4]     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            java.lang.Integer r5 = java.lang.Integer.valueOf(r8)     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            r6 = 0
            r4[r6] = r5     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            java.lang.String r2 = java.lang.String.format(r2, r3, r4)     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            java.lang.Object[] r3 = new java.lang.Object[r6]     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            im.uwrkaxlmjj.sqlite.SQLiteCursor r1 = r1.queryFinalized(r2, r3)     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            r0 = r1
            boolean r1 = r0.next()     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            r9[r6] = r1     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            r0.dispose()     // Catch: java.lang.Throwable -> L29 java.lang.Exception -> L2b
            r0 = 0
            if (r0 == 0) goto L36
            goto L33
        L29:
            r1 = move-exception
            goto L3b
        L2b:
            r1 = move-exception
            java.lang.String r2 = "hasAuthMessage ---> exception 1 "
            im.uwrkaxlmjj.messenger.FileLog.e(r2, r1)     // Catch: java.lang.Throwable -> L29
            if (r0 == 0) goto L36
        L33:
            r0.dispose()
        L36:
            r10.countDown()
            return
        L3b:
            if (r0 == 0) goto L40
            r0.dispose()
        L40:
            r10.countDown()
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$hasAuthMessage$109$MessagesStorage(int, boolean[], java.util.concurrent.CountDownLatch):void");
    }

    public void getEncryptedChat(final int chat_id, final CountDownLatch countDownLatch, final ArrayList<TLObject> result) {
        if (countDownLatch == null || result == null) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$9uhisJdG18IWNrh-mOE0HhTJYhc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getEncryptedChat$110$MessagesStorage(chat_id, result, countDownLatch);
            }
        });
    }

    public /* synthetic */ void lambda$getEncryptedChat$110$MessagesStorage(int chat_id, ArrayList result, CountDownLatch countDownLatch) {
        try {
            try {
                ArrayList<Integer> usersToLoad = new ArrayList<>();
                ArrayList<TLRPC.EncryptedChat> encryptedChats = new ArrayList<>();
                getEncryptedChatsInternal("" + chat_id, encryptedChats, usersToLoad);
                if (!encryptedChats.isEmpty() && !usersToLoad.isEmpty()) {
                    ArrayList<TLRPC.User> users = new ArrayList<>();
                    getUsersInternal(TextUtils.join(",", usersToLoad), users);
                    if (!users.isEmpty()) {
                        result.add(encryptedChats.get(0));
                        result.add(users.get(0));
                    }
                }
            } catch (Exception e) {
                FileLog.e("getEncryptedChat ---> exception ", e);
            }
        } finally {
            countDownLatch.countDown();
        }
    }

    public void putEncryptedChat(final TLRPC.EncryptedChat chat, final TLRPC.User user, final TLRPC.Dialog dialog) {
        if (chat == null) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$vXr5K43eGQekIGAk1OsQMTqvyuU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putEncryptedChat$111$MessagesStorage(chat, user, dialog);
            }
        });
    }

    public /* synthetic */ void lambda$putEncryptedChat$111$MessagesStorage(TLRPC.EncryptedChat chat, TLRPC.User user, TLRPC.Dialog dialog) {
        if ((chat.key_hash == null || chat.key_hash.length < 16) && chat.auth_key != null) {
            chat.key_hash = AndroidUtilities.calcAuthKeyHash(chat.auth_key);
        }
        SQLitePreparedStatement state = null;
        NativeByteBuffer data = null;
        NativeByteBuffer data2 = null;
        NativeByteBuffer data3 = null;
        NativeByteBuffer data4 = null;
        NativeByteBuffer data5 = null;
        try {
            try {
                SQLitePreparedStatement state2 = this.database.executeFast("REPLACE INTO enc_chats VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                NativeByteBuffer data6 = new NativeByteBuffer(chat.getObjectSize());
                NativeByteBuffer data22 = new NativeByteBuffer(chat.a_or_b != null ? chat.a_or_b.length : 1);
                NativeByteBuffer data32 = new NativeByteBuffer(chat.auth_key != null ? chat.auth_key.length : 1);
                NativeByteBuffer data42 = new NativeByteBuffer(chat.future_auth_key != null ? chat.future_auth_key.length : 1);
                NativeByteBuffer data52 = new NativeByteBuffer(chat.key_hash != null ? chat.key_hash.length : 1);
                chat.serializeToStream(data6);
                state2.bindInteger(1, chat.id);
                state2.bindInteger(2, user.id);
                state2.bindString(3, formatUserSearchName(user));
                state2.bindByteBuffer(4, data6);
                if (chat.a_or_b != null) {
                    data22.writeBytes(chat.a_or_b);
                }
                if (chat.auth_key != null) {
                    data32.writeBytes(chat.auth_key);
                }
                if (chat.future_auth_key != null) {
                    data42.writeBytes(chat.future_auth_key);
                }
                if (chat.key_hash != null) {
                    data52.writeBytes(chat.key_hash);
                }
                state2.bindByteBuffer(5, data22);
                state2.bindByteBuffer(6, data32);
                state2.bindInteger(7, chat.ttl);
                state2.bindInteger(8, chat.layer);
                state2.bindInteger(9, chat.seq_in);
                state2.bindInteger(10, chat.seq_out);
                state2.bindInteger(11, chat.key_use_count_out | (chat.key_use_count_in << 16));
                state2.bindLong(12, chat.exchange_id);
                state2.bindInteger(13, chat.key_create_date);
                state2.bindLong(14, chat.future_key_fingerprint);
                state2.bindByteBuffer(15, data42);
                state2.bindByteBuffer(16, data52);
                state2.bindInteger(17, chat.in_seq_no);
                state2.bindInteger(18, chat.admin_id);
                state2.bindInteger(19, chat.mtproto_seq);
                state2.step();
                state2.dispose();
                state = null;
                data6.reuse();
                data = null;
                data22.reuse();
                data2 = null;
                data32.reuse();
                data3 = null;
                data42.reuse();
                data4 = null;
                data52.reuse();
                data5 = null;
                if (dialog != null) {
                    state = this.database.executeFast("REPLACE INTO dialogs VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                    state.bindLong(1, dialog.id);
                    state.bindInteger(2, dialog.last_message_date);
                    state.bindInteger(3, dialog.unread_count);
                    state.bindInteger(4, dialog.top_message);
                    state.bindInteger(5, dialog.read_inbox_max_id);
                    state.bindInteger(6, dialog.read_outbox_max_id);
                    state.bindInteger(7, 0);
                    state.bindInteger(8, dialog.unread_mentions_count);
                    state.bindInteger(9, dialog.pts);
                    state.bindInteger(10, 0);
                    state.bindInteger(11, dialog.pinnedNum);
                    state.bindInteger(12, dialog.flags);
                    state.bindInteger(13, dialog.folder_id);
                    state.bindNull(14);
                    state.step();
                    state.dispose();
                    state = null;
                }
                if (0 != 0) {
                    data.reuse();
                }
                if (0 != 0) {
                    data2.reuse();
                }
                if (0 != 0) {
                    data3.reuse();
                }
                if (0 != 0) {
                    data4.reuse();
                }
                if (0 != 0) {
                    data5.reuse();
                }
                if (state == null) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("putEncryptedChat ---> exception ", e);
                if (data != null) {
                    data.reuse();
                }
                if (data2 != null) {
                    data2.reuse();
                }
                if (data3 != null) {
                    data3.reuse();
                }
                if (data4 != null) {
                    data4.reuse();
                }
                if (data5 != null) {
                    data5.reuse();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (data2 != null) {
                data2.reuse();
            }
            if (data3 != null) {
                data3.reuse();
            }
            if (data4 != null) {
                data4.reuse();
            }
            if (data5 != null) {
                data5.reuse();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    private String formatUserSearchName(TLRPC.User user) {
        StringBuilder str = new StringBuilder();
        if (user.first_name != null && user.first_name.length() > 0) {
            str.append(user.first_name);
        }
        if (user.last_name != null && user.last_name.length() > 0) {
            if (str.length() > 0) {
                str.append(" ");
            }
            str.append(user.last_name);
        }
        str.append(";;;");
        if (user.username != null && user.username.length() > 0) {
            str.append(user.username);
        }
        return str.toString().toLowerCase();
    }

    private void putUsersInternal(ArrayList<TLRPC.User> users) throws Exception {
        if (users == null || users.isEmpty()) {
            return;
        }
        NativeByteBuffer data = null;
        SQLitePreparedStatement state = null;
        try {
            try {
                SQLitePreparedStatement state2 = this.database.executeFast("REPLACE INTO users VALUES(?, ?, ?, ?)");
                for (int a = 0; a < users.size(); a++) {
                    TLRPC.User user = users.get(a);
                    if (user.min) {
                        SQLiteCursor cursor = null;
                        try {
                            try {
                                cursor = this.database.queryFinalized(String.format(Locale.US, "SELECT data FROM users WHERE uid = %d", Integer.valueOf(user.id)), new Object[0]);
                                if (cursor.next() && (data = cursor.byteBufferValue(0)) != null) {
                                    TLRPC.User oldUser = TLRPC.User.TLdeserialize(data, data.readInt32(false), false);
                                    data.reuse();
                                    data = null;
                                    if (oldUser != null) {
                                        if (user.username != null) {
                                            oldUser.username = user.username;
                                            oldUser.flags |= 8;
                                        } else {
                                            oldUser.username = null;
                                            oldUser.flags &= -9;
                                        }
                                        if (user.photo != null) {
                                            oldUser.photo = user.photo;
                                            oldUser.flags |= 32;
                                        } else {
                                            oldUser.photo = null;
                                            oldUser.flags &= -33;
                                        }
                                        user = oldUser;
                                    }
                                }
                                cursor.dispose();
                                cursor = null;
                            } catch (Exception e) {
                                FileLog.e("putUsersInternal --->  exception 1 ", e);
                                if (data != null) {
                                    data.reuse();
                                }
                                if (cursor != null) {
                                }
                            }
                        } finally {
                            if (data != null) {
                                data.reuse();
                            }
                            if (cursor != null) {
                                cursor.dispose();
                            }
                        }
                    }
                    state2.requery();
                    NativeByteBuffer data2 = new NativeByteBuffer(user.getObjectSize());
                    user.serializeToStream(data2);
                    state2.bindInteger(1, user.id);
                    state2.bindString(2, formatUserSearchName(user));
                    if (user.status != null) {
                        if (user.status instanceof TLRPC.TL_userStatusRecently) {
                            user.status.expires = -100;
                        } else if (user.status instanceof TLRPC.TL_userStatusLastWeek) {
                            user.status.expires = -101;
                        } else if (user.status instanceof TLRPC.TL_userStatusLastMonth) {
                            user.status.expires = ScreenAudioCapturer.ERROR_AUDIO_RECORD_INIT_EXCEPTION;
                        }
                        state2.bindInteger(3, user.status.expires);
                    } else {
                        state2.bindInteger(3, 0);
                    }
                    state2.bindByteBuffer(4, data2);
                    state2.step();
                    data2.reuse();
                    data = null;
                }
                state2.dispose();
                state = null;
            } catch (Exception e2) {
                FileLog.e("putUsersInternal --->  exception 2 ", e2);
                throw new Exception(e2);
            }
        } finally {
            if (0 != 0) {
                data.reuse();
            }
            if (state != null) {
                state.dispose();
            }
        }
    }

    public void updateChatDefaultBannedRights(final int chatId, final TLRPC.TL_chatBannedRights rights, final int version) {
        if (rights == null || chatId == 0) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$hiwpslwPavNfcu1CSMpV1MVnRVg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateChatDefaultBannedRights$112$MessagesStorage(chatId, version, rights);
            }
        });
    }

    public /* synthetic */ void lambda$updateChatDefaultBannedRights$112$MessagesStorage(int chatId, int version, TLRPC.TL_chatBannedRights rights) {
        SQLiteCursor cursor = null;
        SQLitePreparedStatement state = null;
        NativeByteBuffer data = null;
        TLRPC.Chat chat = null;
        try {
            try {
                SQLiteCursor cursor2 = this.database.queryFinalized(String.format(Locale.US, "SELECT data FROM chats WHERE uid = %d", Integer.valueOf(chatId)), new Object[0]);
                if (cursor2.next() && (data = cursor2.byteBufferValue(0)) != null) {
                    chat = TLRPC.Chat.TLdeserialize(data, data.readInt32(false), false);
                    data.reuse();
                    data = null;
                }
                cursor2.dispose();
                cursor = null;
            } catch (Exception e) {
                FileLog.e("updateChatDefaultBannedRights ---> exception ", e);
                if (cursor != null) {
                    cursor.dispose();
                }
                if (state != null) {
                    state.dispose();
                }
                if (data == null) {
                    return;
                }
            }
            if (chat != null && (chat.default_banned_rights == null || version >= chat.version)) {
                chat.default_banned_rights = rights;
                chat.flags |= 262144;
                chat.version = version;
                state = this.database.executeFast("UPDATE chats SET data = ? WHERE uid = ?");
                NativeByteBuffer data2 = new NativeByteBuffer(chat.getObjectSize());
                chat.serializeToStream(data2);
                state.bindByteBuffer(1, data2);
                state.bindInteger(2, chat.id);
                state.step();
                data2.reuse();
                data = null;
                state.dispose();
                SQLitePreparedStatement state2 = null;
                if (0 != 0) {
                    cursor.dispose();
                }
                if (0 != 0) {
                    state2.dispose();
                }
                if (0 == 0) {
                    return;
                }
                data.reuse();
                return;
            }
            if (0 != 0) {
                cursor.dispose();
            }
            if (0 != 0) {
                state.dispose();
            }
            if (data != null) {
                data.reuse();
            }
        } catch (Throwable th) {
            if (cursor != null) {
                cursor.dispose();
            }
            if (state != null) {
                state.dispose();
            }
            if (data != null) {
                data.reuse();
            }
            throw th;
        }
    }

    private void putChatsInternal(ArrayList<TLRPC.Chat> chats) throws Exception {
        if (chats == null || chats.isEmpty()) {
            return;
        }
        NativeByteBuffer data = null;
        SQLitePreparedStatement state = null;
        try {
            try {
                SQLitePreparedStatement state2 = this.database.executeFast("REPLACE INTO chats VALUES(?, ?, ?)");
                for (int a = 0; a < chats.size(); a++) {
                    TLRPC.Chat chat = chats.get(a);
                    if (chat.min) {
                        SQLiteCursor cursor = null;
                        try {
                            try {
                                cursor = this.database.queryFinalized(String.format(Locale.US, "SELECT data FROM chats WHERE uid = %d", Integer.valueOf(chat.id)), new Object[0]);
                                if (cursor.next() && (data = cursor.byteBufferValue(0)) != null) {
                                    TLRPC.Chat oldChat = TLRPC.Chat.TLdeserialize(data, data.readInt32(false), false);
                                    data.reuse();
                                    data = null;
                                    if (oldChat != null) {
                                        oldChat.title = chat.title;
                                        oldChat.photo = chat.photo;
                                        oldChat.broadcast = chat.broadcast;
                                        oldChat.verified = chat.verified;
                                        oldChat.megagroup = chat.megagroup;
                                        if (chat.default_banned_rights != null) {
                                            oldChat.default_banned_rights = chat.default_banned_rights;
                                            oldChat.flags |= 262144;
                                        }
                                        if (chat.admin_rights != null) {
                                            oldChat.admin_rights = chat.admin_rights;
                                            oldChat.flags |= 16384;
                                        }
                                        if (chat.banned_rights != null) {
                                            oldChat.banned_rights = chat.banned_rights;
                                            oldChat.flags |= 32768;
                                        }
                                        if (chat.username != null) {
                                            oldChat.username = chat.username;
                                            oldChat.flags |= 64;
                                        } else {
                                            oldChat.username = null;
                                            oldChat.flags &= -65;
                                        }
                                        chat = oldChat;
                                    }
                                }
                                cursor.dispose();
                                cursor = null;
                            } catch (Exception e) {
                                FileLog.e("putChatsInternal --->  exception 1 ", e);
                                if (data != null) {
                                    data.reuse();
                                }
                                if (cursor != null) {
                                }
                            }
                        } finally {
                            if (data != null) {
                                data.reuse();
                            }
                            if (cursor != null) {
                                cursor.dispose();
                            }
                        }
                    }
                    state2.requery();
                    NativeByteBuffer data2 = new NativeByteBuffer(chat.getObjectSize());
                    chat.serializeToStream(data2);
                    state2.bindInteger(1, chat.id);
                    if (chat.title != null) {
                        String name = chat.title.toLowerCase();
                        state2.bindString(2, name);
                    } else {
                        state2.bindString(2, "");
                    }
                    state2.bindByteBuffer(3, data2);
                    state2.step();
                    data2.reuse();
                    data = null;
                }
                state2.dispose();
                state = null;
            } catch (Exception e2) {
                FileLog.e("putChatsInternal --->  exception 2 ", e2);
                throw new Exception(e2);
            }
        } finally {
            if (0 != 0) {
                data.reuse();
            }
            if (state != null) {
                state.dispose();
            }
        }
    }

    public void getUsersInternal(String usersToLoad, ArrayList<TLRPC.User> result) throws Exception {
        if (usersToLoad == null || usersToLoad.length() == 0 || result == null) {
            return;
        }
        SQLiteCursor cursor = null;
        try {
            try {
                SQLiteCursor cursor2 = this.database.queryFinalized(String.format(Locale.US, "SELECT data, status FROM users WHERE uid IN(%s)", usersToLoad), new Object[0]);
                while (cursor2.next()) {
                    NativeByteBuffer data = null;
                    try {
                        try {
                            data = cursor2.byteBufferValue(0);
                            if (data != null) {
                                TLRPC.User user = TLRPC.User.TLdeserialize(data, data.readInt32(false), false);
                                data.reuse();
                                data = null;
                                if (user != null) {
                                    if (user.status != null) {
                                        user.status.expires = cursor2.intValue(1);
                                    }
                                    result.add(user);
                                }
                            }
                        } catch (Exception e) {
                            FileLog.e("getUsersInternal ---> exception 1 ", e);
                            if (data != null) {
                            }
                        }
                        if (data != null) {
                            data.reuse();
                        }
                    } catch (Throwable th) {
                        if (data != null) {
                            data.reuse();
                        }
                        throw th;
                    }
                }
                cursor2.dispose();
                cursor = null;
            } finally {
                if (cursor != null) {
                    cursor.dispose();
                }
            }
        } catch (Exception e2) {
            FileLog.e("getUsersInternal ---> exception 2 ", e2);
            throw new Exception(e2);
        }
    }

    public void getChatsInternal(String chatsToLoad, ArrayList<TLRPC.Chat> result) throws Exception {
        if (chatsToLoad == null || chatsToLoad.length() == 0 || result == null) {
            return;
        }
        SQLiteCursor cursor = null;
        try {
            try {
                SQLiteCursor cursor2 = this.database.queryFinalized(String.format(Locale.US, "SELECT data FROM chats WHERE uid IN(%s)", chatsToLoad), new Object[0]);
                while (cursor2.next()) {
                    NativeByteBuffer data = null;
                    try {
                        try {
                            data = cursor2.byteBufferValue(0);
                            if (data != null) {
                                TLRPC.Chat chat = TLRPC.Chat.TLdeserialize(data, data.readInt32(false), false);
                                data.reuse();
                                data = null;
                                if (chat != null) {
                                    result.add(chat);
                                }
                            }
                        } catch (Exception e) {
                            FileLog.e("getChatsInternal ---> exception 1 ", e);
                            if (data != null) {
                            }
                        }
                        if (data != null) {
                            data.reuse();
                        }
                    } catch (Throwable th) {
                        if (data != null) {
                            data.reuse();
                        }
                        throw th;
                    }
                }
                cursor2.dispose();
                cursor = null;
            } catch (Exception e2) {
                FileLog.e("getChatsInternal ---> exception 2 ", e2);
                throw new Exception(e2);
            }
        } finally {
            if (cursor != null) {
                cursor.dispose();
            }
        }
    }

    public void getEncryptedChatsInternal(String chatsToLoad, ArrayList<TLRPC.EncryptedChat> result, ArrayList<Integer> usersToLoad) throws Exception {
        if (chatsToLoad == null || chatsToLoad.length() == 0 || result == null) {
            return;
        }
        SQLiteCursor cursor = null;
        try {
            try {
                SQLiteCursor cursor2 = this.database.queryFinalized(String.format(Locale.US, "SELECT data, user, g, authkey, ttl, layer, seq_in, seq_out, use_count, exchange_id, key_date, fprint, fauthkey, khash, in_seq_no, admin_id, mtproto_seq FROM enc_chats WHERE uid IN(%s)", chatsToLoad), new Object[0]);
                while (cursor2.next()) {
                    NativeByteBuffer data = null;
                    try {
                        try {
                            data = cursor2.byteBufferValue(0);
                            if (data != null) {
                                TLRPC.EncryptedChat chat = TLRPC.EncryptedChat.TLdeserialize(data, data.readInt32(false), false);
                                data.reuse();
                                data = null;
                                if (chat != null) {
                                    chat.user_id = cursor2.intValue(1);
                                    if (usersToLoad != null && !usersToLoad.contains(Integer.valueOf(chat.user_id))) {
                                        usersToLoad.add(Integer.valueOf(chat.user_id));
                                    }
                                    chat.a_or_b = cursor2.byteArrayValue(2);
                                    chat.auth_key = cursor2.byteArrayValue(3);
                                    chat.ttl = cursor2.intValue(4);
                                    chat.layer = cursor2.intValue(5);
                                    chat.seq_in = cursor2.intValue(6);
                                    chat.seq_out = cursor2.intValue(7);
                                    int use_count = cursor2.intValue(8);
                                    chat.key_use_count_in = (short) (use_count >> 16);
                                    chat.key_use_count_out = (short) use_count;
                                    chat.exchange_id = cursor2.longValue(9);
                                    chat.key_create_date = cursor2.intValue(10);
                                    chat.future_key_fingerprint = cursor2.longValue(11);
                                    chat.future_auth_key = cursor2.byteArrayValue(12);
                                    chat.key_hash = cursor2.byteArrayValue(13);
                                    chat.in_seq_no = cursor2.intValue(14);
                                    int admin_id = cursor2.intValue(15);
                                    if (admin_id != 0) {
                                        chat.admin_id = admin_id;
                                    }
                                    chat.mtproto_seq = cursor2.intValue(16);
                                    result.add(chat);
                                }
                            }
                        } catch (Throwable th) {
                            if (data != null) {
                                data.reuse();
                            }
                            throw th;
                        }
                    } catch (Exception e) {
                        FileLog.e("getEncryptedChatsInternal ---> exception 1 ", e);
                        if (data != null) {
                        }
                    }
                    if (data != null) {
                        data.reuse();
                    }
                }
                cursor2.dispose();
                cursor = null;
            } catch (Exception e2) {
                FileLog.e("getEncryptedChatsInternal ---> exception 2 ", e2);
                throw new Exception(e2);
            }
        } finally {
            if (cursor != null) {
                cursor.dispose();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: putUsersAndChatsInternal, reason: merged with bridge method [inline-methods] */
    public void lambda$putUsersAndChats$113$MessagesStorage(ArrayList<TLRPC.User> users, ArrayList<TLRPC.Chat> chats, boolean withTransaction) {
        try {
            if (withTransaction) {
                try {
                    this.database.beginTransaction();
                } catch (Exception e) {
                    FileLog.e("putUsersAndChatsInternal ---> exception 1 ", e);
                }
            }
            putUsersInternal(users);
            putChatsInternal(chats);
            if (withTransaction) {
                this.database.commitTransaction();
            }
        } catch (Exception e2) {
            FileLog.e("putUsersAndChatsInternal ---> exception 2 ", e2);
        }
    }

    public void putUsersAndChats(final ArrayList<TLRPC.User> users, final ArrayList<TLRPC.Chat> chats, final boolean withTransaction, boolean useQueue) {
        if (users != null && users.isEmpty() && chats != null && chats.isEmpty()) {
            return;
        }
        if (useQueue) {
            this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$a6oAj448JB5uqg8xBgXvxwE5qtg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$putUsersAndChats$113$MessagesStorage(users, chats, withTransaction);
                }
            });
        } else {
            lambda$putUsersAndChats$113$MessagesStorage(users, chats, withTransaction);
        }
    }

    public void removeFromDownloadQueue(final long id, final int type, final boolean move) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$O3XsETd1VNsVZqvzbXhktoUUuGY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$removeFromDownloadQueue$114$MessagesStorage(move, type, id);
            }
        });
    }

    public /* synthetic */ void lambda$removeFromDownloadQueue$114$MessagesStorage(boolean move, int type, long id) {
        SQLiteCursor cursor = null;
        SQLitePreparedStatement state = null;
        try {
            try {
                if (move) {
                    SQLiteCursor cursor2 = this.database.queryFinalized(String.format(Locale.US, "SELECT min(date) FROM download_queue WHERE type = %d", Integer.valueOf(type)), new Object[0]);
                    int minDate = cursor2.next() ? cursor2.intValue(0) : -1;
                    cursor2.dispose();
                    cursor = null;
                    if (minDate != -1) {
                        this.database.executeFast(String.format(Locale.US, "UPDATE download_queue SET date = %d WHERE uid = %d AND type = %d", Integer.valueOf(minDate - 1), Long.valueOf(id), Integer.valueOf(type))).stepThis().dispose();
                        state = null;
                    }
                } else {
                    this.database.executeFast(String.format(Locale.US, "DELETE FROM download_queue WHERE uid = %d AND type = %d", Long.valueOf(id), Integer.valueOf(type))).stepThis().dispose();
                    state = null;
                }
                if (cursor != null) {
                    cursor.dispose();
                }
                if (state == null) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("removeFromDownloadQueue ---> exception ", e);
                if (0 != 0) {
                    cursor.dispose();
                }
                if (0 == 0) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (0 != 0) {
                cursor.dispose();
            }
            if (0 != 0) {
                state.dispose();
            }
            throw th;
        }
    }

    public void clearDownloadQueue(final int type) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$llclWTod6JKgPiuxj-sdxDmRt9Q
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$clearDownloadQueue$115$MessagesStorage(type);
            }
        });
    }

    public /* synthetic */ void lambda$clearDownloadQueue$115$MessagesStorage(int type) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = type == 0 ? this.database.executeFast("DELETE FROM download_queue WHERE 1") : this.database.executeFast(String.format(Locale.US, "DELETE FROM download_queue WHERE type = %d", Integer.valueOf(type)));
                state.stepThis().dispose();
                state = null;
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("clearDownloadQueue ---> exception ", e);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void getDownloadQueue(final int type) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$5gAXykcciisN5zMoxmcUX6N1H-E
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getDownloadQueue$117$MessagesStorage(type);
            }
        });
    }

    public /* synthetic */ void lambda$getDownloadQueue$117$MessagesStorage(final int type) {
        SQLiteCursor cursor = null;
        NativeByteBuffer data = null;
        try {
            try {
                final ArrayList<DownloadObject> objects = new ArrayList<>();
                SQLiteCursor cursor2 = this.database.queryFinalized(String.format(Locale.US, "SELECT uid, type, data, parent FROM download_queue WHERE type = %d ORDER BY date DESC LIMIT 3", Integer.valueOf(type)), new Object[0]);
                while (cursor2.next()) {
                    DownloadObject downloadObject = new DownloadObject();
                    downloadObject.type = cursor2.intValue(1);
                    downloadObject.id = cursor2.longValue(0);
                    downloadObject.parent = cursor2.stringValue(3);
                    data = cursor2.byteBufferValue(2);
                    if (data != null) {
                        TLRPC.MessageMedia messageMedia = TLRPC.MessageMedia.TLdeserialize(data, data.readInt32(false), false);
                        data.reuse();
                        data = null;
                        if (messageMedia.document != null) {
                            downloadObject.object = messageMedia.document;
                        } else if (messageMedia.photo != null) {
                            downloadObject.object = messageMedia.photo;
                        }
                        downloadObject.secret = messageMedia.ttl_seconds > 0 && messageMedia.ttl_seconds <= 60;
                        downloadObject.forceCache = (messageMedia.flags & Integer.MIN_VALUE) != 0;
                    }
                    objects.add(downloadObject);
                }
                cursor2.dispose();
                cursor = null;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$q92VYAkXnnc9FuVmRmlrkhXYwLg
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$116$MessagesStorage(type, objects);
                    }
                });
                if (data != null) {
                    data.reuse();
                }
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("getDownloadQueue ---> exception ", e);
                if (data != null) {
                    data.reuse();
                }
                if (cursor == null) {
                    return;
                }
            }
            cursor.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (cursor != null) {
                cursor.dispose();
            }
            throw th;
        }
    }

    public /* synthetic */ void lambda$null$116$MessagesStorage(int type, ArrayList objects) {
        getDownloadController().processDownloadObjects(type, objects);
    }

    private int getMessageMediaType(TLRPC.Message message) {
        if (message instanceof TLRPC.TL_message_secret) {
            if ((((message.media instanceof TLRPC.TL_messageMediaPhoto) || MessageObject.isGifMessage(message)) && message.ttl > 0 && message.ttl <= 60) || MessageObject.isVoiceMessage(message) || MessageObject.isVideoMessage(message) || MessageObject.isRoundVideoMessage(message)) {
                return 1;
            }
            return ((message.media instanceof TLRPC.TL_messageMediaPhoto) || MessageObject.isVideoMessage(message)) ? 0 : -1;
        }
        if (!(message instanceof TLRPC.TL_message) || (!((message.media instanceof TLRPC.TL_messageMediaPhoto) || (message.media instanceof TLRPC.TL_messageMediaDocument)) || message.media.ttl_seconds == 0)) {
            return ((message.media instanceof TLRPC.TL_messageMediaPhoto) || MessageObject.isVideoMessage(message)) ? 0 : -1;
        }
        return 1;
    }

    public void putWebPages(final LongSparseArray<TLRPC.WebPage> webPages) {
        if (isEmpty(webPages)) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$LsgUYRdLUlmeMg3UZZbBfKqmezo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putWebPages$119$MessagesStorage(webPages);
            }
        });
    }

    public /* synthetic */ void lambda$putWebPages$119$MessagesStorage(LongSparseArray webPages) {
        final ArrayList<TLRPC.Message> messages;
        SQLiteCursor cursor = null;
        NativeByteBuffer data = null;
        SQLitePreparedStatement state = null;
        SQLitePreparedStatement state2 = null;
        try {
            try {
                messages = new ArrayList<>();
                for (int a = 0; a < webPages.size(); a++) {
                    SQLiteCursor cursor2 = this.database.queryFinalized("SELECT mid FROM webpage_pending WHERE id = " + webPages.keyAt(a), new Object[0]);
                    ArrayList<Long> mids = new ArrayList<>();
                    while (cursor2.next()) {
                        mids.add(Long.valueOf(cursor2.longValue(0)));
                    }
                    cursor2.dispose();
                    cursor = null;
                    if (!mids.isEmpty()) {
                        SQLiteCursor cursor3 = this.database.queryFinalized(String.format(Locale.US, "SELECT mid, data FROM messages WHERE mid IN (%s)", TextUtils.join(",", mids)), new Object[0]);
                        while (cursor3.next()) {
                            int mid = cursor3.intValue(0);
                            data = cursor3.byteBufferValue(1);
                            if (data != null) {
                                TLRPC.Message message = TLRPC.Message.TLdeserialize(data, data.readInt32(false), false);
                                message.readAttachPath(data, getUserConfig().clientUserId);
                                data.reuse();
                                data = null;
                                if (message.media instanceof TLRPC.TL_messageMediaWebPage) {
                                    message.id = mid;
                                    message.media.webpage = (TLRPC.WebPage) webPages.valueAt(a);
                                    messages.add(message);
                                }
                            }
                        }
                        cursor3.dispose();
                        cursor = null;
                    }
                }
            } catch (Throwable th) {
                if (data != null) {
                    data.reuse();
                }
                if (cursor != null) {
                    cursor.dispose();
                }
                if (state != null) {
                    state.dispose();
                }
                if (state2 != null) {
                    state2.dispose();
                }
                throw th;
            }
        } catch (Exception e) {
            FileLog.e("putWebPages ---> exception 2 ", e);
            if (data != null) {
                data.reuse();
            }
            if (cursor != null) {
                cursor.dispose();
            }
            if (state != null) {
                state.dispose();
            }
            if (state2 == null) {
                return;
            }
        }
        if (messages.isEmpty()) {
            if (data != null) {
                data.reuse();
            }
            if (cursor != null) {
                cursor.dispose();
            }
            if (0 != 0) {
                state.dispose();
            }
            if (0 != 0) {
                state2.dispose();
                return;
            }
            return;
        }
        try {
            this.database.beginTransaction();
        } catch (Exception e2) {
            FileLog.e("putWebPages ---> exception 1 ", e2);
        }
        SQLitePreparedStatement state3 = this.database.executeFast("UPDATE messages SET data = ? WHERE mid = ?");
        SQLitePreparedStatement state22 = this.database.executeFast("UPDATE media_v2 SET data = ? WHERE mid = ?");
        for (int a2 = 0; a2 < messages.size(); a2++) {
            TLRPC.Message message2 = messages.get(a2);
            NativeByteBuffer data2 = new NativeByteBuffer(message2.getObjectSize());
            message2.serializeToStream(data2);
            long messageId = message2.id;
            if (message2.to_id.channel_id != 0) {
                messageId |= ((long) message2.to_id.channel_id) << 32;
            }
            state3.requery();
            state3.bindByteBuffer(1, data2);
            state3.bindLong(2, messageId);
            state3.step();
            state22.requery();
            state22.bindByteBuffer(1, data2);
            state22.bindLong(2, messageId);
            state22.step();
            data2.reuse();
            data = null;
        }
        state3.dispose();
        state = null;
        state22.dispose();
        state2 = null;
        this.database.commitTransaction();
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$jyBnITFxcFxhDUF78NxIqJIu0_o
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$118$MessagesStorage(messages);
            }
        });
        if (data != null) {
            data.reuse();
        }
        if (cursor != null) {
            cursor.dispose();
        }
        if (0 != 0) {
            state.dispose();
        }
        if (0 == 0) {
            return;
        }
        state2.dispose();
    }

    public /* synthetic */ void lambda$null$118$MessagesStorage(ArrayList messages) {
        getNotificationCenter().postNotificationName(NotificationCenter.didReceivedWebpages, messages);
    }

    public void overwriteChannel(final int channel_id, final TLRPC.TL_updates_channelDifferenceTooLong difference, final int newDialogType) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$P6Ot-yngGvQvC2-ZV2TP3yge-qY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$overwriteChannel$121$MessagesStorage(channel_id, newDialogType, difference);
            }
        });
    }

    public /* synthetic */ void lambda$overwriteChannel$121$MessagesStorage(int channel_id, int newDialogType, TLRPC.TL_updates_channelDifferenceTooLong difference) {
        SQLiteCursor cursor = null;
        SQLitePreparedStatement state = null;
        boolean checkInvite = false;
        final long did = -channel_id;
        int pinned = 0;
        try {
            try {
                SQLiteCursor cursor2 = this.database.queryFinalized("SELECT pinned FROM dialogs WHERE did = " + did, new Object[0]);
                if (cursor2.next()) {
                    pinned = cursor2.intValue(0);
                } else if (newDialogType != 0) {
                    checkInvite = true;
                }
                cursor2.dispose();
                SQLiteCursor cursor3 = null;
                this.database.executeFast("DELETE FROM messages WHERE uid = " + did).stepThis().dispose();
                this.database.executeFast("DELETE FROM bot_keyboard WHERE uid = " + did).stepThis().dispose();
                this.database.executeFast("UPDATE media_counts_v2 SET old = 1 WHERE uid = " + did).stepThis().dispose();
                this.database.executeFast("DELETE FROM media_v2 WHERE uid = " + did).stepThis().dispose();
                this.database.executeFast("DELETE FROM messages_holes WHERE uid = " + did).stepThis().dispose();
                this.database.executeFast("DELETE FROM media_holes_v2 WHERE uid = " + did).stepThis().dispose();
                state = null;
                getMediaDataController().clearBotKeyboard(did, null);
                TLRPC.TL_messages_dialogs dialogs = new TLRPC.TL_messages_dialogs();
                dialogs.chats.addAll(difference.chats);
                dialogs.users.addAll(difference.users);
                dialogs.messages.addAll(difference.messages);
                TLRPC.Dialog dialog = difference.dialog;
                dialog.id = did;
                dialog.flags = 1;
                dialog.notify_settings = null;
                dialog.pinned = pinned != 0;
                dialog.pinnedNum = pinned;
                dialogs.dialogs.add(dialog);
                putDialogsInternal(dialogs, 0);
                updateDialogsWithDeletedMessages(new ArrayList<>(), null, false, channel_id);
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$oxMa5hs4nr4wZY7C0uz7BIxPYoQ
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$120$MessagesStorage(did);
                    }
                });
                if (checkInvite) {
                    if (newDialogType == 1) {
                        getMessagesController().checkChannelInviter(channel_id);
                    } else {
                        getMessagesController().generateJoinMessage(channel_id, false);
                    }
                }
                if (0 != 0) {
                    cursor3.dispose();
                }
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("overwriteChannel ---> exception ", e);
                if (0 != 0) {
                    cursor.dispose();
                }
                if (0 == 0) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (0 != 0) {
                cursor.dispose();
            }
            if (0 != 0) {
                state.dispose();
            }
            throw th;
        }
    }

    public /* synthetic */ void lambda$null$120$MessagesStorage(long did) {
        getNotificationCenter().postNotificationName(NotificationCenter.removeAllMessagesFromDialog, Long.valueOf(did), true);
    }

    public void putChannelViews(final SparseArray<SparseIntArray> channelViews, final boolean isChannel) {
        if (isEmpty(channelViews)) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$iNJ3fr-TtNLSbg13gZG-meafEJI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putChannelViews$122$MessagesStorage(channelViews, isChannel);
            }
        });
    }

    public /* synthetic */ void lambda$putChannelViews$122$MessagesStorage(SparseArray channelViews, boolean isChannel) {
        try {
            this.database.beginTransaction();
        } catch (Exception e) {
            FileLog.e("putChannelViews ---> exception 1 ", e);
        }
        SQLitePreparedStatement state = null;
        try {
            try {
                SQLitePreparedStatement state2 = this.database.executeFast("UPDATE messages SET media = max((SELECT media FROM messages WHERE mid = ?), ?) WHERE mid = ?");
                for (int a = 0; a < channelViews.size(); a++) {
                    int peer = channelViews.keyAt(a);
                    SparseIntArray messages = (SparseIntArray) channelViews.get(peer);
                    for (int b = 0; b < messages.size(); b++) {
                        int views = messages.get(messages.keyAt(b));
                        long messageId = messages.keyAt(b);
                        if (isChannel) {
                            messageId |= ((long) (-peer)) << 32;
                        }
                        state2.requery();
                        state2.bindLong(1, messageId);
                        state2.bindInteger(2, views);
                        state2.bindLong(3, messageId);
                        state2.step();
                    }
                }
                state2.dispose();
                state = null;
                this.database.commitTransaction();
                if (0 == 0) {
                    return;
                }
            } catch (Exception e2) {
                FileLog.e("putChannelViews ---> exception 2 ", e2);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    private boolean isValidKeyboardToSave(TLRPC.Message message) {
        return (message.reply_markup == null || (message.reply_markup instanceof TLRPC.TL_replyInlineMarkup) || (message.reply_markup.selective && !message.mentioned)) ? false : true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:1103:0x0c00 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:1165:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:1169:? A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:374:0x096d  */
    /* JADX WARN: Removed duplicated region for block: B:401:0x09f7  */
    /* JADX WARN: Removed duplicated region for block: B:418:0x0a6b A[Catch: all -> 0x0a31, Exception -> 0x0a45, TRY_ENTER, TRY_LEAVE, TryCatch #150 {Exception -> 0x0a45, all -> 0x0a31, blocks: (B:405:0x0a2a, B:418:0x0a6b), top: B:995:0x0a2a }] */
    /* JADX WARN: Removed duplicated region for block: B:420:0x0a73 A[Catch: all -> 0x0f4b, Exception -> 0x0f62, TRY_ENTER, TryCatch #134 {Exception -> 0x0f62, all -> 0x0f4b, blocks: (B:403:0x0a01, B:415:0x0a5b, B:421:0x0a7c, B:425:0x0a89, B:420:0x0a73), top: B:1027:0x0a01 }] */
    /* JADX WARN: Removed duplicated region for block: B:423:0x0a86  */
    /* JADX WARN: Removed duplicated region for block: B:424:0x0a88  */
    /* JADX WARN: Removed duplicated region for block: B:440:0x0aff  */
    /* JADX WARN: Removed duplicated region for block: B:443:0x0b09  */
    /* JADX WARN: Removed duplicated region for block: B:453:0x0b61  */
    /* JADX WARN: Removed duplicated region for block: B:456:0x0b69  */
    /* JADX WARN: Removed duplicated region for block: B:460:0x0b8e A[Catch: all -> 0x0f21, Exception -> 0x0f36, TRY_ENTER, TRY_LEAVE, TryCatch #157 {Exception -> 0x0f36, all -> 0x0f21, blocks: (B:441:0x0b03, B:454:0x0b63, B:460:0x0b8e), top: B:981:0x0b03 }] */
    /* JADX WARN: Removed duplicated region for block: B:488:0x0c35 A[Catch: all -> 0x0ea7, Exception -> 0x0ebd, TRY_ENTER, TryCatch #96 {Exception -> 0x0ebd, all -> 0x0ea7, blocks: (B:478:0x0c00, B:488:0x0c35, B:490:0x0c43, B:492:0x0c4e, B:501:0x0c6b, B:507:0x0c9a), top: B:1103:0x0c00 }] */
    /* JADX WARN: Removed duplicated region for block: B:580:0x0ed3  */
    /* JADX WARN: Removed duplicated region for block: B:924:0x19cf  */
    /* JADX WARN: Removed duplicated region for block: B:926:0x19d4  */
    /* JADX WARN: Removed duplicated region for block: B:928:0x19d9  */
    /* JADX WARN: Removed duplicated region for block: B:930:0x19de  */
    /* JADX WARN: Removed duplicated region for block: B:932:0x19e3  */
    /* JADX WARN: Removed duplicated region for block: B:934:0x19e8  */
    /* JADX WARN: Removed duplicated region for block: B:936:0x19ed  */
    /* JADX WARN: Removed duplicated region for block: B:938:0x19f2  */
    /* JADX WARN: Removed duplicated region for block: B:940:0x19f7  */
    /* JADX WARN: Removed duplicated region for block: B:942:0x19fc  */
    /* JADX WARN: Removed duplicated region for block: B:947:0x1a04  */
    /* JADX WARN: Removed duplicated region for block: B:949:0x1a09  */
    /* JADX WARN: Removed duplicated region for block: B:951:0x1a0e  */
    /* JADX WARN: Removed duplicated region for block: B:953:0x1a13  */
    /* JADX WARN: Removed duplicated region for block: B:955:0x1a18  */
    /* JADX WARN: Removed duplicated region for block: B:957:0x1a1d  */
    /* JADX WARN: Removed duplicated region for block: B:959:0x1a22  */
    /* JADX WARN: Removed duplicated region for block: B:961:0x1a27  */
    /* JADX WARN: Removed duplicated region for block: B:963:0x1a2c  */
    /* JADX WARN: Removed duplicated region for block: B:965:0x1a31  */
    /* JADX WARN: Removed duplicated region for block: B:985:0x0a99 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:995:0x0a2a A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX INFO: renamed from: putMessagesInternal, reason: merged with bridge method [inline-methods] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void lambda$putMessages$124$MessagesStorage(java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC.Message> r58, boolean r59, boolean r60, int r61, boolean r62, boolean r63) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 6709
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$putMessages$124$MessagesStorage(java.util.ArrayList, boolean, boolean, int, boolean, boolean):void");
    }

    public /* synthetic */ void lambda$putMessagesInternal$123$MessagesStorage(int downloadMediaMaskFinal) {
        getDownloadController().newDownloadObjectsAvailable(downloadMediaMaskFinal);
    }

    public void putMessages(ArrayList<TLRPC.Message> messages, boolean withTransaction, boolean useQueue, boolean doNotUpdateDialogDate, int downloadMask, boolean scheduled) {
        putMessages(messages, withTransaction, useQueue, doNotUpdateDialogDate, downloadMask, false, scheduled);
    }

    public void putMessages(final ArrayList<TLRPC.Message> messages, final boolean withTransaction, boolean useQueue, final boolean doNotUpdateDialogDate, final int downloadMask, final boolean ifNoLastMessage, final boolean scheduled) throws Throwable {
        if (messages.size() == 0) {
            return;
        }
        if (useQueue) {
            this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$cTXfOCiIHr50uw77M5Y4u5iIryY
                @Override // java.lang.Runnable
                public final void run() throws Throwable {
                    this.f$0.lambda$putMessages$124$MessagesStorage(messages, withTransaction, doNotUpdateDialogDate, downloadMask, ifNoLastMessage, scheduled);
                }
            });
        } else {
            lambda$putMessages$124$MessagesStorage(messages, withTransaction, doNotUpdateDialogDate, downloadMask, ifNoLastMessage, scheduled);
        }
    }

    public void markMessageAsSendError(final TLRPC.Message message, final boolean scheduled) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$OUaTFXlMWrNLHNMK53UuoFTH_SI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$markMessageAsSendError$125$MessagesStorage(message, scheduled);
            }
        });
    }

    public /* synthetic */ void lambda$markMessageAsSendError$125$MessagesStorage(TLRPC.Message message, boolean scheduled) {
        SQLitePreparedStatement state = null;
        try {
            try {
                long messageId = message.id;
                if (message.to_id.channel_id != 0) {
                    messageId |= ((long) message.to_id.channel_id) << 32;
                }
                if (scheduled) {
                    state = this.database.executeFast("UPDATE scheduled_messages SET send_state = 2 WHERE mid = " + messageId);
                } else {
                    state = this.database.executeFast("UPDATE messages SET send_state = 2 WHERE mid = " + messageId);
                }
                state.stepThis().dispose();
                state = null;
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("markMessageAsSendError ---> exception ", e);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void setMessageSeq(final int mid, final int seq_in, final int seq_out) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$5Uk9JbvzmXcGumweAOJKd3XfKc4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$setMessageSeq$126$MessagesStorage(mid, seq_in, seq_out);
            }
        });
    }

    public /* synthetic */ void lambda$setMessageSeq$126$MessagesStorage(int mid, int seq_in, int seq_out) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast("REPLACE INTO messages_seq VALUES(?, ?, ?)");
                state.requery();
                state.bindInteger(1, mid);
                state.bindInteger(2, seq_in);
                state.bindInteger(3, seq_out);
                state.step();
                state.dispose();
                state = null;
            } catch (Exception e) {
                FileLog.e("setMessageSeq ---> exception ", e);
                if (state != null) {
                }
            }
            if (0 != 0) {
                state.dispose();
            }
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:139:0x01d3  */
    /* JADX WARN: Removed duplicated region for block: B:157:0x0246 A[Catch: all -> 0x01fb, PHI: r11
      0x0246: PHI (r11v10 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement) = 
      (r11v8 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement)
      (r11v15 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement)
     binds: [B:167:0x025a, B:156:0x0244] A[DONT_GENERATE, DONT_INLINE], TRY_ENTER, TRY_LEAVE, TryCatch #19 {all -> 0x01fb, blocks: (B:143:0x01dc, B:157:0x0246, B:169:0x025d, B:224:0x0311, B:226:0x0315), top: B:290:0x01da, inners: #38 }] */
    /* JADX WARN: Removed duplicated region for block: B:171:0x0264  */
    /* JADX WARN: Removed duplicated region for block: B:175:0x0281  */
    /* JADX WARN: Removed duplicated region for block: B:186:0x02af A[Catch: all -> 0x0286, PHI: r11
      0x02af: PHI (r11v20 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement) = 
      (r11v18 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement)
      (r11v23 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement)
     binds: [B:196:0x02c1, B:185:0x02ad] A[DONT_GENERATE, DONT_INLINE], TRY_ENTER, TRY_LEAVE, TryCatch #27 {all -> 0x0286, blocks: (B:172:0x0267, B:186:0x02af, B:198:0x02c4, B:217:0x0304, B:219:0x0308), top: B:292:0x0267, inners: #28 }] */
    /* JADX WARN: Removed duplicated region for block: B:200:0x02cb  */
    /* JADX WARN: Removed duplicated region for block: B:204:0x02e8  */
    /* JADX WARN: Removed duplicated region for block: B:245:0x0365 A[Catch: all -> 0x033d, PHI: r11
      0x0365: PHI (r11v43 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement) = 
      (r11v41 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement)
      (r11v46 'state' im.uwrkaxlmjj.sqlite.SQLitePreparedStatement)
     binds: [B:255:0x0377, B:244:0x0363] A[DONT_GENERATE, DONT_INLINE], TRY_ENTER, TRY_LEAVE, TryCatch #21 {all -> 0x033d, blocks: (B:232:0x031f, B:245:0x0365, B:257:0x037a, B:261:0x0384, B:263:0x0388), top: B:291:0x031d, inners: #37 }] */
    /* JADX WARN: Removed duplicated region for block: B:259:0x0381  */
    /* JADX WARN: Removed duplicated region for block: B:272:0x03a3  */
    /* JADX WARN: Removed duplicated region for block: B:277:0x03ac  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0060  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00b6 A[PHI: r4 r6 r9
      0x00b6: PHI (r4v4 'scheduled' int) = (r4v3 'scheduled' int), (r4v13 'scheduled' int) binds: [B:68:0x00ee, B:49:0x00b4] A[DONT_GENERATE, DONT_INLINE]
      0x00b6: PHI (r6v12 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor) = (r6v11 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor), (r6v17 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor) binds: [B:68:0x00ee, B:49:0x00b4] A[DONT_GENERATE, DONT_INLINE]
      0x00b6: PHI (r9v3 'did' long) = (r9v2 'did' long), (r9v4 'did' long) binds: [B:68:0x00ee, B:49:0x00b4] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:88:0x012f A[PHI: r4 r6 r9
      0x012f: PHI (r4v19 'scheduled' int) = (r4v18 'scheduled' int), (r4v29 'scheduled' int) binds: [B:110:0x0176, B:87:0x012d] A[DONT_GENERATE, DONT_INLINE]
      0x012f: PHI (r6v21 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor) = (r6v20 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor), (r6v26 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor) binds: [B:110:0x0176, B:87:0x012d] A[DONT_GENERATE, DONT_INLINE]
      0x012f: PHI (r9v8 'did' long) = (r9v7 'did' long), (r9v9 'did' long) binds: [B:110:0x0176, B:87:0x012d] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX INFO: renamed from: updateMessageStateAndIdInternal, reason: merged with bridge method [inline-methods] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public long[] lambda$updateMessageStateAndId$127$MessagesStorage(long r21, java.lang.Integer r23, int r24, int r25, int r26, int r27) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 944
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$updateMessageStateAndId$127$MessagesStorage(long, java.lang.Integer, int, int, int, int):long[]");
    }

    public long[] updateMessageStateAndId(final long random_id, final Integer _oldId, final int newId, final int date, boolean useQueue, final int channelId, final int scheduled) {
        if (!useQueue) {
            return lambda$updateMessageStateAndId$127$MessagesStorage(random_id, _oldId, newId, date, channelId, scheduled);
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$jdPgCcqsrPpp38a7c2ZM22kXCmA
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$updateMessageStateAndId$127$MessagesStorage(random_id, _oldId, newId, date, channelId, scheduled);
            }
        });
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: updateUsersInternal, reason: merged with bridge method [inline-methods] */
    public void lambda$updateUsers$128$MessagesStorage(ArrayList<TLRPC.User> users, boolean onlyStatus, boolean withTransaction) {
        SQLitePreparedStatement state = null;
        try {
            try {
                if (onlyStatus) {
                    if (withTransaction) {
                        try {
                            this.database.beginTransaction();
                        } catch (Exception e) {
                            FileLog.e("updateUsersInternal ---> exception 1 ", e);
                        }
                    }
                    SQLitePreparedStatement state2 = this.database.executeFast("UPDATE users SET status = ? WHERE uid = ?");
                    int N = users.size();
                    for (int a = 0; a < N; a++) {
                        TLRPC.User user = users.get(a);
                        state2.requery();
                        if (user.status != null) {
                            state2.bindInteger(1, user.status.expires);
                        } else {
                            state2.bindInteger(1, 0);
                        }
                        state2.bindInteger(2, user.id);
                        state2.step();
                    }
                    state2.dispose();
                    state = null;
                    if (withTransaction) {
                        this.database.commitTransaction();
                    }
                } else {
                    StringBuilder ids = new StringBuilder();
                    SparseArray<TLRPC.User> usersDict = new SparseArray<>();
                    int N2 = users.size();
                    for (int a2 = 0; a2 < N2; a2++) {
                        TLRPC.User user2 = users.get(a2);
                        if (ids.length() != 0) {
                            ids.append(",");
                        }
                        ids.append(user2.id);
                        usersDict.put(user2.id, user2);
                    }
                    ArrayList<TLRPC.User> loadedUsers = new ArrayList<>();
                    getUsersInternal(ids.toString(), loadedUsers);
                    int N3 = loadedUsers.size();
                    for (int a3 = 0; a3 < N3; a3++) {
                        TLRPC.User user3 = loadedUsers.get(a3);
                        TLRPC.User updateUser = usersDict.get(user3.id);
                        if (updateUser != null) {
                            if (updateUser.first_name != null && updateUser.last_name != null) {
                                if (!UserObject.isContact(user3)) {
                                    user3.first_name = updateUser.first_name;
                                    user3.last_name = updateUser.last_name;
                                }
                                user3.username = updateUser.username;
                            } else if (updateUser.photo != null) {
                                user3.photo = updateUser.photo;
                            } else if (updateUser.phone != null) {
                                user3.phone = updateUser.phone;
                            }
                        }
                    }
                    if (!loadedUsers.isEmpty()) {
                        if (withTransaction) {
                            try {
                                this.database.beginTransaction();
                            } catch (Exception e2) {
                                FileLog.e("updateUsersInternal ---> exception 2 ", e2);
                            }
                        }
                        putUsersInternal(loadedUsers);
                        if (withTransaction) {
                            this.database.commitTransaction();
                        }
                    }
                }
                if (state == null) {
                    return;
                }
            } catch (Exception e3) {
                FileLog.e("updateUsersInternal ---> exception 3 ", e3);
                if (0 == 0) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (0 != 0) {
                state.dispose();
            }
            throw th;
        }
    }

    public void updateUsers(final ArrayList<TLRPC.User> users, final boolean onlyStatus, final boolean withTransaction, boolean useQueue) {
        if (users == null || users.isEmpty()) {
            return;
        }
        if (useQueue) {
            this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$h9e1_FqVOt0LcjS2ffsICpzuSiw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$updateUsers$128$MessagesStorage(users, onlyStatus, withTransaction);
                }
            });
        } else {
            lambda$updateUsers$128$MessagesStorage(users, onlyStatus, withTransaction);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: markMessagesAsReadInternal, reason: merged with bridge method [inline-methods] */
    public void lambda$markMessagesAsRead$130$MessagesStorage(SparseLongArray inbox, SparseLongArray outbox, SparseIntArray encryptedMessages) {
        SQLitePreparedStatement state = null;
        SQLitePreparedStatement state1 = null;
        try {
            try {
                if (!isEmpty(inbox)) {
                    SQLitePreparedStatement state2 = this.database.executeFast("DELETE FROM unread_push_messages WHERE uid = ? AND mid <= ?");
                    for (int b = 0; b < inbox.size(); b++) {
                        int key = inbox.keyAt(b);
                        long messageId = inbox.get(key);
                        this.database.executeFast(String.format(Locale.US, "UPDATE messages SET read_state = read_state | 1 WHERE uid = %d AND mid > 0 AND mid <= %d AND read_state IN(0,2) AND out = 0", Integer.valueOf(key), Long.valueOf(messageId))).stepThis().dispose();
                        state1 = null;
                        state2.requery();
                        state2.bindLong(1, key);
                        state2.bindLong(2, messageId);
                        state2.step();
                    }
                    state2.dispose();
                    state = null;
                }
                if (!isEmpty(outbox)) {
                    for (int b2 = 0; b2 < outbox.size(); b2++) {
                        int key2 = outbox.keyAt(b2);
                        this.database.executeFast(String.format(Locale.US, "UPDATE messages SET read_state = read_state | 1 WHERE uid = %d AND mid > 0 AND mid <= %d AND read_state IN(0,2) AND out = 1", Integer.valueOf(key2), Long.valueOf(outbox.get(key2)))).stepThis().dispose();
                        state = null;
                    }
                }
                if (encryptedMessages != null && !isEmpty(encryptedMessages)) {
                    for (int a = 0; a < encryptedMessages.size(); a++) {
                        long dialog_id = ((long) encryptedMessages.keyAt(a)) << 32;
                        int max_date = encryptedMessages.valueAt(a);
                        SQLitePreparedStatement state3 = this.database.executeFast("UPDATE messages SET read_state = read_state | 1 WHERE uid = ? AND date <= ? AND read_state IN(0,2) AND out = 1");
                        state3.requery();
                        state3.bindLong(1, dialog_id);
                        state3.bindInteger(2, max_date);
                        state3.step();
                        state3.dispose();
                        state = null;
                    }
                }
                if (state != null) {
                    state.dispose();
                }
                if (state1 == null) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("markMessagesAsReadInternal ---> exception ", e);
                if (state != null) {
                    state.dispose();
                }
                if (state1 == null) {
                    return;
                }
            }
            state1.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            if (state1 != null) {
                state1.dispose();
            }
            throw th;
        }
    }

    public void markMessagesContentAsRead(final ArrayList<Long> mids, final int date) {
        if (isEmpty(mids)) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$MZlKA48BK-mlcbWn8Ib1yyzYnhM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$markMessagesContentAsRead$129$MessagesStorage(mids, date);
            }
        });
    }

    public /* synthetic */ void lambda$markMessagesContentAsRead$129$MessagesStorage(ArrayList mids, int date) {
        SQLitePreparedStatement state = null;
        SQLiteCursor cursor = null;
        try {
            try {
                String midsStr = TextUtils.join(",", mids);
                this.database.executeFast(String.format(Locale.US, "UPDATE messages SET read_state = read_state | 2 WHERE mid IN (%s)", midsStr)).stepThis().dispose();
                state = null;
                if (date != 0) {
                    cursor = this.database.queryFinalized(String.format(Locale.US, "SELECT mid, ttl FROM messages WHERE mid IN (%s) AND ttl > 0", midsStr), new Object[0]);
                    ArrayList<Integer> arrayList = null;
                    while (cursor.next()) {
                        if (arrayList == null) {
                            arrayList = new ArrayList<>();
                        }
                        arrayList.add(Integer.valueOf(cursor.intValue(0)));
                    }
                    if (arrayList != null) {
                        emptyMessagesMedia(arrayList);
                    }
                    cursor.dispose();
                    cursor = null;
                }
                if (0 != 0) {
                    state.dispose();
                }
                if (cursor == null) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("markMessagesContentAsRead ---> exception ", e);
                if (state != null) {
                    state.dispose();
                }
                if (cursor == null) {
                    return;
                }
            }
            cursor.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            if (cursor != null) {
                cursor.dispose();
            }
            throw th;
        }
    }

    public void markMessagesAsRead(final SparseLongArray inbox, final SparseLongArray outbox, final SparseIntArray encryptedMessages, boolean useQueue) {
        if (useQueue) {
            this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$fY1m-K4f2cbIZFHT2Isgtl72HxA
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$markMessagesAsRead$130$MessagesStorage(inbox, outbox, encryptedMessages);
                }
            });
        } else {
            lambda$markMessagesAsRead$130$MessagesStorage(inbox, outbox, encryptedMessages);
        }
    }

    public void markMessagesAsDeletedByRandoms(final ArrayList<Long> messages) {
        if (messages.isEmpty()) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$EgJjzBR7n0iwtlr5FhO730HrHnk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$markMessagesAsDeletedByRandoms$132$MessagesStorage(messages);
            }
        });
    }

    public /* synthetic */ void lambda$markMessagesAsDeletedByRandoms$132$MessagesStorage(ArrayList messages) {
        SQLiteCursor cursor = null;
        try {
            try {
                String ids = TextUtils.join(",", messages);
                SQLiteCursor cursor2 = this.database.queryFinalized(String.format(Locale.US, "SELECT mid FROM randoms WHERE random_id IN(%s)", ids), new Object[0]);
                final ArrayList<Integer> mids = new ArrayList<>();
                while (cursor2.next()) {
                    mids.add(Integer.valueOf(cursor2.intValue(0)));
                }
                cursor2.dispose();
                cursor = null;
                if (!mids.isEmpty()) {
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$Q9r6hgeZ6Ym8FSj2dzo47Fy5jA0
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$null$131$MessagesStorage(mids);
                        }
                    });
                    updateDialogsWithReadMessagesInternal(mids, null, null, null);
                    lambda$markMessagesAsDeleted$135$MessagesStorage(mids, 0, true, false);
                    lambda$updateDialogsWithDeletedMessages$134$MessagesStorage(mids, null, 0);
                }
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("markMessagesAsDeletedByRandoms ---> exception ", e);
                if (cursor == null) {
                    return;
                }
            }
            cursor.dispose();
        } catch (Throwable th) {
            if (cursor != null) {
                cursor.dispose();
            }
            throw th;
        }
    }

    public /* synthetic */ void lambda$null$131$MessagesStorage(ArrayList mids) {
        getNotificationCenter().postNotificationName(NotificationCenter.messagesDeleted, mids, 0, false);
    }

    protected void deletePushMessages(long dialogId, ArrayList<Integer> messages) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast(String.format(Locale.US, "DELETE FROM unread_push_messages WHERE uid = %d AND mid IN(%s)", Long.valueOf(dialogId), TextUtils.join(",", messages)));
                state.stepThis().dispose();
                state = null;
            } catch (Exception e) {
                FileLog.e("deletePushMessages ---> exception ", e);
                if (state != null) {
                }
            }
            if (0 != 0) {
                state.dispose();
            }
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    private void broadcastScheduledMessagesChange(final Long did) {
        SQLiteCursor cursor = null;
        try {
            try {
                SQLiteCursor cursor2 = this.database.queryFinalized(String.format(Locale.US, "SELECT COUNT(mid) FROM scheduled_messages WHERE uid = %d", did), new Object[0]);
                final int count = cursor2.next() ? cursor2.intValue(0) : 0;
                cursor2.dispose();
                cursor = null;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$-exooRVUV0JeazjXjSxqOEZHYGM
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$broadcastScheduledMessagesChange$133$MessagesStorage(did, count);
                    }
                });
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("broadcastScheduledMessagesChange ---> exception ", e);
                if (cursor == null) {
                    return;
                }
            }
            cursor.dispose();
        } catch (Throwable th) {
            if (cursor != null) {
                cursor.dispose();
            }
            throw th;
        }
    }

    public /* synthetic */ void lambda$broadcastScheduledMessagesChange$133$MessagesStorage(Long did, int count) {
        getNotificationCenter().postNotificationName(NotificationCenter.scheduledMessagesUpdated, did, Integer.valueOf(count));
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:128:0x0382 A[Catch: all -> 0x0568, Exception -> 0x0574, TRY_LEAVE, TryCatch #33 {Exception -> 0x0574, all -> 0x0568, blocks: (B:112:0x0279, B:121:0x02b3, B:126:0x0304, B:128:0x0382, B:153:0x041e), top: B:268:0x0279 }] */
    /* JADX WARN: Removed duplicated region for block: B:168:0x04cb  */
    /* JADX WARN: Removed duplicated region for block: B:180:0x0532  */
    /* JADX WARN: Removed duplicated region for block: B:182:0x0537  */
    /* JADX WARN: Removed duplicated region for block: B:184:0x053c  */
    /* JADX WARN: Removed duplicated region for block: B:240:0x060c  */
    /* JADX WARN: Removed duplicated region for block: B:242:0x0611  */
    /* JADX WARN: Removed duplicated region for block: B:244:0x0616  */
    /* JADX WARN: Removed duplicated region for block: B:250:0x061f  */
    /* JADX WARN: Removed duplicated region for block: B:252:0x0624  */
    /* JADX WARN: Removed duplicated region for block: B:254:0x0629  */
    /* JADX WARN: Removed duplicated region for block: B:272:0x0266 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:274:0x0233 A[EXC_TOP_SPLITTER, PHI: r18
      0x0233: PHI (r18v12 'data' im.uwrkaxlmjj.tgnet.NativeByteBuffer) = (r18v16 'data' im.uwrkaxlmjj.tgnet.NativeByteBuffer), (r18v11 'data' im.uwrkaxlmjj.tgnet.NativeByteBuffer) binds: [B:102:0x0250, B:94:0x0231] A[DONT_GENERATE, DONT_INLINE], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:286:0x05d9 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:321:? A[Catch: all -> 0x05de, Exception -> 0x05e2, SYNTHETIC, TRY_LEAVE, TryCatch #24 {Exception -> 0x05e2, all -> 0x05de, blocks: (B:221:0x05d9, B:223:0x05dd), top: B:286:0x05d9 }] */
    /* JADX WARN: Removed duplicated region for block: B:322:? A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:323:? A[RETURN, SYNTHETIC] */
    /* JADX INFO: renamed from: markMessagesAsDeletedInternal, reason: merged with bridge method [inline-methods] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.util.ArrayList<java.lang.Long> lambda$markMessagesAsDeleted$135$MessagesStorage(java.util.ArrayList<java.lang.Integer> r31, int r32, boolean r33, boolean r34) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 1581
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$markMessagesAsDeleted$135$MessagesStorage(java.util.ArrayList, int, boolean, boolean):java.util.ArrayList");
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:154:0x0321  */
    /* JADX WARN: Removed duplicated region for block: B:156:0x0326  */
    /* JADX WARN: Removed duplicated region for block: B:158:0x032b  */
    /* JADX WARN: Removed duplicated region for block: B:162:0x0332  */
    /* JADX WARN: Removed duplicated region for block: B:164:0x0337  */
    /* JADX WARN: Removed duplicated region for block: B:166:0x033c  */
    /* JADX WARN: Removed duplicated region for block: B:202:? A[RETURN, SYNTHETIC] */
    /* JADX INFO: renamed from: updateDialogsWithDeletedMessagesInternal, reason: merged with bridge method [inline-methods] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void lambda$updateDialogsWithDeletedMessages$134$MessagesStorage(java.util.ArrayList<java.lang.Integer> r25, java.util.ArrayList<java.lang.Long> r26, int r27) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 832
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$updateDialogsWithDeletedMessages$134$MessagesStorage(java.util.ArrayList, java.util.ArrayList, int):void");
    }

    public void updateDialogsWithDeletedMessages(final ArrayList<Integer> messages, final ArrayList<Long> additionalDialogsToUpdate, boolean useQueue, final int channelId) {
        if (messages.isEmpty() && channelId == 0) {
            return;
        }
        if (useQueue) {
            this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$Bx4TgDx_xdNoYxOBAffV2FV4D8I
                @Override // java.lang.Runnable
                public final void run() throws Throwable {
                    this.f$0.lambda$updateDialogsWithDeletedMessages$134$MessagesStorage(messages, additionalDialogsToUpdate, channelId);
                }
            });
        } else {
            lambda$updateDialogsWithDeletedMessages$134$MessagesStorage(messages, additionalDialogsToUpdate, channelId);
        }
    }

    public ArrayList<Long> markMessagesAsDeleted(final ArrayList<Integer> messages, boolean useQueue, final int channelId, final boolean deleteFiles, final boolean scheduled) {
        if (messages.isEmpty()) {
            return null;
        }
        if (useQueue) {
            this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$9xT_43Wpl62bGlliKxKzakku8ug
                @Override // java.lang.Runnable
                public final void run() throws Throwable {
                    this.f$0.lambda$markMessagesAsDeleted$135$MessagesStorage(messages, channelId, deleteFiles, scheduled);
                }
            });
            return null;
        }
        return lambda$markMessagesAsDeleted$135$MessagesStorage(messages, channelId, deleteFiles, scheduled);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:109:0x02a9  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x02ae  */
    /* JADX WARN: Removed duplicated region for block: B:113:0x02b3  */
    /* JADX WARN: Removed duplicated region for block: B:137:0x0301 A[Catch: all -> 0x02f9, Exception -> 0x02fc, TryCatch #28 {Exception -> 0x02fc, all -> 0x02f9, blocks: (B:131:0x02f5, B:137:0x0301, B:139:0x0305), top: B:176:0x02f5 }] */
    /* JADX WARN: Removed duplicated region for block: B:150:0x0334  */
    /* JADX WARN: Removed duplicated region for block: B:152:0x0339  */
    /* JADX WARN: Removed duplicated region for block: B:154:0x033e  */
    /* JADX WARN: Removed duplicated region for block: B:159:0x0346  */
    /* JADX WARN: Removed duplicated region for block: B:161:0x034b  */
    /* JADX WARN: Removed duplicated region for block: B:163:0x0350  */
    /* JADX WARN: Removed duplicated region for block: B:176:0x02f5 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:194:0x0143 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:70:0x015d A[Catch: all -> 0x0147, Exception -> 0x0151, TRY_LEAVE, TryCatch #19 {Exception -> 0x0151, all -> 0x0147, blocks: (B:64:0x0143, B:70:0x015d), top: B:194:0x0143 }] */
    /* JADX WARN: Removed duplicated region for block: B:76:0x0170 A[Catch: all -> 0x02c5, Exception -> 0x02d0, TRY_LEAVE, TryCatch #23 {Exception -> 0x02d0, all -> 0x02c5, blocks: (B:74:0x016a, B:76:0x0170), top: B:186:0x016a }] */
    /* JADX INFO: renamed from: markMessagesAsDeletedInternal, reason: merged with bridge method [inline-methods] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.util.ArrayList<java.lang.Long> lambda$markMessagesAsDeleted$136$MessagesStorage(int r25, int r26, boolean r27) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 852
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$markMessagesAsDeleted$136$MessagesStorage(int, int, boolean):java.util.ArrayList");
    }

    public ArrayList<Long> markMessagesAsDeleted(final int channelId, final int mid, boolean useQueue, final boolean deleteFiles) {
        if (useQueue) {
            this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$3paJyHNSkFEA8WQ7GuHVRhhPEXk
                @Override // java.lang.Runnable
                public final void run() throws Throwable {
                    this.f$0.lambda$markMessagesAsDeleted$136$MessagesStorage(channelId, mid, deleteFiles);
                }
            });
            return null;
        }
        return lambda$markMessagesAsDeleted$136$MessagesStorage(channelId, mid, deleteFiles);
    }

    private void fixUnsupportedMedia(TLRPC.Message message) {
        if (message == null) {
            return;
        }
        if (message.media instanceof TLRPC.TL_messageMediaUnsupported_old) {
            if (message.media.bytes.length == 0) {
                message.media.bytes = new byte[1];
                message.media.bytes[0] = 105;
                return;
            }
            return;
        }
        if (message.media instanceof TLRPC.TL_messageMediaUnsupported) {
            message.media = new TLRPC.TL_messageMediaUnsupported_old();
            message.media.bytes = new byte[1];
            message.media.bytes[0] = 105;
            message.flags |= 512;
        }
    }

    private void doneHolesInTable(String table, long did, int max_id) throws Exception {
        SQLitePreparedStatement state;
        SQLitePreparedStatement state2 = null;
        try {
            try {
                if (max_id == 0) {
                    state = this.database.executeFast(String.format(Locale.US, "DELETE FROM " + table + " WHERE uid = %d", Long.valueOf(did)));
                } else {
                    state = this.database.executeFast(String.format(Locale.US, "DELETE FROM " + table + " WHERE uid = %d AND start = 0", Long.valueOf(did)));
                }
                state.stepThis().dispose();
                state2 = this.database.executeFast("REPLACE INTO " + table + " VALUES(?, ?, ?)");
                state2.requery();
                state2.bindLong(1, did);
                state2.bindInteger(2, 1);
                state2.bindInteger(3, 1);
                state2.step();
                state2.dispose();
                state2 = null;
            } catch (Exception e) {
                FileLog.e("doneHolesInTable ---> exception ", e);
                throw new Exception(e);
            }
        } finally {
            if (state2 != null) {
                state2.dispose();
            }
        }
    }

    public void doneHolesInMedia(long did, int max_id, int type) throws Exception {
        SQLitePreparedStatement state;
        SQLitePreparedStatement state2;
        SQLitePreparedStatement state3;
        SQLitePreparedStatement state4 = null;
        try {
            try {
                if (type == -1) {
                    if (max_id == 0) {
                        state3 = this.database.executeFast(String.format(Locale.US, "DELETE FROM media_holes_v2 WHERE uid = %d", Long.valueOf(did)));
                    } else {
                        state3 = this.database.executeFast(String.format(Locale.US, "DELETE FROM media_holes_v2 WHERE uid = %d AND start = 0", Long.valueOf(did)));
                    }
                    state3.stepThis().dispose();
                    SQLitePreparedStatement state5 = this.database.executeFast("REPLACE INTO media_holes_v2 VALUES(?, ?, ?, ?)");
                    for (int a = 0; a < 5; a++) {
                        state5.requery();
                        state5.bindLong(1, did);
                        state5.bindInteger(2, a);
                        state5.bindInteger(3, 1);
                        state5.bindInteger(4, 1);
                        state5.step();
                    }
                    state5.dispose();
                    state2 = null;
                } else {
                    if (max_id == 0) {
                        state = this.database.executeFast(String.format(Locale.US, "DELETE FROM media_holes_v2 WHERE uid = %d AND type = %d", Long.valueOf(did), Integer.valueOf(type)));
                    } else {
                        state = this.database.executeFast(String.format(Locale.US, "DELETE FROM media_holes_v2 WHERE uid = %d AND type = %d AND start = 0", Long.valueOf(did), Integer.valueOf(type)));
                    }
                    state.stepThis().dispose();
                    SQLitePreparedStatement state6 = this.database.executeFast("REPLACE INTO media_holes_v2 VALUES(?, ?, ?, ?)");
                    state6.requery();
                    state6.bindLong(1, did);
                    state6.bindInteger(2, type);
                    state6.bindInteger(3, 1);
                    state6.bindInteger(4, 1);
                    state6.step();
                    state6.dispose();
                    state2 = null;
                }
            } catch (Exception e) {
                FileLog.e("doneHolesInMedia ---> exception ", e);
                throw new Exception(e);
            }
        } finally {
            if (state4 != null) {
                state4.dispose();
            }
        }
    }

    private static class Hole {
        public int end;
        public int start;
        public int type;

        public Hole(int s, int e) {
            this.start = s;
            this.end = e;
        }

        public Hole(int t, int s, int e) {
            this.type = t;
            this.start = s;
            this.end = e;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:86:0x025a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void closeHolesInMedia(long r25, int r27, int r28, int r29) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 793
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.closeHolesInMedia(long, int, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:100:0x02df  */
    /* JADX WARN: Removed duplicated region for block: B:136:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0202  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x02d0  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x02da  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void closeHolesInTable(java.lang.String r23, long r24, int r26, int r27) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 739
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.closeHolesInTable(java.lang.String, long, int, int):void");
    }

    public void replaceMessageIfExists(final TLRPC.Message message, final int currentAccount, final ArrayList<TLRPC.User> users, final ArrayList<TLRPC.Chat> chats, final boolean broadcast) {
        if (message == null) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$5hj-ZcOrRNJkKe792YHuOASgE2E
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$replaceMessageIfExists$138$MessagesStorage(message, broadcast, users, chats, currentAccount);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:111:0x0203  */
    /* JADX WARN: Removed duplicated region for block: B:113:0x0208  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x020d  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x0212  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x021c  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x0221  */
    /* JADX WARN: Removed duplicated region for block: B:125:0x0226  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x022b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$replaceMessageIfExists$138$MessagesStorage(im.uwrkaxlmjj.tgnet.TLRPC.Message r20, boolean r21, java.util.ArrayList r22, java.util.ArrayList r23, int r24) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 559
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$replaceMessageIfExists$138$MessagesStorage(im.uwrkaxlmjj.tgnet.TLRPC$Message, boolean, java.util.ArrayList, java.util.ArrayList, int):void");
    }

    public /* synthetic */ void lambda$null$137$MessagesStorage(MessageObject messageObject, ArrayList arrayList) {
        getNotificationCenter().postNotificationName(NotificationCenter.replaceMessagesObjects, Long.valueOf(messageObject.getDialogId()), arrayList);
    }

    public void putMessages(final TLRPC.messages_Messages messages, final long dialog_id, final int load_type, final int max_id, final boolean createDialog, final boolean scheduled) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$6m8JZc8F3_Wgqy6gEv2xp9CjLAA
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$putMessages$139$MessagesStorage(scheduled, dialog_id, messages, load_type, max_id, createDialog);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:116:0x02a2  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x02a9  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x032b A[Catch: all -> 0x03bd, Exception -> 0x03cd, TryCatch #59 {Exception -> 0x03cd, all -> 0x03bd, blocks: (B:129:0x02f7, B:140:0x0327, B:142:0x032b, B:144:0x0332, B:146:0x0338, B:148:0x033e, B:150:0x0344), top: B:522:0x02f7 }] */
    /* JADX WARN: Removed duplicated region for block: B:179:0x03b8  */
    /* JADX WARN: Removed duplicated region for block: B:248:0x054c  */
    /* JADX WARN: Removed duplicated region for block: B:296:0x06bb  */
    /* JADX WARN: Removed duplicated region for block: B:310:0x0712  */
    /* JADX WARN: Removed duplicated region for block: B:364:0x0820  */
    /* JADX WARN: Removed duplicated region for block: B:394:0x08e8 A[Catch: Exception -> 0x096a, all -> 0x09e6, TryCatch #2 {Exception -> 0x096a, blocks: (B:391:0x08c5, B:392:0x08cc, B:394:0x08e8, B:395:0x0926, B:397:0x092d), top: B:485:0x08c5 }] */
    /* JADX WARN: Removed duplicated region for block: B:397:0x092d A[Catch: Exception -> 0x096a, all -> 0x09e6, TRY_LEAVE, TryCatch #2 {Exception -> 0x096a, blocks: (B:391:0x08c5, B:392:0x08cc, B:394:0x08e8, B:395:0x0926, B:397:0x092d), top: B:485:0x08c5 }] */
    /* JADX WARN: Removed duplicated region for block: B:399:0x0938  */
    /* JADX WARN: Removed duplicated region for block: B:401:0x093d  */
    /* JADX WARN: Removed duplicated region for block: B:403:0x0942  */
    /* JADX WARN: Removed duplicated region for block: B:405:0x0947  */
    /* JADX WARN: Removed duplicated region for block: B:407:0x094c  */
    /* JADX WARN: Removed duplicated region for block: B:409:0x0951  */
    /* JADX WARN: Removed duplicated region for block: B:411:0x0956  */
    /* JADX WARN: Removed duplicated region for block: B:413:0x095b  */
    /* JADX WARN: Removed duplicated region for block: B:415:0x0960  */
    /* JADX WARN: Removed duplicated region for block: B:442:0x09b7  */
    /* JADX WARN: Removed duplicated region for block: B:444:0x09bc  */
    /* JADX WARN: Removed duplicated region for block: B:446:0x09c1  */
    /* JADX WARN: Removed duplicated region for block: B:448:0x09c6  */
    /* JADX WARN: Removed duplicated region for block: B:450:0x09cb  */
    /* JADX WARN: Removed duplicated region for block: B:452:0x09d0  */
    /* JADX WARN: Removed duplicated region for block: B:454:0x09d5  */
    /* JADX WARN: Removed duplicated region for block: B:456:0x09da  */
    /* JADX WARN: Removed duplicated region for block: B:458:0x09df  */
    /* JADX WARN: Removed duplicated region for block: B:461:0x09e5 A[ORIG_RETURN, RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:465:0x09ea  */
    /* JADX WARN: Removed duplicated region for block: B:467:0x09ef  */
    /* JADX WARN: Removed duplicated region for block: B:469:0x09f4  */
    /* JADX WARN: Removed duplicated region for block: B:471:0x09f9  */
    /* JADX WARN: Removed duplicated region for block: B:473:0x09fe  */
    /* JADX WARN: Removed duplicated region for block: B:475:0x0a03  */
    /* JADX WARN: Removed duplicated region for block: B:477:0x0a08  */
    /* JADX WARN: Removed duplicated region for block: B:479:0x0a0d  */
    /* JADX WARN: Removed duplicated region for block: B:481:0x0a12  */
    /* JADX WARN: Removed duplicated region for block: B:483:0x0a17  */
    /* JADX WARN: Removed duplicated region for block: B:485:0x08c5 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:503:0x02af A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:536:0x06f7 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:556:0x0271 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:564:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:565:? A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$putMessages$139$MessagesStorage(boolean r36, long r37, im.uwrkaxlmjj.tgnet.TLRPC.messages_Messages r39, int r40, int r41, boolean r42) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 2587
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$putMessages$139$MessagesStorage(boolean, long, im.uwrkaxlmjj.tgnet.TLRPC$messages_Messages, int, int, boolean):void");
    }

    public static void addUsersAndChatsFromMessage(TLRPC.Message message, ArrayList<Integer> usersToLoad, ArrayList<Integer> chatsToLoad) {
        if (message.from_id != 0) {
            if (message.from_id > 0) {
                if (!usersToLoad.contains(Integer.valueOf(message.from_id))) {
                    usersToLoad.add(Integer.valueOf(message.from_id));
                }
            } else if (!chatsToLoad.contains(Integer.valueOf(-message.from_id))) {
                chatsToLoad.add(Integer.valueOf(-message.from_id));
            }
        }
        if (message.via_bot_id != 0 && !usersToLoad.contains(Integer.valueOf(message.via_bot_id))) {
            usersToLoad.add(Integer.valueOf(message.via_bot_id));
        }
        if (message.action != null) {
            if (message.action.user_id != 0 && !usersToLoad.contains(Integer.valueOf(message.action.user_id))) {
                usersToLoad.add(Integer.valueOf(message.action.user_id));
            }
            if (message.action.channel_id != 0 && !chatsToLoad.contains(Integer.valueOf(message.action.channel_id))) {
                chatsToLoad.add(Integer.valueOf(message.action.channel_id));
            }
            if (message.action.chat_id != 0 && !chatsToLoad.contains(Integer.valueOf(message.action.chat_id))) {
                chatsToLoad.add(Integer.valueOf(message.action.chat_id));
            }
            if (!message.action.users.isEmpty()) {
                for (int a = 0; a < message.action.users.size(); a++) {
                    Integer uid = message.action.users.get(a);
                    if (!usersToLoad.contains(uid)) {
                        usersToLoad.add(uid);
                    }
                }
            }
        }
        if (!message.entities.isEmpty()) {
            for (int a2 = 0; a2 < message.entities.size(); a2++) {
                TLRPC.MessageEntity entity = message.entities.get(a2);
                if (entity instanceof TLRPC.TL_messageEntityMentionName) {
                    usersToLoad.add(Integer.valueOf(((TLRPC.TL_messageEntityMentionName) entity).user_id));
                } else if (entity instanceof TLRPC.TL_inputMessageEntityMentionName) {
                    usersToLoad.add(Integer.valueOf(((TLRPC.TL_inputMessageEntityMentionName) entity).user_id.user_id));
                }
            }
        }
        if (message.media != null && message.media.user_id != 0 && !usersToLoad.contains(Integer.valueOf(message.media.user_id))) {
            usersToLoad.add(Integer.valueOf(message.media.user_id));
        }
        if (message.fwd_from != null) {
            if (message.fwd_from.from_id != 0 && !usersToLoad.contains(Integer.valueOf(message.fwd_from.from_id))) {
                usersToLoad.add(Integer.valueOf(message.fwd_from.from_id));
            }
            if (message.fwd_from.channel_id != 0 && !chatsToLoad.contains(Integer.valueOf(message.fwd_from.channel_id))) {
                chatsToLoad.add(Integer.valueOf(message.fwd_from.channel_id));
            }
            if (message.fwd_from.saved_from_peer != null) {
                if (message.fwd_from.saved_from_peer.user_id != 0) {
                    if (!chatsToLoad.contains(Integer.valueOf(message.fwd_from.saved_from_peer.user_id))) {
                        usersToLoad.add(Integer.valueOf(message.fwd_from.saved_from_peer.user_id));
                    }
                } else if (message.fwd_from.saved_from_peer.channel_id != 0) {
                    if (!chatsToLoad.contains(Integer.valueOf(message.fwd_from.saved_from_peer.channel_id))) {
                        chatsToLoad.add(Integer.valueOf(message.fwd_from.saved_from_peer.channel_id));
                    }
                } else if (message.fwd_from.saved_from_peer.chat_id != 0 && !chatsToLoad.contains(Integer.valueOf(message.fwd_from.saved_from_peer.chat_id))) {
                    chatsToLoad.add(Integer.valueOf(message.fwd_from.saved_from_peer.chat_id));
                }
            }
        }
        if (message.ttl < 0 && !chatsToLoad.contains(Integer.valueOf(-message.ttl))) {
            chatsToLoad.add(Integer.valueOf(-message.ttl));
        }
    }

    public void getDialogs(final int folderId, final int offset, final int count) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$pmlgeymYvqy2UbWYOYtF_sgw7-4
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$getDialogs$140$MessagesStorage(folderId, offset, count);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:103:0x026b A[Catch: all -> 0x03c5, Exception -> 0x03cf, TRY_LEAVE, TryCatch #60 {Exception -> 0x03cf, all -> 0x03c5, blocks: (B:101:0x0267, B:103:0x026b, B:116:0x029e), top: B:426:0x0267 }] */
    /* JADX WARN: Removed duplicated region for block: B:115:0x029c  */
    /* JADX WARN: Removed duplicated region for block: B:177:0x03a0  */
    /* JADX WARN: Removed duplicated region for block: B:196:0x03e8 A[Catch: all -> 0x03ed, Exception -> 0x03f6, TryCatch #77 {Exception -> 0x03f6, all -> 0x03ed, blocks: (B:196:0x03e8, B:198:0x03ec, B:192:0x03df), top: B:392:0x03df }] */
    /* JADX WARN: Removed duplicated region for block: B:216:0x043d  */
    /* JADX WARN: Removed duplicated region for block: B:219:0x0450  */
    /* JADX WARN: Removed duplicated region for block: B:226:0x0478 A[Catch: all -> 0x0493, Exception -> 0x049c, TryCatch #47 {Exception -> 0x049c, all -> 0x0493, blocks: (B:217:0x0446, B:220:0x0452, B:222:0x045c, B:223:0x0464, B:225:0x046f, B:226:0x0478, B:228:0x0482), top: B:452:0x0446 }] */
    /* JADX WARN: Removed duplicated region for block: B:367:0x072f  */
    /* JADX WARN: Removed duplicated region for block: B:369:0x0734  */
    /* JADX WARN: Removed duplicated region for block: B:392:0x03df A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:398:0x03a8 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:477:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0168  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x017f  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x01a0  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x01a2  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x01b8  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x01ba  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x01d7 A[Catch: all -> 0x0172, Exception -> 0x0178, TRY_ENTER, TryCatch #80 {Exception -> 0x0178, all -> 0x0172, blocks: (B:54:0x016a, B:76:0x01d7, B:78:0x01e8), top: B:386:0x016a }] */
    /* JADX WARN: Removed duplicated region for block: B:80:0x01f0  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0209  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$getDialogs$140$MessagesStorage(int r40, int r41, int r42) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 1864
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$getDialogs$140$MessagesStorage(int, int, int):void");
    }

    public static void createFirstHoles(long did, SQLitePreparedStatement state5, SQLitePreparedStatement state6, int messageId) throws Exception {
        state5.requery();
        state5.bindLong(1, did);
        state5.bindInteger(2, messageId == 1 ? 1 : 0);
        state5.bindInteger(3, messageId);
        state5.step();
        for (int b = 0; b < 5; b++) {
            state6.requery();
            state6.bindLong(1, did);
            state6.bindInteger(2, b);
            state6.bindInteger(3, messageId == 1 ? 1 : 0);
            state6.bindInteger(4, messageId);
            state6.step();
        }
    }

    /* JADX WARN: Can't wrap try/catch for region: R(13:(4:371|23|24|(6:383|25|26|345|27|28))|(7:31|32|(16:361|34|35|385|36|37|365|38|39|335|40|375|41|42|(2:44|396)(8:74|359|75|76|(11:351|78|(1:80)(1:86)|87|88|391|89|(3:349|91|92)(1:97)|377|98|(21:373|100|(1:108)(1:103)|109|110|111|(1:113)(1:115)|116|117|(1:119)(1:120)|121|(1:123)|124|125|341|126|(1:136)(2:(2:339|129)|130)|137|138|369|139)(0))(1:161)|333|162|(11:381|164|(2:166|167)|172|(1:174)|175|(1:177)(2:179|180)|181|(2:183|184)|185|(7:187|188|357|189|(1:191)(1:192)|193|397)(2:199|395))(8:172|(0)|175|(0)(0)|181|(0)|185|(0)(0)))|200)(12:58|337|59|(1:73)(5:63|64|(1:66)|67|68)|74|359|75|76|(0)(0)|333|162|(0)(0))|273|398|363|29)|394|213|343|214|215|389|216|217|379|218|(2:220|221)(1:222)) */
    /* JADX WARN: Can't wrap try/catch for region: R(14:(21:371|23|24|383|25|26|345|27|28|(7:31|32|(16:361|34|35|385|36|37|365|38|39|335|40|375|41|42|(2:44|396)(8:74|359|75|76|(11:351|78|(1:80)(1:86)|87|88|391|89|(3:349|91|92)(1:97)|377|98|(21:373|100|(1:108)(1:103)|109|110|111|(1:113)(1:115)|116|117|(1:119)(1:120)|121|(1:123)|124|125|341|126|(1:136)(2:(2:339|129)|130)|137|138|369|139)(0))(1:161)|333|162|(11:381|164|(2:166|167)|172|(1:174)|175|(1:177)(2:179|180)|181|(2:183|184)|185|(7:187|188|357|189|(1:191)(1:192)|193|397)(2:199|395))(8:172|(0)|175|(0)(0)|181|(0)|185|(0)(0)))|200)(12:58|337|59|(1:73)(5:63|64|(1:66)|67|68)|74|359|75|76|(0)(0)|333|162|(0)(0))|273|398|363|29)|394|213|343|214|215|389|216|217|379|218|(2:220|221)(1:222))(1:251)|330|255|(1:257)|(1:259)|(1:261)|(1:263)|(1:265)|(1:267)|(1:269)|(1:271)|(1:309)|273|398) */
    /* JADX WARN: Can't wrap try/catch for region: R(16:371|23|24|(6:383|25|26|345|27|28)|(7:31|32|(16:361|34|35|385|36|37|365|38|39|335|40|375|41|42|(2:44|396)(8:74|359|75|76|(11:351|78|(1:80)(1:86)|87|88|391|89|(3:349|91|92)(1:97)|377|98|(21:373|100|(1:108)(1:103)|109|110|111|(1:113)(1:115)|116|117|(1:119)(1:120)|121|(1:123)|124|125|341|126|(1:136)(2:(2:339|129)|130)|137|138|369|139)(0))(1:161)|333|162|(11:381|164|(2:166|167)|172|(1:174)|175|(1:177)(2:179|180)|181|(2:183|184)|185|(7:187|188|357|189|(1:191)(1:192)|193|397)(2:199|395))(8:172|(0)|175|(0)(0)|181|(0)|185|(0)(0)))|200)(12:58|337|59|(1:73)(5:63|64|(1:66)|67|68)|74|359|75|76|(0)(0)|333|162|(0)(0))|273|398|363|29)|394|213|343|214|215|389|216|217|379|218|(2:220|221)(1:222)) */
    /* JADX WARN: Can't wrap try/catch for region: R(21:371|23|24|383|25|26|345|27|28|(7:31|32|(16:361|34|35|385|36|37|365|38|39|335|40|375|41|42|(2:44|396)(8:74|359|75|76|(11:351|78|(1:80)(1:86)|87|88|391|89|(3:349|91|92)(1:97)|377|98|(21:373|100|(1:108)(1:103)|109|110|111|(1:113)(1:115)|116|117|(1:119)(1:120)|121|(1:123)|124|125|341|126|(1:136)(2:(2:339|129)|130)|137|138|369|139)(0))(1:161)|333|162|(11:381|164|(2:166|167)|172|(1:174)|175|(1:177)(2:179|180)|181|(2:183|184)|185|(7:187|188|357|189|(1:191)(1:192)|193|397)(2:199|395))(8:172|(0)|175|(0)(0)|181|(0)|185|(0)(0)))|200)(12:58|337|59|(1:73)(5:63|64|(1:66)|67|68)|74|359|75|76|(0)(0)|333|162|(0)(0))|273|398|363|29)|394|213|343|214|215|389|216|217|379|218|(2:220|221)(1:222)) */
    /* JADX WARN: Can't wrap try/catch for region: R(28:0|2|(2:387|3)|9|(6:12|13|353|14|15|10)|393|20|347|21|(21:371|23|24|383|25|26|345|27|28|(7:31|32|(16:361|34|35|385|36|37|365|38|39|335|40|375|41|42|(2:44|396)(8:74|359|75|76|(11:351|78|(1:80)(1:86)|87|88|391|89|(3:349|91|92)(1:97)|377|98|(21:373|100|(1:108)(1:103)|109|110|111|(1:113)(1:115)|116|117|(1:119)(1:120)|121|(1:123)|124|125|341|126|(1:136)(2:(2:339|129)|130)|137|138|369|139)(0))(1:161)|333|162|(11:381|164|(2:166|167)|172|(1:174)|175|(1:177)(2:179|180)|181|(2:183|184)|185|(7:187|188|357|189|(1:191)(1:192)|193|397)(2:199|395))(8:172|(0)|175|(0)(0)|181|(0)|185|(0)(0)))|200)(12:58|337|59|(1:73)(5:63|64|(1:66)|67|68)|74|359|75|76|(0)(0)|333|162|(0)(0))|273|398|363|29)|394|213|343|214|215|389|216|217|379|218|(2:220|221)(1:222))(1:251)|252|355|253|254|330|255|(1:257)|(1:259)|(1:261)|(1:263)|(1:265)|(1:267)|(1:269)|(1:271)|(1:309)|273|398|(1:(0))) */
    /* JADX WARN: Code restructure failed: missing block: B:223:0x0578, code lost:
    
        r0 = th;
     */
    /* JADX WARN: Code restructure failed: missing block: B:224:0x0579, code lost:
    
        r5 = r18;
        r4 = r19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:225:0x0583, code lost:
    
        r0 = e;
     */
    /* JADX WARN: Code restructure failed: missing block: B:226:0x0584, code lost:
    
        r5 = r18;
        r4 = r19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:227:0x058e, code lost:
    
        r0 = th;
     */
    /* JADX WARN: Code restructure failed: missing block: B:228:0x058f, code lost:
    
        r10 = r4;
        r5 = r18;
        r4 = r19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:229:0x059a, code lost:
    
        r0 = e;
     */
    /* JADX WARN: Code restructure failed: missing block: B:230:0x059b, code lost:
    
        r10 = r4;
        r5 = r18;
        r4 = r19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:231:0x05a6, code lost:
    
        r0 = th;
     */
    /* JADX WARN: Code restructure failed: missing block: B:232:0x05a7, code lost:
    
        r10 = r4;
        r9 = r14;
        r5 = r18;
        r4 = r19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:233:0x05b3, code lost:
    
        r0 = e;
     */
    /* JADX WARN: Code restructure failed: missing block: B:234:0x05b4, code lost:
    
        r10 = r4;
        r9 = r14;
        r5 = r18;
        r4 = r19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:274:0x0661, code lost:
    
        r0 = e;
     */
    /* JADX WARN: Code restructure failed: missing block: B:276:0x0663, code lost:
    
        r0 = th;
     */
    /* JADX WARN: Code restructure failed: missing block: B:278:0x0668, code lost:
    
        r0 = e;
     */
    /* JADX WARN: Code restructure failed: missing block: B:292:0x069a, code lost:
    
        r5.reuse();
     */
    /* JADX WARN: Code restructure failed: missing block: B:294:0x069f, code lost:
    
        r4.dispose();
     */
    /* JADX WARN: Code restructure failed: missing block: B:296:0x06a4, code lost:
    
        r6.dispose();
     */
    /* JADX WARN: Code restructure failed: missing block: B:298:0x06a9, code lost:
    
        r7.dispose();
     */
    /* JADX WARN: Code restructure failed: missing block: B:300:0x06ae, code lost:
    
        r8.dispose();
     */
    /* JADX WARN: Code restructure failed: missing block: B:302:0x06b3, code lost:
    
        r9.dispose();
     */
    /* JADX WARN: Code restructure failed: missing block: B:304:0x06b8, code lost:
    
        r10.dispose();
     */
    /* JADX WARN: Code restructure failed: missing block: B:306:0x06bd, code lost:
    
        r11.dispose();
     */
    /* JADX WARN: Code restructure failed: missing block: B:399:?, code lost:
    
        return;
     */
    /* JADX WARN: Removed duplicated region for block: B:108:0x029f  */
    /* JADX WARN: Removed duplicated region for block: B:161:0x03d7  */
    /* JADX WARN: Removed duplicated region for block: B:172:0x040e A[Catch: all -> 0x04e3, Exception -> 0x04f0, PHI: r2
      0x040e: PHI (r2v61 'topMessage' long) = (r2v57 'topMessage' long), (r2v57 'topMessage' long), (r2v60 'topMessage' long) binds: [B:163:0x03e5, B:165:0x03eb, B:167:0x03f1] A[DONT_GENERATE, DONT_INLINE], TRY_ENTER, TryCatch #62 {Exception -> 0x04f0, all -> 0x04e3, blocks: (B:162:0x03e0, B:172:0x040e, B:174:0x0457, B:175:0x0459, B:181:0x048d, B:185:0x0497, B:187:0x049b, B:180:0x048a), top: B:333:0x03e0 }] */
    /* JADX WARN: Removed duplicated region for block: B:174:0x0457 A[Catch: all -> 0x04e3, Exception -> 0x04f0, TryCatch #62 {Exception -> 0x04f0, all -> 0x04e3, blocks: (B:162:0x03e0, B:172:0x040e, B:174:0x0457, B:175:0x0459, B:181:0x048d, B:185:0x0497, B:187:0x049b, B:180:0x048a), top: B:333:0x03e0 }] */
    /* JADX WARN: Removed duplicated region for block: B:177:0x0469 A[Catch: all -> 0x03f6, Exception -> 0x0402, TRY_ENTER, TRY_LEAVE, TryCatch #38 {Exception -> 0x0402, all -> 0x03f6, blocks: (B:164:0x03e7, B:166:0x03ed, B:177:0x0469, B:183:0x0492), top: B:381:0x03e7 }] */
    /* JADX WARN: Removed duplicated region for block: B:179:0x0485  */
    /* JADX WARN: Removed duplicated region for block: B:183:0x0492 A[Catch: all -> 0x03f6, Exception -> 0x0402, TRY_ENTER, TRY_LEAVE, TryCatch #38 {Exception -> 0x0402, all -> 0x03f6, blocks: (B:164:0x03e7, B:166:0x03ed, B:177:0x0469, B:183:0x0492), top: B:381:0x03e7 }] */
    /* JADX WARN: Removed duplicated region for block: B:187:0x049b A[Catch: all -> 0x04e3, Exception -> 0x04f0, TRY_LEAVE, TryCatch #62 {Exception -> 0x04f0, all -> 0x04e3, blocks: (B:162:0x03e0, B:172:0x040e, B:174:0x0457, B:175:0x0459, B:181:0x048d, B:185:0x0497, B:187:0x049b, B:180:0x048a), top: B:333:0x03e0 }] */
    /* JADX WARN: Removed duplicated region for block: B:199:0x04ce  */
    /* JADX WARN: Removed duplicated region for block: B:292:0x069a  */
    /* JADX WARN: Removed duplicated region for block: B:294:0x069f  */
    /* JADX WARN: Removed duplicated region for block: B:296:0x06a4  */
    /* JADX WARN: Removed duplicated region for block: B:298:0x06a9  */
    /* JADX WARN: Removed duplicated region for block: B:300:0x06ae  */
    /* JADX WARN: Removed duplicated region for block: B:302:0x06b3  */
    /* JADX WARN: Removed duplicated region for block: B:304:0x06b8  */
    /* JADX WARN: Removed duplicated region for block: B:306:0x06bd  */
    /* JADX WARN: Removed duplicated region for block: B:312:0x06c7  */
    /* JADX WARN: Removed duplicated region for block: B:314:0x06cc  */
    /* JADX WARN: Removed duplicated region for block: B:316:0x06d1  */
    /* JADX WARN: Removed duplicated region for block: B:318:0x06d6  */
    /* JADX WARN: Removed duplicated region for block: B:320:0x06db  */
    /* JADX WARN: Removed duplicated region for block: B:322:0x06e0  */
    /* JADX WARN: Removed duplicated region for block: B:324:0x06e5  */
    /* JADX WARN: Removed duplicated region for block: B:326:0x06ea  */
    /* JADX WARN: Removed duplicated region for block: B:328:0x06ef  */
    /* JADX WARN: Removed duplicated region for block: B:351:0x01d0 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:381:0x03e7 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:399:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void putDialogsInternal(im.uwrkaxlmjj.tgnet.TLRPC.messages_Dialogs r29, int r30) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 1779
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.putDialogsInternal(im.uwrkaxlmjj.tgnet.TLRPC$messages_Dialogs, int):void");
    }

    public void getDialogFolderId(final long dialogId, final IntCallback callback) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$iVDPMAYxpbP0s4DjG3HBSEVvawk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getDialogFolderId$142$MessagesStorage(dialogId, callback);
            }
        });
    }

    public /* synthetic */ void lambda$getDialogFolderId$142$MessagesStorage(long dialogId, final IntCallback callback) {
        SQLiteCursor cursor = null;
        try {
            try {
                SQLiteCursor cursor2 = this.database.queryFinalized("SELECT folder_id FROM dialogs WHERE did = ?", Long.valueOf(dialogId));
                final int folderId = cursor2.next() ? cursor2.intValue(0) : -1;
                cursor2.dispose();
                cursor = null;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$2bB98-GWRChzwUDa_gwcbpRBcuU
                    @Override // java.lang.Runnable
                    public final void run() {
                        callback.run(folderId);
                    }
                });
                if (0 != 0) {
                    cursor.dispose();
                }
            } catch (Exception e) {
                FileLog.e("getDialogFolderId ---> exception ", e);
                if (cursor != null) {
                    cursor.dispose();
                }
            }
        } catch (Throwable th) {
            if (cursor != null) {
                cursor.dispose();
            }
            throw th;
        }
    }

    public void setDialogsFolderId(final ArrayList<TLRPC.TL_folderPeer> peers, final ArrayList<TLRPC.TL_inputFolderPeer> inputPeers, final long dialogId, final int folderId) {
        if (peers == null && inputPeers == null && dialogId == 0) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$3mH7TWx-fdk9cK0-N3S2v-XYFXY
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$setDialogsFolderId$143$MessagesStorage(peers, inputPeers, folderId, dialogId);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:44:0x00c0  */
    /* JADX WARN: Removed duplicated region for block: B:57:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$setDialogsFolderId$143$MessagesStorage(java.util.ArrayList r15, java.util.ArrayList r16, int r17, long r18) throws java.lang.Throwable {
        /*
            r14 = this;
            r1 = r14
            r2 = r15
            r3 = r16
            r4 = 0
            im.uwrkaxlmjj.sqlite.SQLiteDatabase r0 = r1.database     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> L12
            r0.beginTransaction()     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> L12
            goto L18
        Lb:
            r0 = move-exception
            r8 = r17
        Le:
            r5 = r18
            goto Lbe
        L12:
            r0 = move-exception
            java.lang.String r5 = "setDialogsFolderId ---> exception 1 "
            im.uwrkaxlmjj.messenger.FileLog.e(r5, r0)     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
        L18:
            im.uwrkaxlmjj.sqlite.SQLiteDatabase r0 = r1.database     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            java.lang.String r5 = "UPDATE dialogs SET folder_id = ?, pinned = ? WHERE did = ?"
            im.uwrkaxlmjj.sqlite.SQLitePreparedStatement r0 = r0.executeFast(r5)     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            r4 = r0
            r0 = 3
            r5 = 0
            r6 = 2
            r7 = 1
            if (r2 == 0) goto L54
            r8 = 0
            int r9 = r15.size()     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
        L2c:
            if (r8 >= r9) goto L4f
            java.lang.Object r10 = r15.get(r8)     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            im.uwrkaxlmjj.tgnet.TLRPC$TL_folderPeer r10 = (im.uwrkaxlmjj.tgnet.TLRPC.TL_folderPeer) r10     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            im.uwrkaxlmjj.tgnet.TLRPC$Peer r11 = r10.peer     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            long r11 = im.uwrkaxlmjj.messenger.DialogObject.getPeerDialogId(r11)     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            r4.requery()     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            int r13 = r10.folder_id     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            r4.bindInteger(r7, r13)     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            r4.bindInteger(r6, r5)     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            r4.bindLong(r0, r11)     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            r4.step()     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            int r8 = r8 + 1
            goto L2c
        L4f:
            r8 = r17
            r5 = r18
            goto L96
        L54:
            if (r3 == 0) goto L83
            r8 = 0
            int r9 = r16.size()     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
        L5b:
            if (r8 >= r9) goto L7e
            java.lang.Object r10 = r3.get(r8)     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            im.uwrkaxlmjj.tgnet.TLRPC$TL_inputFolderPeer r10 = (im.uwrkaxlmjj.tgnet.TLRPC.TL_inputFolderPeer) r10     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            im.uwrkaxlmjj.tgnet.TLRPC$InputPeer r11 = r10.peer     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            long r11 = im.uwrkaxlmjj.messenger.DialogObject.getPeerDialogId(r11)     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            r4.requery()     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            int r13 = r10.folder_id     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            r4.bindInteger(r7, r13)     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            r4.bindInteger(r6, r5)     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            r4.bindLong(r0, r11)     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            r4.step()     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            int r8 = r8 + 1
            goto L5b
        L7e:
            r8 = r17
            r5 = r18
            goto L96
        L83:
            r4.requery()     // Catch: java.lang.Throwable -> Lb java.lang.Exception -> Laf
            r8 = r17
            r4.bindInteger(r7, r8)     // Catch: java.lang.Throwable -> Laa java.lang.Exception -> Lad
            r4.bindInteger(r6, r5)     // Catch: java.lang.Throwable -> Laa java.lang.Exception -> Lad
            r5 = r18
            r4.bindLong(r0, r5)     // Catch: java.lang.Exception -> La8 java.lang.Throwable -> Lbd
            r4.step()     // Catch: java.lang.Exception -> La8 java.lang.Throwable -> Lbd
        L96:
            r4.dispose()     // Catch: java.lang.Exception -> La8 java.lang.Throwable -> Lbd
            r4 = 0
            im.uwrkaxlmjj.sqlite.SQLiteDatabase r0 = r1.database     // Catch: java.lang.Exception -> La8 java.lang.Throwable -> Lbd
            r0.commitTransaction()     // Catch: java.lang.Exception -> La8 java.lang.Throwable -> Lbd
            r14.lambda$checkIfFolderEmpty$145$MessagesStorage(r7)     // Catch: java.lang.Exception -> La8 java.lang.Throwable -> Lbd
            if (r4 == 0) goto Lbc
        La4:
            r4.dispose()
            goto Lbc
        La8:
            r0 = move-exception
            goto Lb4
        Laa:
            r0 = move-exception
            goto Le
        Lad:
            r0 = move-exception
            goto Lb2
        Laf:
            r0 = move-exception
            r8 = r17
        Lb2:
            r5 = r18
        Lb4:
            java.lang.String r7 = "setDialogsFolderId ---> exception 2 "
            im.uwrkaxlmjj.messenger.FileLog.e(r7, r0)     // Catch: java.lang.Throwable -> Lbd
            if (r4 == 0) goto Lbc
            goto La4
        Lbc:
            return
        Lbd:
            r0 = move-exception
        Lbe:
            if (r4 == 0) goto Lc3
            r4.dispose()
        Lc3:
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$setDialogsFolderId$143$MessagesStorage(java.util.ArrayList, java.util.ArrayList, int, long):void");
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: checkIfFolderEmptyInternal, reason: merged with bridge method [inline-methods] */
    public void lambda$checkIfFolderEmpty$145$MessagesStorage(final int folderId) {
        SQLiteCursor cursor = null;
        SQLitePreparedStatement state = null;
        try {
            try {
                cursor = this.database.queryFinalized("SELECT did FROM dialogs WHERE folder_id = ?", Integer.valueOf(folderId));
                if (!cursor.next()) {
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$8gSmwYhgSaL2EjGsA2msKdELhks
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$checkIfFolderEmptyInternal$144$MessagesStorage(folderId);
                        }
                    });
                    this.database.executeFast("DELETE FROM dialogs WHERE did = " + DialogObject.makeFolderDialogId(folderId)).stepThis().dispose();
                    state = null;
                }
                cursor.dispose();
                SQLiteCursor cursor2 = null;
                if (0 != 0) {
                    cursor2.dispose();
                }
                if (state == null) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("checkIfFolderEmptyInternal ---> exception ", e);
                if (cursor != null) {
                    cursor.dispose();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (cursor != null) {
                cursor.dispose();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public /* synthetic */ void lambda$checkIfFolderEmptyInternal$144$MessagesStorage(int folderId) {
        getMessagesController().onFolderEmpty(folderId);
    }

    public void checkIfFolderEmpty(final int folderId) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$Fq9Zf83QjWCzxt7tSEL5uZtO5n8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$checkIfFolderEmpty$145$MessagesStorage(folderId);
            }
        });
    }

    public void unpinAllDialogsExceptNew(final ArrayList<Long> dids, final int folderId) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$uQe1XdABLJOqyqnxDdvD_yj7rTE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$unpinAllDialogsExceptNew$146$MessagesStorage(dids, folderId);
            }
        });
    }

    public /* synthetic */ void lambda$unpinAllDialogsExceptNew$146$MessagesStorage(ArrayList dids, int folderId) {
        SQLiteCursor cursor = null;
        SQLitePreparedStatement state = null;
        try {
            try {
                ArrayList<Long> unpinnedDialogs = new ArrayList<>();
                SQLiteCursor cursor2 = this.database.queryFinalized(String.format(Locale.US, "SELECT did, folder_id FROM dialogs WHERE pinned != 0 AND did NOT IN (%s)", TextUtils.join(",", dids)), new Object[0]);
                while (cursor2.next()) {
                    long did = cursor2.longValue(0);
                    int fid = cursor2.intValue(1);
                    if (fid == folderId && ((int) did) != 0 && !DialogObject.isFolderDialogId(did)) {
                        unpinnedDialogs.add(Long.valueOf(cursor2.longValue(0)));
                    }
                }
                cursor2.dispose();
                cursor = null;
                if (!unpinnedDialogs.isEmpty()) {
                    state = this.database.executeFast("UPDATE dialogs SET pinned = ? WHERE did = ?");
                    for (int a = 0; a < unpinnedDialogs.size(); a++) {
                        long did2 = unpinnedDialogs.get(a).longValue();
                        state.requery();
                        state.bindInteger(1, 0);
                        state.bindLong(2, did2);
                        state.step();
                    }
                    state.dispose();
                    state = null;
                }
                if (0 != 0) {
                    cursor.dispose();
                }
                if (state == null) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("unpinAllDialogsExceptNew ---> exception ", e);
                if (cursor != null) {
                    cursor.dispose();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (cursor != null) {
                cursor.dispose();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void setDialogUnread(final long did, final boolean unread) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$aRZBunnaNjTWh_KHMf2MrAvDj2Y
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$setDialogUnread$147$MessagesStorage(did, unread);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0041  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0043  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0074 A[ORIG_RETURN, RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$setDialogUnread$147$MessagesStorage(long r8, boolean r10) {
        /*
            r7 = this;
            r0 = 0
            r1 = 0
            r2 = 0
            im.uwrkaxlmjj.sqlite.SQLiteDatabase r3 = r7.database     // Catch: java.lang.Throwable -> L33 java.lang.Exception -> L35
            java.lang.StringBuilder r4 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L33 java.lang.Exception -> L35
            r4.<init>()     // Catch: java.lang.Throwable -> L33 java.lang.Exception -> L35
            java.lang.String r5 = "SELECT flags FROM dialogs WHERE did = "
            r4.append(r5)     // Catch: java.lang.Throwable -> L33 java.lang.Exception -> L35
            r4.append(r8)     // Catch: java.lang.Throwable -> L33 java.lang.Exception -> L35
            java.lang.String r4 = r4.toString()     // Catch: java.lang.Throwable -> L33 java.lang.Exception -> L35
            r5 = 0
            java.lang.Object[] r6 = new java.lang.Object[r5]     // Catch: java.lang.Throwable -> L33 java.lang.Exception -> L35
            im.uwrkaxlmjj.sqlite.SQLiteCursor r3 = r3.queryFinalized(r4, r6)     // Catch: java.lang.Throwable -> L33 java.lang.Exception -> L35
            r2 = r3
            boolean r3 = r2.next()     // Catch: java.lang.Throwable -> L33 java.lang.Exception -> L35
            if (r3 == 0) goto L29
            int r3 = r2.intValue(r5)     // Catch: java.lang.Throwable -> L33 java.lang.Exception -> L35
            r1 = r3
        L29:
            r2.dispose()     // Catch: java.lang.Throwable -> L33 java.lang.Exception -> L35
            r2 = 0
            if (r2 == 0) goto L3e
        L2f:
            r2.dispose()     // Catch: java.lang.Throwable -> L69 java.lang.Exception -> L6b
            goto L3e
        L33:
            r3 = move-exception
            goto L62
        L35:
            r3 = move-exception
            java.lang.String r4 = "setDialogUnread ---> exception 1 "
            im.uwrkaxlmjj.messenger.FileLog.e(r4, r3)     // Catch: java.lang.Throwable -> L33
            if (r2 == 0) goto L3e
            goto L2f
        L3e:
            r3 = 1
            if (r10 == 0) goto L43
            r1 = r1 | r3
            goto L45
        L43:
            r1 = r1 & (-2)
        L45:
            im.uwrkaxlmjj.sqlite.SQLiteDatabase r4 = r7.database     // Catch: java.lang.Throwable -> L69 java.lang.Exception -> L6b
            java.lang.String r5 = "UPDATE dialogs SET flags = ? WHERE did = ?"
            im.uwrkaxlmjj.sqlite.SQLitePreparedStatement r4 = r4.executeFast(r5)     // Catch: java.lang.Throwable -> L69 java.lang.Exception -> L6b
            r0 = r4
            r0.bindInteger(r3, r1)     // Catch: java.lang.Throwable -> L69 java.lang.Exception -> L6b
            r3 = 2
            r0.bindLong(r3, r8)     // Catch: java.lang.Throwable -> L69 java.lang.Exception -> L6b
            r0.step()     // Catch: java.lang.Throwable -> L69 java.lang.Exception -> L6b
            r0.dispose()     // Catch: java.lang.Throwable -> L69 java.lang.Exception -> L6b
            r0 = 0
            if (r0 == 0) goto L74
        L5e:
            r0.dispose()
            goto L74
        L62:
            if (r2 == 0) goto L67
            r2.dispose()     // Catch: java.lang.Throwable -> L69 java.lang.Exception -> L6b
        L67:
            throw r3     // Catch: java.lang.Throwable -> L69 java.lang.Exception -> L6b
        L69:
            r1 = move-exception
            goto L75
        L6b:
            r1 = move-exception
            java.lang.String r2 = "setDialogUnread ---> exception 2 "
            im.uwrkaxlmjj.messenger.FileLog.e(r2, r1)     // Catch: java.lang.Throwable -> L69
            if (r0 == 0) goto L74
            goto L5e
        L74:
            return
        L75:
            if (r0 == 0) goto L7a
            r0.dispose()
        L7a:
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesStorage.lambda$setDialogUnread$147$MessagesStorage(long, boolean):void");
    }

    public void setDialogPinned(final long did, final int pinned) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$0CUzKIGT4NujCzLV7RQh5p1jmL4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$setDialogPinned$148$MessagesStorage(pinned, did);
            }
        });
    }

    public /* synthetic */ void lambda$setDialogPinned$148$MessagesStorage(int pinned, long did) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast("UPDATE dialogs SET pinned = ? WHERE did = ?");
                state.bindInteger(1, pinned);
                state.bindLong(2, did);
                state.step();
                state.dispose();
                state = null;
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("setDialogPinned ---> exception ", e);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void putDialogs(final TLRPC.messages_Dialogs dialogs, final int check) {
        if (dialogs.dialogs.isEmpty()) {
            return;
        }
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$XTiHm4lGz05Vh5RdnlpRMbzZW4w
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$putDialogs$149$MessagesStorage(dialogs, check);
            }
        });
    }

    public /* synthetic */ void lambda$putDialogs$149$MessagesStorage(TLRPC.messages_Dialogs dialogs, int check) throws Throwable {
        putDialogsInternal(dialogs, check);
        loadUnreadMessages();
    }

    public int getDialogReadMax(final boolean outbox, final long dialog_id) {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final Integer[] max = {0};
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$fHt_x4Pwra5X27sEH6ul7rVFFoM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getDialogReadMax$150$MessagesStorage(outbox, dialog_id, max, countDownLatch);
            }
        });
        try {
            countDownLatch.await();
        } catch (Exception e) {
            FileLog.e("getDialogReadMax ---> exception 2 ", e);
        }
        return max[0].intValue();
    }

    public /* synthetic */ void lambda$getDialogReadMax$150$MessagesStorage(boolean outbox, long dialog_id, Integer[] max, CountDownLatch countDownLatch) {
        SQLiteCursor cursor = null;
        try {
            try {
                if (outbox) {
                    cursor = this.database.queryFinalized("SELECT outbox_max FROM dialogs WHERE did = " + dialog_id, new Object[0]);
                } else {
                    cursor = this.database.queryFinalized("SELECT inbox_max FROM dialogs WHERE did = " + dialog_id, new Object[0]);
                }
                if (cursor.next()) {
                    max[0] = Integer.valueOf(cursor.intValue(0));
                }
                cursor.dispose();
                cursor = null;
            } catch (Exception e) {
                FileLog.e("getDialogReadMax ---> exception 1 ", e);
                if (cursor != null) {
                }
            }
            countDownLatch.countDown();
        } finally {
            if (cursor != null) {
                cursor.dispose();
            }
        }
    }

    public int getChannelPtsSync(final int channelId) {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final Integer[] pts = {0};
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$ZHSBpe9xciphS53qbuXxlQEuQI0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getChannelPtsSync$151$MessagesStorage(channelId, pts, countDownLatch);
            }
        });
        try {
            countDownLatch.await();
        } catch (Exception e) {
            FileLog.e("getChannelPtsSync ---> exception 3 " + e);
        }
        return pts[0].intValue();
    }

    public /* synthetic */ void lambda$getChannelPtsSync$151$MessagesStorage(int channelId, Integer[] pts, CountDownLatch countDownLatch) {
        SQLiteCursor cursor = null;
        try {
            try {
                cursor = this.database.queryFinalized("SELECT pts FROM dialogs WHERE did = " + (-channelId), new Object[0]);
                if (cursor.next()) {
                    pts[0] = Integer.valueOf(cursor.intValue(0));
                }
                cursor.dispose();
                cursor = null;
            } catch (Exception e) {
                FileLog.e("getChannelPtsSync ---> exception 1 " + e);
                if (cursor != null) {
                }
            }
            if (countDownLatch != null) {
                try {
                    countDownLatch.countDown();
                } catch (Exception e2) {
                    FileLog.e("getChannelPtsSync ---> exception 2 " + e2);
                }
            }
        } finally {
            if (cursor != null) {
                cursor.dispose();
            }
        }
    }

    public TLRPC.User getUserSync(final int user_id) {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final TLRPC.User[] user = new TLRPC.User[1];
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$C6K41jjGCCWC-qCLWSEsdX7egWg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getUserSync$152$MessagesStorage(user, user_id, countDownLatch);
            }
        });
        try {
            countDownLatch.await();
        } catch (Exception e) {
            FileLog.e("getUserSync ---> exception " + e);
        }
        return user[0];
    }

    public /* synthetic */ void lambda$getUserSync$152$MessagesStorage(TLRPC.User[] user, int user_id, CountDownLatch countDownLatch) {
        user[0] = getUser(user_id);
        countDownLatch.countDown();
    }

    public TLRPC.Chat getChatSync(final int chat_id) {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final TLRPC.Chat[] chat = new TLRPC.Chat[1];
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$wC3gO7KmE1MJqJzCZ-1L2H1Fn20
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getChatSync$153$MessagesStorage(chat, chat_id, countDownLatch);
            }
        });
        try {
            countDownLatch.await();
        } catch (Exception e) {
            FileLog.e("getChatSync ---> exception " + e);
        }
        return chat[0];
    }

    public /* synthetic */ void lambda$getChatSync$153$MessagesStorage(TLRPC.Chat[] chat, int chat_id, CountDownLatch countDownLatch) {
        chat[0] = getChat(chat_id);
        countDownLatch.countDown();
    }

    public TLRPC.User getUser(int user_id) {
        try {
            ArrayList<TLRPC.User> users = new ArrayList<>();
            getUsersInternal("" + user_id, users);
            if (users.isEmpty()) {
                return null;
            }
            TLRPC.User user = users.get(0);
            return user;
        } catch (Exception e) {
            FileLog.e("getUser ---> exception ", e);
            return null;
        }
    }

    public ArrayList<TLRPC.User> getUsers(ArrayList<Integer> uids) {
        ArrayList<TLRPC.User> users = new ArrayList<>();
        try {
            getUsersInternal(TextUtils.join(",", uids), users);
        } catch (Exception e) {
            users.clear();
            FileLog.e("getUsers ---> exception ", e);
        }
        return users;
    }

    public TLRPC.Chat getChat(int chat_id) {
        try {
            ArrayList<TLRPC.Chat> chats = new ArrayList<>();
            getChatsInternal("" + chat_id, chats);
            if (chats.isEmpty()) {
                return null;
            }
            TLRPC.Chat chat = chats.get(0);
            return chat;
        } catch (Exception e) {
            FileLog.e("getChat ---> exception " + e);
            return null;
        }
    }

    public TLRPC.EncryptedChat getEncryptedChat(int chat_id) {
        try {
            ArrayList<TLRPC.EncryptedChat> encryptedChats = new ArrayList<>();
            getEncryptedChatsInternal("" + chat_id, encryptedChats, null);
            if (encryptedChats.isEmpty()) {
                return null;
            }
            TLRPC.EncryptedChat chat = encryptedChats.get(0);
            return chat;
        } catch (Exception e) {
            FileLog.e("getEncryptedChat ---> exception " + e);
            return null;
        }
    }

    public void saveContactsApplyInfo(ArrayList<TLRPCContacts.ContactApplyInfo> infos) throws Exception {
        if (infos == null || infos.isEmpty()) {
            return;
        }
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast("REPLACE INTO contacts_apply_info VALUES(?, ?, ?, ?, ?, ?, ?)");
                for (int i = 0; i < infos.size(); i++) {
                    TLRPCContacts.ContactApplyInfo info = infos.get(i);
                    state.requery();
                    state.bindInteger(1, info.id);
                    state.bindInteger(2, info.for_apply_id);
                    state.bindInteger(3, info.from_peer.user_id);
                    state.bindInteger(4, info.state);
                    state.bindString(5, info.greet);
                    state.bindInteger(6, info.date);
                    state.bindInteger(7, info.expire);
                    state.step();
                }
                state.dispose();
                state = null;
            } catch (Exception e) {
                FileLog.e("saveContactsApplyInfo ---> exception " + e);
                throw new Exception(e);
            }
        } finally {
            if (state != null) {
                state.dispose();
            }
        }
    }

    public void putInternalContactsApplyInfos(final ArrayList<TLRPCContacts.ContactApplyInfo> infos) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$0apfjnL9aXOGRWuoPyVVEWVwLw4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putInternalContactsApplyInfos$154$MessagesStorage(infos);
            }
        });
    }

    public /* synthetic */ void lambda$putInternalContactsApplyInfos$154$MessagesStorage(ArrayList infos) {
        try {
            saveContactsApplyInfo(infos);
        } catch (Exception e) {
            FileLog.e("putInternalContactsApplyInfos ---> exception " + e);
        }
    }

    public ArrayList<TLRPCContacts.ContactApplyInfo> getContactsApplyInfos() {
        SQLiteCursor cursor = null;
        try {
            try {
                ArrayList<TLRPCContacts.ContactApplyInfo> applyInfos = new ArrayList<>();
                cursor = this.database.queryFinalized("SELECT apply_id, uid, state, greet, date, expire FROM contacts_apply_info WHERE for_apply_id =0 ORDER BY date DESC LIMIT 200", new Object[0]);
                while (cursor.next()) {
                    int apply_id = cursor.intValue(0);
                    int uid = cursor.intValue(1);
                    int state = cursor.intValue(2);
                    String greet = cursor.stringValue(3);
                    int date = cursor.intValue(4);
                    int expire = cursor.intValue(5);
                    TLRPCContacts.ContactApplyInfo info = new TLRPCContacts.ContactApplyInfo();
                    info.id = apply_id;
                    info.from_peer = getMessagesController().getPeer(uid);
                    info.state = state;
                    info.for_apply_id = 0;
                    info.expire = expire;
                    info.date = date;
                    info.greet = greet;
                    applyInfos.add(info);
                }
                cursor.dispose();
                SQLiteCursor cursor2 = null;
                if (0 != 0) {
                    cursor2.dispose();
                }
                return applyInfos;
            } catch (Exception e) {
                FileLog.e("getContactsApplyInfos ---> exception ", e);
                if (cursor == null) {
                    return null;
                }
                cursor.dispose();
                return null;
            }
        } catch (Throwable th) {
            if (cursor != null) {
                cursor.dispose();
            }
            throw th;
        }
    }

    public void deleteContactsApply() {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$Vqx2EjP3qVE0s3P5Eml83VYr3HA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$deleteContactsApply$155$MessagesStorage();
            }
        });
    }

    public /* synthetic */ void lambda$deleteContactsApply$155$MessagesStorage() {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast("DELETE FROM contacts_apply_info");
                state.stepThis().dispose();
                state = null;
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("deleteContactsApply ---> exception ", e);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void deleteContactsApply(final ArrayList<Integer> ids) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$RskFkhNnxqsGHFfSkKUNgD5MbnQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$deleteContactsApply$156$MessagesStorage(ids);
            }
        });
    }

    public /* synthetic */ void lambda$deleteContactsApply$156$MessagesStorage(ArrayList ids) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast(String.format(Locale.US, "DELETE FROM contacts_apply_info WHERE apply_id IN(%s)", TextUtils.join(",", ids)));
                state.stepThis().dispose();
                state = null;
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("deleteContactsApply ---> exception ", e);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void deleteContactsApplyByUserId(final ArrayList<Integer> ids) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$ikHN4X4NtB9OBOrk-HmbhBPlPVU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$deleteContactsApplyByUserId$157$MessagesStorage(ids);
            }
        });
    }

    public /* synthetic */ void lambda$deleteContactsApplyByUserId$157$MessagesStorage(ArrayList ids) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast(String.format(Locale.US, "DELETE FROM contacts_apply_info WHERE uid IN(%s)", TextUtils.join(",", ids)));
                state.stepThis().dispose();
                state = null;
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("deleteContactsApplyByUserId ---> exception ", e);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void updateContactsApply(final TLRPCContacts.ContactApplyInfo info) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$UtNG0Z84SsPbHS230Lg8_rNen7Y
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateContactsApply$158$MessagesStorage(info);
            }
        });
    }

    public /* synthetic */ void lambda$updateContactsApply$158$MessagesStorage(TLRPCContacts.ContactApplyInfo info) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast("UPDATE contacts_apply_info SET state = ? WHERE apply_id = ?");
                state.bindInteger(1, info.state);
                state.bindInteger(2, info.id);
                state.step();
                state.dispose();
                state = null;
            } catch (Exception e) {
                FileLog.e("updateContactsApply ---> exception ", e);
                if (state != null) {
                }
            }
            if (0 != 0) {
                state.dispose();
            }
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public void updateContactsApplyByUserIds(final ArrayList<Integer> ids) {
        this.storageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesStorage$kL3l_dC-rnmaeoJ3svibd6noJEE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateContactsApplyByUserIds$159$MessagesStorage(ids);
            }
        });
    }

    public /* synthetic */ void lambda$updateContactsApplyByUserIds$159$MessagesStorage(ArrayList ids) {
        SQLitePreparedStatement state = null;
        try {
            try {
                state = this.database.executeFast(String.format(Locale.US, "UPDATE contacts_apply_info SET state = 1 WHERE uid IN(%s)", TextUtils.join(",", ids)));
                state.stepThis().dispose();
                state = null;
                if (0 == 0) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e("updateContactsApplyByUserIds ---> exception ", e);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }
}
