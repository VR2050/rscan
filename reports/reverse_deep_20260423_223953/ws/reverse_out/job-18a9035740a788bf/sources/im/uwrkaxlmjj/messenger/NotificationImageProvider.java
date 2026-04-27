package im.uwrkaxlmjj.messenger;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.UriMatcher;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.text.TextUtils;
import com.google.android.exoplayer2.C;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public class NotificationImageProvider extends ContentProvider implements NotificationCenter.NotificationCenterDelegate {
    public static final String AUTHORITY = "singansfg.uwrkaxlmjj.sdancsuhsfj.notification_image_provider";
    private static final UriMatcher matcher;
    private HashSet<String> waitingForFiles = new HashSet<>();
    private final Object sync = new Object();
    private HashMap<String, Long> fileStartTimes = new HashMap<>();

    static {
        UriMatcher uriMatcher = new UriMatcher(-1);
        matcher = uriMatcher;
        uriMatcher.addURI(AUTHORITY, "msg_media_raw/#/*", 1);
    }

    @Override // android.content.ContentProvider
    public boolean onCreate() {
        for (int i = 0; i < UserConfig.getActivatedAccountsCount(); i++) {
            NotificationCenter.getInstance(i).addObserver(this, NotificationCenter.fileDidLoad);
        }
        return true;
    }

    @Override // android.content.ContentProvider
    public void shutdown() {
        for (int i = 0; i < UserConfig.getActivatedAccountsCount(); i++) {
            NotificationCenter.getInstance(i).removeObserver(this, NotificationCenter.fileDidLoad);
        }
    }

    @Override // android.content.ContentProvider
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override // android.content.ContentProvider
    public String getType(Uri uri) {
        return null;
    }

    @Override // android.content.ContentProvider
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override // android.content.ContentProvider
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override // android.content.ContentProvider
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override // android.content.ContentProvider
    public String[] getStreamTypes(Uri uri, String mimeTypeFilter) {
        if (mimeTypeFilter.startsWith("*/") || mimeTypeFilter.startsWith("image/")) {
            return new String[]{"image/jpeg", "image/png", "image/webp"};
        }
        return null;
    }

    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:68:? -> B:52:0x00ee). Please report as a decompilation issue!!! */
    @Override // android.content.ContentProvider
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws Throwable {
        Long _startTime;
        if (!"r".equals(mode)) {
            throw new SecurityException("Can only open files for read");
        }
        if (matcher.match(uri) == 1) {
            List<String> path = uri.getPathSegments();
            Integer.parseInt(path.get(1));
            String name = path.get(2);
            String finalPath = uri.getQueryParameter("final_path");
            String fallbackPath = uri.getQueryParameter("fallback");
            File finalFile = new File(finalPath);
            ApplicationLoader.postInitApplication();
            if (AndroidUtilities.isInternalUri(Uri.fromFile(finalFile))) {
                throw new SecurityException("trying to read internal file");
            }
            boolean zExists = finalFile.exists();
            int i = C.ENCODING_PCM_MU_LAW;
            if (zExists) {
                return ParcelFileDescriptor.open(finalFile, C.ENCODING_PCM_MU_LAW);
            }
            Long _startTime2 = this.fileStartTimes.get(name);
            long startTime = _startTime2 != null ? _startTime2.longValue() : System.currentTimeMillis();
            if (_startTime2 == null) {
                this.fileStartTimes.put(name, Long.valueOf(startTime));
            }
            while (!finalFile.exists()) {
                if (System.currentTimeMillis() - startTime >= 3000) {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.w("Waiting for " + name + " to download timed out");
                    }
                    if (TextUtils.isEmpty(fallbackPath)) {
                        throw new FileNotFoundException("Download timed out");
                    }
                    File file = new File(fallbackPath);
                    if (AndroidUtilities.isInternalUri(Uri.fromFile(file))) {
                        throw new SecurityException("trying to read internal file");
                    }
                    return ParcelFileDescriptor.open(file, i);
                }
                synchronized (this.sync) {
                    try {
                        this.waitingForFiles.add(name);
                        try {
                            _startTime = _startTime2;
                        } catch (InterruptedException e) {
                            _startTime = _startTime2;
                        }
                    } catch (Throwable th) {
                        th = th;
                        throw th;
                    }
                    try {
                        try {
                            this.sync.wait(1000L);
                        } catch (InterruptedException e2) {
                        }
                    } catch (Throwable th2) {
                        th = th2;
                        throw th;
                    }
                }
                _startTime2 = _startTime;
                i = C.ENCODING_PCM_MU_LAW;
            }
            return ParcelFileDescriptor.open(finalFile, C.ENCODING_PCM_MU_LAW);
        }
        throw new FileNotFoundException("Invalid URI");
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.fileDidLoad) {
            synchronized (this.sync) {
                String name = (String) args[0];
                if (this.waitingForFiles.remove(name)) {
                    this.fileStartTimes.remove(name);
                    this.sync.notifyAll();
                }
            }
        }
    }
}
