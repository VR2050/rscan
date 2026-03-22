package com.luck.picture.lib.model;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.MediaStore;
import android.text.TextUtils;
import com.luck.picture.lib.C3979R;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.entity.LocalMediaFolder;
import com.luck.picture.lib.entity.MediaData;
import com.luck.picture.lib.listener.OnQueryDataResultListener;
import com.luck.picture.lib.model.LocalMediaPageLoader;
import com.luck.picture.lib.thread.PictureThreadUtils;
import com.luck.picture.lib.tools.MediaUtils;
import com.luck.picture.lib.tools.SdkVersionUtils;
import com.luck.picture.lib.tools.ValueOf;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public final class LocalMediaPageLoader {
    private static final int AUDIO_DURATION = 500;
    private static final String COLUMN_BUCKET_ID = "bucket_id";
    private static final String COLUMN_COUNT = "count";
    private static final long FILE_SIZE_UNIT = 1048576;
    private static final String GROUP_BY_BUCKET_Id = " GROUP BY (bucket_id";
    private static final String NOT_GIF = "!='image/gif' AND mime_type!='image/*'";
    private static final String NOT_GIF_UNKNOWN = "!='image/*'";
    private static final String ORDER_BY = "_id DESC";
    private static final String SELECTION = "(media_type=? ) AND _size>0) GROUP BY (bucket_id";
    private static final String SELECTION_29 = "media_type=?  AND _size>0";
    private static final String SELECTION_NOT_GIF = "(media_type=? AND mime_type!='image/gif' AND mime_type!='image/*') AND _size>0) GROUP BY (bucket_id";
    private static final String SELECTION_NOT_GIF_29 = "media_type=? AND mime_type!='image/gif' AND mime_type!='image/*' AND _size>0";
    private static final String SELECTION_SPECIFIED_FORMAT = "(media_type=? AND mime_type";
    private static final String SELECTION_SPECIFIED_FORMAT_29 = "media_type=? AND mime_type";
    private static final String TAG = "LocalMediaPageLoader";

    /* renamed from: a */
    public static final /* synthetic */ int f10211a = 0;
    private static LocalMediaPageLoader instance;
    private PictureSelectionConfig config = PictureSelectionConfig.getInstance();
    private Context mContext;
    private static final Uri QUERY_URI = MediaStore.Files.getContentUri("external");
    private static final String[] SELECTION_ALL_ARGS = {String.valueOf(1), String.valueOf(3)};
    private static final String COLUMN_BUCKET_DISPLAY_NAME = "bucket_display_name";
    private static final String[] PROJECTION_29 = {"_id", "bucket_id", COLUMN_BUCKET_DISPLAY_NAME, "mime_type"};
    private static final String[] PROJECTION = {"_id", "_data", "bucket_id", COLUMN_BUCKET_DISPLAY_NAME, "mime_type", "COUNT(*) AS count"};
    private static final String[] PROJECTION_PAGE = {"_id", "_data", "mime_type", "width", "height", "duration", "_size", COLUMN_BUCKET_DISPLAY_NAME, "_display_name", "bucket_id"};

    public LocalMediaPageLoader(Context context) {
        this.mContext = context;
    }

    private String getDurationCondition(long j2, long j3) {
        int i2 = this.config.videoMaxSecond;
        long j4 = i2 == 0 ? Long.MAX_VALUE : i2;
        if (j2 != 0) {
            j4 = Math.min(j4, j2);
        }
        Locale locale = Locale.CHINA;
        Object[] objArr = new Object[3];
        objArr[0] = Long.valueOf(Math.max(j3, this.config.videoMinSecond));
        objArr[1] = Math.max(j3, (long) this.config.videoMinSecond) == 0 ? "" : "=";
        objArr[2] = Long.valueOf(j4);
        return String.format(locale, "%d <%s duration and duration <= %d", objArr);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static String getFirstUri(Cursor cursor) {
        return getRealPathAndroid_Q(cursor.getLong(cursor.getColumnIndex("_id")));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static String getFirstUrl(Cursor cursor) {
        return cursor.getString(cursor.getColumnIndex("_data"));
    }

    public static LocalMediaPageLoader getInstance(Context context) {
        if (instance == null) {
            synchronized (LocalMediaPageLoader.class) {
                if (instance == null) {
                    instance = new LocalMediaPageLoader(context.getApplicationContext());
                }
            }
        }
        return instance;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String getPageSelection(long j2) {
        String durationCondition = getDurationCondition(0L, 0L);
        boolean z = !TextUtils.isEmpty(this.config.specifiedFormat);
        int i2 = this.config.chooseMode;
        if (i2 == 0) {
            if (j2 != -1) {
                StringBuilder m586H = C1499a.m586H("(media_type=?");
                C1499a.m608b0(m586H, this.config.isGif ? "" : " AND mime_type!='image/gif' AND mime_type!='image/*'", " OR ", "media_type", "=? AND ");
                C1499a.m608b0(m586H, durationCondition, ") AND ", "bucket_id", "=? AND ");
                return C1499a.m582D(m586H, "_size", ">0");
            }
            StringBuilder m586H2 = C1499a.m586H("(media_type=?");
            C1499a.m608b0(m586H2, this.config.isGif ? "" : " AND mime_type!='image/gif' AND mime_type!='image/*'", " OR ", "media_type", "=? AND ");
            m586H2.append(durationCondition);
            m586H2.append(") AND ");
            m586H2.append("_size");
            m586H2.append(">0");
            return m586H2.toString();
        }
        if (i2 == 1) {
            if (j2 != -1) {
                if (z) {
                    StringBuilder m586H3 = C1499a.m586H("(media_type=?");
                    C1499a.m608b0(m586H3, this.config.isGif ? "" : C1499a.m582D(C1499a.m586H(" AND mime_type!='image/gif' AND mime_type!='image/*' AND mime_type='"), this.config.specifiedFormat, "'"), ") AND ", "bucket_id", "=? AND ");
                    return C1499a.m582D(m586H3, "_size", ">0");
                }
                StringBuilder m586H4 = C1499a.m586H("(media_type=?");
                C1499a.m608b0(m586H4, this.config.isGif ? "" : " AND mime_type!='image/gif' AND mime_type!='image/*'", ") AND ", "bucket_id", "=? AND ");
                return C1499a.m582D(m586H4, "_size", ">0");
            }
            if (z) {
                StringBuilder m590L = C1499a.m590L("(media_type=?", " AND mime_type='");
                C1499a.m608b0(m590L, this.config.specifiedFormat, "'", ") AND ", "_size");
                m590L.append(">0");
                return m590L.toString();
            }
            StringBuilder m586H5 = C1499a.m586H("(media_type=?");
            m586H5.append(this.config.isGif ? "" : " AND mime_type!='image/gif' AND mime_type!='image/*'");
            m586H5.append(") AND ");
            m586H5.append("_size");
            m586H5.append(">0");
            return m586H5.toString();
        }
        if (i2 != 2 && i2 != 3) {
            return null;
        }
        if (j2 == -1) {
            if (z) {
                StringBuilder m586H6 = C1499a.m586H("(media_type=? AND mime_type='");
                C1499a.m608b0(m586H6, this.config.specifiedFormat, "' AND ", durationCondition, ") AND ");
                return C1499a.m582D(m586H6, "_size", ">0");
            }
            return "(media_type=? AND " + durationCondition + ") AND _size>0";
        }
        if (z) {
            StringBuilder m586H7 = C1499a.m586H("(media_type=? AND mime_type='");
            C1499a.m608b0(m586H7, this.config.specifiedFormat, "' AND ", durationCondition, ") AND ");
            m586H7.append("bucket_id");
            m586H7.append("=? AND ");
            m586H7.append("_size");
            m586H7.append(">0");
            return m586H7.toString();
        }
        StringBuilder sb = new StringBuilder();
        sb.append("(media_type=? AND ");
        sb.append(durationCondition);
        sb.append(") AND ");
        sb.append("bucket_id");
        sb.append("=? AND ");
        return C1499a.m582D(sb, "_size", ">0");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String[] getPageSelectionArgs(long j2) {
        int i2 = this.config.chooseMode;
        if (i2 == 0) {
            return j2 == -1 ? new String[]{String.valueOf(1), String.valueOf(3)} : new String[]{String.valueOf(1), String.valueOf(3), ValueOf.toString(Long.valueOf(j2))};
        }
        if (i2 == 1) {
            return getSelectionArgsForPageSingleMediaType(1, j2);
        }
        if (i2 == 2) {
            return getSelectionArgsForPageSingleMediaType(3, j2);
        }
        if (i2 != 3) {
            return null;
        }
        return getSelectionArgsForPageSingleMediaType(2, j2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static String getRealPathAndroid_Q(long j2) {
        return QUERY_URI.buildUpon().appendPath(ValueOf.toString(Long.valueOf(j2))).build().toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String getSelection() {
        PictureSelectionConfig pictureSelectionConfig = this.config;
        int i2 = pictureSelectionConfig.chooseMode;
        if (i2 == 0) {
            return getSelectionArgsForAllMediaCondition(getDurationCondition(0L, 0L), this.config.isGif);
        }
        if (i2 == 1) {
            if (TextUtils.isEmpty(pictureSelectionConfig.specifiedFormat)) {
                return SdkVersionUtils.checkedAndroid_Q() ? this.config.isGif ? SELECTION_29 : SELECTION_NOT_GIF_29 : this.config.isGif ? SELECTION : SELECTION_NOT_GIF;
            }
            if (!SdkVersionUtils.checkedAndroid_Q()) {
                StringBuilder m586H = C1499a.m586H("(media_type=? AND mime_type='");
                C1499a.m608b0(m586H, this.config.specifiedFormat, "') AND ", "_size", ">0)");
                m586H.append(GROUP_BY_BUCKET_Id);
                return m586H.toString();
            }
            StringBuilder m586H2 = C1499a.m586H("media_type=? AND mime_type='");
            m586H2.append(this.config.specifiedFormat);
            m586H2.append("' AND ");
            m586H2.append("_size");
            m586H2.append(">0");
            return m586H2.toString();
        }
        if (i2 == 2) {
            if (TextUtils.isEmpty(pictureSelectionConfig.specifiedFormat)) {
                return getSelectionArgsForSingleMediaCondition(getDurationCondition(0L, 0L));
            }
            if (!SdkVersionUtils.checkedAndroid_Q()) {
                StringBuilder m586H3 = C1499a.m586H("(media_type=? AND mime_type='");
                C1499a.m608b0(m586H3, this.config.specifiedFormat, "') AND ", "_size", ">0)");
                m586H3.append(GROUP_BY_BUCKET_Id);
                return m586H3.toString();
            }
            StringBuilder m586H4 = C1499a.m586H("media_type=? AND mime_type='");
            m586H4.append(this.config.specifiedFormat);
            m586H4.append("' AND ");
            m586H4.append("_size");
            m586H4.append(">0");
            return m586H4.toString();
        }
        if (i2 != 3) {
            return null;
        }
        if (TextUtils.isEmpty(pictureSelectionConfig.specifiedFormat)) {
            return getSelectionArgsForSingleMediaCondition(getDurationCondition(0L, 500L));
        }
        if (!SdkVersionUtils.checkedAndroid_Q()) {
            StringBuilder m586H5 = C1499a.m586H("(media_type=? AND mime_type='");
            C1499a.m608b0(m586H5, this.config.specifiedFormat, "') AND ", "_size", ">0)");
            m586H5.append(GROUP_BY_BUCKET_Id);
            return m586H5.toString();
        }
        StringBuilder m586H6 = C1499a.m586H("media_type=? AND mime_type='");
        m586H6.append(this.config.specifiedFormat);
        m586H6.append("' AND ");
        m586H6.append("_size");
        m586H6.append(">0");
        return m586H6.toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String[] getSelectionArgs() {
        int i2 = this.config.chooseMode;
        if (i2 == 0) {
            return SELECTION_ALL_ARGS;
        }
        if (i2 == 1) {
            return getSelectionArgsForSingleMediaType(1);
        }
        if (i2 == 2) {
            return getSelectionArgsForSingleMediaType(3);
        }
        if (i2 != 3) {
            return null;
        }
        return getSelectionArgsForSingleMediaType(2);
    }

    private static String getSelectionArgsForAllMediaCondition(String str, boolean z) {
        if (SdkVersionUtils.checkedAndroid_Q()) {
            StringBuilder m586H = C1499a.m586H("(media_type=?");
            C1499a.m608b0(m586H, z ? "" : " AND mime_type!='image/gif' AND mime_type!='image/*'", " OR ", "media_type", "=? AND ");
            m586H.append(str);
            m586H.append(") AND ");
            m586H.append("_size");
            m586H.append(">0");
            return m586H.toString();
        }
        StringBuilder m586H2 = C1499a.m586H("(media_type=?");
        C1499a.m608b0(m586H2, z ? "" : " AND mime_type!='image/gif' AND mime_type!='image/*'", " OR ", "media_type=? AND ", str);
        m586H2.append(") AND ");
        m586H2.append("_size");
        m586H2.append(">0)");
        m586H2.append(GROUP_BY_BUCKET_Id);
        return m586H2.toString();
    }

    private static String[] getSelectionArgsForPageSingleMediaType(int i2, long j2) {
        return j2 == -1 ? new String[]{String.valueOf(i2)} : new String[]{String.valueOf(i2), ValueOf.toString(Long.valueOf(j2))};
    }

    private static String getSelectionArgsForSingleMediaCondition(String str) {
        if (SdkVersionUtils.checkedAndroid_Q()) {
            return C1499a.m637w("media_type=? AND _size>0 AND ", str);
        }
        return "(media_type=?) AND _size>0 AND " + str + ChineseToPinyinResource.Field.RIGHT_BRACKET + GROUP_BY_BUCKET_Id;
    }

    private static String[] getSelectionArgsForSingleMediaType(int i2) {
        return new String[]{String.valueOf(i2)};
    }

    public static void setInstanceNull() {
        instance = null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sortFolder(List<LocalMediaFolder> list) {
        Collections.sort(list, new Comparator() { // from class: b.t.a.a.k0.b
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                LocalMediaFolder localMediaFolder = (LocalMediaFolder) obj;
                LocalMediaFolder localMediaFolder2 = (LocalMediaFolder) obj2;
                int i2 = LocalMediaPageLoader.f10211a;
                if (localMediaFolder.getData() == null || localMediaFolder2.getData() == null) {
                    return 0;
                }
                return Integer.compare(localMediaFolder2.getImageNum(), localMediaFolder.getImageNum());
            }
        });
    }

    public String getFirstCover(long j2) {
        Cursor cursor;
        Cursor cursor2 = null;
        try {
            Cursor query = SdkVersionUtils.checkedAndroid_R() ? this.mContext.getContentResolver().query(QUERY_URI, new String[]{"_id", "_data"}, MediaUtils.createQueryArgsBundle(getPageSelection(j2), getPageSelectionArgs(j2), 1, 0), null) : this.mContext.getContentResolver().query(QUERY_URI, new String[]{"_id", "_data"}, getPageSelection(j2), getPageSelectionArgs(j2), "_id DESC limit 1 offset 0");
            if (query != null) {
                try {
                    if (query.getCount() > 0) {
                        if (!query.moveToFirst()) {
                            if (!query.isClosed()) {
                                query.close();
                            }
                            return null;
                        }
                        String realPathAndroid_Q = SdkVersionUtils.checkedAndroid_Q() ? getRealPathAndroid_Q(query.getLong(query.getColumnIndexOrThrow("_id"))) : query.getString(query.getColumnIndexOrThrow("_data"));
                        if (!query.isClosed()) {
                            query.close();
                        }
                        return realPathAndroid_Q;
                    }
                } catch (Exception e2) {
                    cursor = query;
                    e = e2;
                    try {
                        e.printStackTrace();
                        if (cursor != null && !cursor.isClosed()) {
                            cursor.close();
                        }
                        return null;
                    } catch (Throwable th) {
                        th = th;
                        cursor2 = cursor;
                        if (cursor2 != null && !cursor2.isClosed()) {
                            cursor2.close();
                        }
                        throw th;
                    }
                } catch (Throwable th2) {
                    cursor2 = query;
                    th = th2;
                    if (cursor2 != null) {
                        cursor2.close();
                    }
                    throw th;
                }
            }
            if (query != null && !query.isClosed()) {
                query.close();
            }
        } catch (Exception e3) {
            e = e3;
            cursor = null;
        } catch (Throwable th3) {
            th = th3;
        }
        return null;
    }

    public void loadAllMedia(final OnQueryDataResultListener<LocalMediaFolder> onQueryDataResultListener) {
        PictureThreadUtils.executeByIo(new PictureThreadUtils.SimpleTask<List<LocalMediaFolder>>() { // from class: com.luck.picture.lib.model.LocalMediaPageLoader.2
            @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
            public List<LocalMediaFolder> doInBackground() {
                int i2;
                Cursor query = LocalMediaPageLoader.this.mContext.getContentResolver().query(LocalMediaPageLoader.QUERY_URI, SdkVersionUtils.checkedAndroid_Q() ? LocalMediaPageLoader.PROJECTION_29 : LocalMediaPageLoader.PROJECTION, LocalMediaPageLoader.this.getSelection(), LocalMediaPageLoader.this.getSelectionArgs(), LocalMediaPageLoader.ORDER_BY);
                if (query != null) {
                    try {
                        try {
                            int count = query.getCount();
                            ArrayList arrayList = new ArrayList();
                            if (count > 0) {
                                if (SdkVersionUtils.checkedAndroid_Q()) {
                                    HashMap hashMap = new HashMap();
                                    while (query.moveToNext()) {
                                        long j2 = query.getLong(query.getColumnIndex("bucket_id"));
                                        Long l2 = (Long) hashMap.get(Long.valueOf(j2));
                                        hashMap.put(Long.valueOf(j2), l2 == null ? 1L : Long.valueOf(l2.longValue() + 1));
                                    }
                                    if (query.moveToFirst()) {
                                        HashSet hashSet = new HashSet();
                                        i2 = 0;
                                        do {
                                            long j3 = query.getLong(query.getColumnIndex("bucket_id"));
                                            if (!hashSet.contains(Long.valueOf(j3))) {
                                                LocalMediaFolder localMediaFolder = new LocalMediaFolder();
                                                localMediaFolder.setBucketId(j3);
                                                String string = query.getString(query.getColumnIndex(LocalMediaPageLoader.COLUMN_BUCKET_DISPLAY_NAME));
                                                long longValue = ((Long) hashMap.get(Long.valueOf(j3))).longValue();
                                                long j4 = query.getLong(query.getColumnIndex("_id"));
                                                localMediaFolder.setName(string);
                                                localMediaFolder.setImageNum(ValueOf.toInt(Long.valueOf(longValue)));
                                                localMediaFolder.setFirstImagePath(LocalMediaPageLoader.getRealPathAndroid_Q(j4));
                                                arrayList.add(localMediaFolder);
                                                hashSet.add(Long.valueOf(j3));
                                                i2 = (int) (i2 + longValue);
                                            }
                                        } while (query.moveToNext());
                                    } else {
                                        i2 = 0;
                                    }
                                } else {
                                    query.moveToFirst();
                                    int i3 = 0;
                                    do {
                                        LocalMediaFolder localMediaFolder2 = new LocalMediaFolder();
                                        long j5 = query.getLong(query.getColumnIndex("bucket_id"));
                                        String string2 = query.getString(query.getColumnIndex(LocalMediaPageLoader.COLUMN_BUCKET_DISPLAY_NAME));
                                        int i4 = query.getInt(query.getColumnIndex("count"));
                                        localMediaFolder2.setBucketId(j5);
                                        localMediaFolder2.setFirstImagePath(query.getString(query.getColumnIndex("_data")));
                                        localMediaFolder2.setName(string2);
                                        localMediaFolder2.setImageNum(i4);
                                        arrayList.add(localMediaFolder2);
                                        i3 += i4;
                                    } while (query.moveToNext());
                                    i2 = i3;
                                }
                                LocalMediaPageLoader.this.sortFolder(arrayList);
                                LocalMediaFolder localMediaFolder3 = new LocalMediaFolder();
                                localMediaFolder3.setImageNum(i2);
                                localMediaFolder3.setChecked(true);
                                localMediaFolder3.setBucketId(-1L);
                                if (query.moveToFirst()) {
                                    localMediaFolder3.setFirstImagePath(SdkVersionUtils.checkedAndroid_Q() ? LocalMediaPageLoader.getFirstUri(query) : LocalMediaPageLoader.getFirstUrl(query));
                                }
                                localMediaFolder3.setName(LocalMediaPageLoader.this.config.chooseMode == PictureMimeType.ofAudio() ? LocalMediaPageLoader.this.mContext.getString(C3979R.string.picture_all_audio) : LocalMediaPageLoader.this.mContext.getString(C3979R.string.picture_camera_roll));
                                localMediaFolder3.setOfAllType(LocalMediaPageLoader.this.config.chooseMode);
                                localMediaFolder3.setCameraFolder(true);
                                arrayList.add(0, localMediaFolder3);
                                if (!query.isClosed()) {
                                    query.close();
                                }
                                return arrayList;
                            }
                        } catch (Exception e2) {
                            e2.printStackTrace();
                            String unused = LocalMediaPageLoader.TAG;
                            e2.getMessage();
                            if (!query.isClosed()) {
                                query.close();
                            }
                            return null;
                        }
                    } catch (Throwable th) {
                        if (!query.isClosed()) {
                            query.close();
                        }
                        throw th;
                    }
                }
                if (query != null && !query.isClosed()) {
                    query.close();
                }
                return new ArrayList();
            }

            @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
            public void onSuccess(List<LocalMediaFolder> list) {
                OnQueryDataResultListener onQueryDataResultListener2 = onQueryDataResultListener;
                if (onQueryDataResultListener2 == null || list == null) {
                    return;
                }
                onQueryDataResultListener2.onComplete(list, 1, false);
            }
        });
    }

    public void loadPageMediaData(long j2, int i2, int i3, OnQueryDataResultListener onQueryDataResultListener) {
        loadPageMediaData(j2, i2, i3, this.config.pageSize, onQueryDataResultListener);
    }

    public void loadPageMediaData(long j2, int i2, OnQueryDataResultListener<LocalMedia> onQueryDataResultListener) {
        int i3 = this.config.pageSize;
        loadPageMediaData(j2, i2, i3, i3, onQueryDataResultListener);
    }

    public void loadPageMediaData(final long j2, final int i2, final int i3, final int i4, final OnQueryDataResultListener<LocalMedia> onQueryDataResultListener) {
        PictureThreadUtils.executeByIo(new PictureThreadUtils.SimpleTask<MediaData>() { // from class: com.luck.picture.lib.model.LocalMediaPageLoader.1
            /* JADX WARN: Not initialized variable reg: 4, insn: 0x028d: MOVE (r2 I:??[OBJECT, ARRAY]) = (r4 I:??[OBJECT, ARRAY]), block:B:122:0x028d */
            /* JADX WARN: Removed duplicated region for block: B:36:0x0243 A[LOOP:0: B:26:0x0117->B:36:0x0243, LOOP_END] */
            /* JADX WARN: Removed duplicated region for block: B:37:0x0242 A[EDGE_INSN: B:37:0x0242->B:38:0x0242 BREAK  A[LOOP:0: B:26:0x0117->B:36:0x0243], SYNTHETIC] */
            @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public com.luck.picture.lib.entity.MediaData doInBackground() {
                /*
                    Method dump skipped, instructions count: 666
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.luck.picture.lib.model.LocalMediaPageLoader.C39991.doInBackground():com.luck.picture.lib.entity.MediaData");
            }

            @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
            public void onSuccess(MediaData mediaData) {
                OnQueryDataResultListener onQueryDataResultListener2 = onQueryDataResultListener;
                if (onQueryDataResultListener2 == null || mediaData == null) {
                    return;
                }
                onQueryDataResultListener2.onComplete(mediaData.data, i2, mediaData.isHasNextMore);
            }
        });
    }
}
