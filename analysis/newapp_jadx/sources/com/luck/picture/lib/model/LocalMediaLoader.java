package com.luck.picture.lib.model;

import android.content.Context;
import android.net.Uri;
import android.provider.MediaStore;
import android.text.TextUtils;
import com.luck.picture.lib.config.PictureConfig;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.entity.LocalMediaFolder;
import com.luck.picture.lib.model.LocalMediaLoader;
import com.luck.picture.lib.tools.SdkVersionUtils;
import com.luck.picture.lib.tools.ValueOf;
import java.io.File;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import p005b.p131d.p132a.p133a.C1499a;

@Deprecated
/* loaded from: classes2.dex */
public final class LocalMediaLoader {
    private static final int AUDIO_DURATION = 500;
    private static final long FILE_SIZE_UNIT = 1048576;
    private static final String NOT_GIF = "!='image/gif'";
    private static final String ORDER_BY = "_id DESC";
    private static final String SELECTION = "media_type=? AND _size>0";
    private static final String SELECTION_NOT_GIF = "media_type=? AND _size>0 AND mime_type!='image/gif'";
    private static final String SELECTION_SPECIFIED_FORMAT = "media_type=? AND _size>0 AND mime_type";
    private static final String TAG = "LocalMediaLoader";

    /* renamed from: a */
    public static final /* synthetic */ int f10210a = 0;
    private Context mContext;
    private static final Uri QUERY_URI = MediaStore.Files.getContentUri("external");
    private static final String[] PROJECTION = {"_id", "_data", "mime_type", "width", "height", "duration", "_size", "bucket_display_name", "_display_name", PictureConfig.EXTRA_BUCKET_ID};
    private static final String[] SELECTION_ALL_ARGS = {String.valueOf(1), String.valueOf(3)};
    private boolean isAndroidQ = SdkVersionUtils.checkedAndroid_Q();
    private PictureSelectionConfig config = PictureSelectionConfig.getInstance();

    public LocalMediaLoader(Context context) {
        this.mContext = context.getApplicationContext();
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

    private LocalMediaFolder getImageFolder(String str, String str2, List<LocalMediaFolder> list) {
        if (!this.config.isFallbackVersion) {
            for (LocalMediaFolder localMediaFolder : list) {
                String name = localMediaFolder.getName();
                if (!TextUtils.isEmpty(name) && name.equals(str2)) {
                    return localMediaFolder;
                }
            }
            LocalMediaFolder localMediaFolder2 = new LocalMediaFolder();
            localMediaFolder2.setName(str2);
            localMediaFolder2.setFirstImagePath(str);
            list.add(localMediaFolder2);
            return localMediaFolder2;
        }
        File parentFile = new File(str).getParentFile();
        for (LocalMediaFolder localMediaFolder3 : list) {
            String name2 = localMediaFolder3.getName();
            if (!TextUtils.isEmpty(name2) && parentFile != null && name2.equals(parentFile.getName())) {
                return localMediaFolder3;
            }
        }
        LocalMediaFolder localMediaFolder4 = new LocalMediaFolder();
        localMediaFolder4.setName(parentFile != null ? parentFile.getName() : "");
        localMediaFolder4.setFirstImagePath(str);
        list.add(localMediaFolder4);
        return localMediaFolder4;
    }

    private String getRealPathAndroid_Q(long j2) {
        return QUERY_URI.buildUpon().appendPath(ValueOf.toString(Long.valueOf(j2))).build().toString();
    }

    private String getSelection() {
        PictureSelectionConfig pictureSelectionConfig = this.config;
        int i2 = pictureSelectionConfig.chooseMode;
        if (i2 == 0) {
            return getSelectionArgsForAllMediaCondition(getDurationCondition(0L, 0L), this.config.isGif);
        }
        if (i2 == 1) {
            return !TextUtils.isEmpty(pictureSelectionConfig.specifiedFormat) ? C1499a.m582D(C1499a.m586H("media_type=? AND _size>0 AND mime_type='"), this.config.specifiedFormat, "'") : this.config.isGif ? SELECTION : SELECTION_NOT_GIF;
        }
        if (i2 == 2) {
            return !TextUtils.isEmpty(pictureSelectionConfig.specifiedFormat) ? C1499a.m582D(C1499a.m586H("media_type=? AND _size>0 AND mime_type='"), this.config.specifiedFormat, "'") : getSelectionArgsForSingleMediaCondition();
        }
        if (i2 != 3) {
            return null;
        }
        return !TextUtils.isEmpty(pictureSelectionConfig.specifiedFormat) ? C1499a.m582D(C1499a.m586H("media_type=? AND _size>0 AND mime_type='"), this.config.specifiedFormat, "'") : getSelectionArgsForSingleMediaCondition(getDurationCondition(0L, 500L));
    }

    private String[] getSelectionArgs() {
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
        StringBuilder m586H = C1499a.m586H("(media_type=?");
        C1499a.m608b0(m586H, z ? "" : " AND mime_type!='image/gif'", " OR ", "media_type=? AND ", str);
        return C1499a.m583E(m586H, ") AND ", "_size", ">0");
    }

    private static String getSelectionArgsForSingleMediaCondition() {
        return SELECTION;
    }

    private static String getSelectionArgsForSingleMediaCondition(String str) {
        return C1499a.m637w("media_type=? AND _size>0 AND ", str);
    }

    private static String[] getSelectionArgsForSingleMediaType(int i2) {
        return new String[]{String.valueOf(i2)};
    }

    private void sortFolder(List<LocalMediaFolder> list) {
        Collections.sort(list, new Comparator() { // from class: b.t.a.a.k0.a
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                LocalMediaFolder localMediaFolder = (LocalMediaFolder) obj;
                LocalMediaFolder localMediaFolder2 = (LocalMediaFolder) obj2;
                int i2 = LocalMediaLoader.f10210a;
                if (localMediaFolder.getData() == null || localMediaFolder2.getData() == null) {
                    return 0;
                }
                return Integer.compare(localMediaFolder2.getImageNum(), localMediaFolder.getImageNum());
            }
        });
    }

    /* JADX WARN: Code restructure failed: missing block: B:66:0x014e, code lost:
    
        if (r24 < r3) goto L49;
     */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0204 A[LOOP:0: B:16:0x0080->B:37:0x0204, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:38:0x01b8 A[EDGE_INSN: B:38:0x01b8->B:39:0x01b8 BREAK  A[LOOP:0: B:16:0x0080->B:37:0x0204], SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.util.List<com.luck.picture.lib.entity.LocalMediaFolder> loadAllMedia() {
        /*
            Method dump skipped, instructions count: 588
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.luck.picture.lib.model.LocalMediaLoader.loadAllMedia():java.util.List");
    }
}
