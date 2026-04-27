package org.webrtc.mozi;

import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/* JADX INFO: loaded from: classes3.dex */
public class MediaCodecCache {
    private static final String TAG = "MediaCodecCache";
    private static final List<MediaCodecInfo> sCodecInfoCache = new CopyOnWriteArrayList();

    public static void initCodecCache() {
        try {
            sCodecInfoCache.clear();
            int count = MediaCodecList.getCodecCount();
            for (int index = 0; index < count; index++) {
                MediaCodecInfo info = MediaCodecList.getCodecInfoAt(index);
                sCodecInfoCache.add(info);
            }
            Logging.d(TAG, "initCodecCache size = " + sCodecInfoCache.size());
        } catch (Throwable e) {
            Logging.e(TAG, "initCodecCache exception", e);
        }
    }

    public static List<MediaCodecInfo> getCodecInfoCache() {
        return sCodecInfoCache;
    }
}
