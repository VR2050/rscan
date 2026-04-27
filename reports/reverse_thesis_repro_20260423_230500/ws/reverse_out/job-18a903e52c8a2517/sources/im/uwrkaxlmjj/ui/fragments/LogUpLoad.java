package im.uwrkaxlmjj.ui.fragments;

import com.google.android.exoplayer2.util.Log;
import im.uwrkaxlmjj.messenger.Utilities;
import okhttp3.MediaType;

/* JADX INFO: loaded from: classes5.dex */
public class LogUpLoad {
    private static final MediaType MEDIA_TYPE_TEXT = MediaType.parse("text/plain; charset=utf-8");
    private static final MediaType MEDIA_TYPE_BINARY = MediaType.parse("application/octet-stream");

    public static void uploadLogFile(final int uid) {
        Log.d("bond", "开始日志上传");
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$LogUpLoad$CMosUyUUq8sAjV_yQYP0aM4DZDo
            @Override // java.lang.Runnable
            public final void run() {
                LogUpLoad.lambda$uploadLogFile$0(uid);
            }
        });
    }

    /* JADX WARN: Can't wrap try/catch for region: R(13:60|(6:59|8|(4:11|(2:12|(1:14))|15|9)|62|16|(1:18))|20|30|31|32|33|57|34|(1:36)(1:37)|56|41|64) */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x0165, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x0166, code lost:
    
        com.google.android.exoplayer2.util.Log.d("bond", "日志上传错误 = " + r0.getMessage());
     */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0126 A[Catch: IOException -> 0x0165, Exception -> 0x0185, TryCatch #1 {IOException -> 0x0165, blocks: (B:34:0x0113, B:36:0x0126, B:37:0x0136), top: B:57:0x0113, outer: #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0136 A[Catch: IOException -> 0x0165, Exception -> 0x0185, TRY_LEAVE, TryCatch #1 {IOException -> 0x0165, blocks: (B:34:0x0113, B:36:0x0126, B:37:0x0136), top: B:57:0x0113, outer: #2 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static /* synthetic */ void lambda$uploadLogFile$0(int r17) {
        /*
            Method dump skipped, instruction units count: 405
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.fragments.LogUpLoad.lambda$uploadLogFile$0(int):void");
    }
}
