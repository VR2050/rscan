package p005b.p362y.p363a.p365e;

import android.content.Context;
import java.io.File;
import java.util.Map;
import tv.danmaku.ijk.media.player.IMediaPlayer;

/* renamed from: b.y.a.e.a */
/* loaded from: classes2.dex */
public interface InterfaceC2922a {

    /* renamed from: b.y.a.e.a$a */
    public interface a {
    }

    boolean cachePreview(Context context, File file, String str);

    void clearCache(Context context, File file, String str);

    void doCacheLogic(Context context, IMediaPlayer iMediaPlayer, String str, Map<String, String> map, File file);

    boolean hadCached();

    void release();

    void setCacheAvailableListener(a aVar);
}
