package tv.danmaku.ijk.media.exo2;

import android.content.Context;
import android.net.Uri;
import java.io.File;
import java.util.Map;
import p005b.p362y.p363a.p365e.InterfaceC2922a;
import tv.danmaku.ijk.media.player.IMediaPlayer;

/* loaded from: classes3.dex */
public class ExoPlayerCacheManager implements InterfaceC2922a {
    public ExoSourceManager mExoSourceManager;

    @Override // p005b.p362y.p363a.p365e.InterfaceC2922a
    public boolean cachePreview(Context context, File file, String str) {
        return ExoSourceManager.cachePreView(context, file, str);
    }

    @Override // p005b.p362y.p363a.p365e.InterfaceC2922a
    public void clearCache(Context context, File file, String str) {
        ExoSourceManager.clearCache(context, file, str);
    }

    @Override // p005b.p362y.p363a.p365e.InterfaceC2922a
    public void doCacheLogic(Context context, IMediaPlayer iMediaPlayer, String str, Map<String, String> map, File file) {
        if (!(iMediaPlayer instanceof IjkExo2MediaPlayer)) {
            throw new UnsupportedOperationException("ExoPlayerCacheManager only support IjkExo2MediaPlayer");
        }
        IjkExo2MediaPlayer ijkExo2MediaPlayer = (IjkExo2MediaPlayer) iMediaPlayer;
        this.mExoSourceManager = ijkExo2MediaPlayer.getExoHelper();
        ijkExo2MediaPlayer.setCache(true);
        ijkExo2MediaPlayer.setCacheDir(file);
        ijkExo2MediaPlayer.setDataSource(context, Uri.parse(str), map);
    }

    @Override // p005b.p362y.p363a.p365e.InterfaceC2922a
    public boolean hadCached() {
        ExoSourceManager exoSourceManager = this.mExoSourceManager;
        return exoSourceManager != null && exoSourceManager.hadCached();
    }

    @Override // p005b.p362y.p363a.p365e.InterfaceC2922a
    public void release() {
        this.mExoSourceManager = null;
    }

    @Override // p005b.p362y.p363a.p365e.InterfaceC2922a
    public void setCacheAvailableListener(InterfaceC2922a.a aVar) {
    }
}
