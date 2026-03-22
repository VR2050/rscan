package tv.danmaku.ijk.media.exo2;

import android.content.Context;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.view.Surface;
import android.view.SurfaceHolder;
import androidx.annotation.Nullable;
import androidx.annotation.Size;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.source.TrackGroupArray;
import com.google.android.exoplayer2.trackselection.DefaultTrackSelector;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import p005b.p199l.p200a.p201a.AbstractC2404x0;
import p005b.p199l.p200a.p201a.C1906a0;
import p005b.p199l.p200a.p201a.C1936b0;
import p005b.p199l.p200a.p201a.C1940c0;
import p005b.p199l.p200a.p201a.C2251m0;
import p005b.p199l.p200a.p201a.C2262n0;
import p005b.p199l.p200a.p201a.C2336p0;
import p005b.p199l.p200a.p201a.C2393s;
import p005b.p199l.p200a.p201a.C2400v0;
import p005b.p199l.p200a.p201a.C2402w0;
import p005b.p199l.p200a.p201a.C2405y;
import p005b.p199l.p200a.p201a.InterfaceC2077h0;
import p005b.p199l.p200a.p201a.InterfaceC2368q0;
import p005b.p199l.p200a.p201a.p202a1.C1917i;
import p005b.p199l.p200a.p201a.p202a1.InterfaceC1919k;
import p005b.p199l.p200a.p201a.p204c1.C1944d;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z;
import p005b.p199l.p200a.p201a.p245m1.AbstractC2255d;
import p005b.p199l.p200a.p201a.p245m1.C2258g;
import p005b.p199l.p200a.p201a.p248o1.C2326r;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.InterfaceC2346f;
import p005b.p199l.p200a.p201a.p253z0.C2408a;
import p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b;
import tv.danmaku.ijk.media.exo2.demo.EventLogger;
import tv.danmaku.ijk.media.player.AbstractMediaPlayer;
import tv.danmaku.ijk.media.player.IMediaPlayer;
import tv.danmaku.ijk.media.player.MediaInfo;
import tv.danmaku.ijk.media.player.misc.IjkTrackInfo;

/* loaded from: classes3.dex */
public class IjkExo2MediaPlayer extends AbstractMediaPlayer implements InterfaceC2368q0.a, InterfaceC2409b {
    public static int ON_POSITION_DISCOUNTINUITY = 2702;
    private static final String TAG = "IjkExo2MediaPlayer";
    public boolean isLastReportedPlayWhenReady;
    public Context mAppContext;
    public File mCacheDir;
    public String mDataSource;
    public EventLogger mEventLogger;
    public ExoSourceManager mExoHelper;
    public C2402w0 mInternalPlayer;
    public InterfaceC2077h0 mLoadControl;
    public InterfaceC2202y mMediaSource;
    private String mOverrideExtension;
    public C1906a0 mRendererFactory;
    public C2262n0 mSpeedPlaybackParameters;
    public Surface mSurface;
    public AbstractC2255d mTrackSelector;
    public int mVideoHeight;
    public int mVideoWidth;
    public Map<String, String> mHeaders = new HashMap();
    public boolean isPreparing = true;
    public boolean isBuffering = false;
    public boolean isLooping = false;
    public boolean isPreview = false;
    public boolean isCache = false;
    public int audioSessionId = 0;
    public int lastReportedPlaybackState = 1;

    public IjkExo2MediaPlayer(Context context) {
        this.mAppContext = context.getApplicationContext();
        this.mExoHelper = ExoSourceManager.newInstance(context, this.mHeaders);
    }

    private int getVideoRendererIndex() {
        if (this.mInternalPlayer != null) {
            int i2 = 0;
            while (true) {
                C2402w0 c2402w0 = this.mInternalPlayer;
                c2402w0.m2684U();
                if (i2 >= c2402w0.f6341c.f3251c.length) {
                    break;
                }
                C2402w0 c2402w02 = this.mInternalPlayer;
                c2402w02.m2684U();
                if (c2402w02.f6341c.f3251c[i2].getTrackType() == 2) {
                    return i2;
                }
                i2++;
            }
        }
        return 0;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public int getAudioSessionId() {
        return this.audioSessionId;
    }

    public int getBufferedPercentage() {
        C2402w0 c2402w0 = this.mInternalPlayer;
        if (c2402w0 == null) {
            return 0;
        }
        return c2402w0.m2651F();
    }

    public File getCacheDir() {
        return this.mCacheDir;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public long getCurrentPosition() {
        C2402w0 c2402w0 = this.mInternalPlayer;
        if (c2402w0 == null) {
            return 0L;
        }
        return c2402w0.getCurrentPosition();
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public String getDataSource() {
        return this.mDataSource;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public long getDuration() {
        C2402w0 c2402w0 = this.mInternalPlayer;
        if (c2402w0 == null) {
            return 0L;
        }
        return c2402w0.getDuration();
    }

    public ExoSourceManager getExoHelper() {
        return this.mExoHelper;
    }

    public InterfaceC2077h0 getLoadControl() {
        return this.mLoadControl;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public MediaInfo getMediaInfo() {
        return null;
    }

    public InterfaceC2202y getMediaSource() {
        return this.mMediaSource;
    }

    public String getOverrideExtension() {
        return this.mOverrideExtension;
    }

    public C1906a0 getRendererFactory() {
        return this.mRendererFactory;
    }

    public float getSpeed() {
        C2402w0 c2402w0 = this.mInternalPlayer;
        c2402w0.m2684U();
        return c2402w0.f6341c.f3268t.f5669b;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public IjkTrackInfo[] getTrackInfo() {
        return null;
    }

    public AbstractC2255d getTrackSelector() {
        return this.mTrackSelector;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public int getVideoHeight() {
        return this.mVideoHeight;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public int getVideoSarDen() {
        return 1;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public int getVideoSarNum() {
        return 1;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public int getVideoWidth() {
        return this.mVideoWidth;
    }

    public boolean isCache() {
        return this.isCache;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public boolean isLooping() {
        return this.isLooping;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public boolean isPlayable() {
        return true;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public boolean isPlaying() {
        C2402w0 c2402w0 = this.mInternalPlayer;
        if (c2402w0 == null) {
            return false;
        }
        int mo1354a = c2402w0.mo1354a();
        if (mo1354a == 2 || mo1354a == 3) {
            return this.mInternalPlayer.mo1361h();
        }
        return false;
    }

    public boolean isPreview() {
        return this.isPreview;
    }

    public void onAudioAttributesChanged(InterfaceC2409b.a aVar, C1917i c1917i) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onAudioSessionId(InterfaceC2409b.a aVar, int i2) {
        this.audioSessionId = i2;
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onAudioUnderrun(InterfaceC2409b.a aVar, int i2, long j2, long j3) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onBandwidthEstimate(InterfaceC2409b.a aVar, int i2, long j2, long j3) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onDecoderDisabled(InterfaceC2409b.a aVar, int i2, C1944d c1944d) {
        this.audioSessionId = 0;
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onDecoderEnabled(InterfaceC2409b.a aVar, int i2, C1944d c1944d) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onDecoderInitialized(InterfaceC2409b.a aVar, int i2, String str, long j2) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onDecoderInputFormatChanged(InterfaceC2409b.a aVar, int i2, Format format) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onDownstreamFormatChanged(InterfaceC2409b.a aVar, InterfaceC2203z.c cVar) {
    }

    public void onDrmKeysLoaded(InterfaceC2409b.a aVar) {
    }

    public void onDrmKeysRemoved(InterfaceC2409b.a aVar) {
    }

    public void onDrmKeysRestored(InterfaceC2409b.a aVar) {
    }

    public void onDrmSessionAcquired(InterfaceC2409b.a aVar) {
    }

    public void onDrmSessionManagerError(InterfaceC2409b.a aVar, Exception exc) {
    }

    public void onDrmSessionReleased(InterfaceC2409b.a aVar) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onDroppedVideoFrames(InterfaceC2409b.a aVar, int i2, long j2) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onIsPlayingChanged(InterfaceC2409b.a aVar, boolean z) {
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onIsPlayingChanged(boolean z) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onLoadCanceled(InterfaceC2409b.a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onLoadCompleted(InterfaceC2409b.a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onLoadError(InterfaceC2409b.a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar, IOException iOException, boolean z) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onLoadStarted(InterfaceC2409b.a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onLoadingChanged(InterfaceC2409b.a aVar, boolean z) {
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onLoadingChanged(boolean z) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onMediaPeriodCreated(InterfaceC2409b.a aVar) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onMediaPeriodReleased(InterfaceC2409b.a aVar) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onMetadata(InterfaceC2409b.a aVar, Metadata metadata) {
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onPlaybackParametersChanged(C2262n0 c2262n0) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onPlaybackParametersChanged(InterfaceC2409b.a aVar, C2262n0 c2262n0) {
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onPlaybackSuppressionReasonChanged(int i2) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onPlaybackSuppressionReasonChanged(InterfaceC2409b.a aVar, int i2) {
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onPlayerError(C1936b0 c1936b0) {
        notifyOnError(1, 1);
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onPlayerError(InterfaceC2409b.a aVar, C1936b0 c1936b0) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onPlayerStateChanged(InterfaceC2409b.a aVar, boolean z, int i2) {
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onPlayerStateChanged(boolean z, int i2) {
        if (this.isLastReportedPlayWhenReady != z || this.lastReportedPlaybackState != i2) {
            if (this.isBuffering && (i2 == 3 || i2 == 4)) {
                notifyOnInfo(IMediaPlayer.MEDIA_INFO_BUFFERING_END, this.mInternalPlayer.m2651F());
                this.isBuffering = false;
            }
            if (this.isPreparing && i2 == 3) {
                notifyOnPrepared();
                this.isPreparing = false;
            }
            if (i2 == 2) {
                notifyOnInfo(IMediaPlayer.MEDIA_INFO_BUFFERING_START, this.mInternalPlayer.m2651F());
                this.isBuffering = true;
            } else if (i2 == 4) {
                notifyOnCompletion();
            }
        }
        this.isLastReportedPlayWhenReady = z;
        this.lastReportedPlaybackState = i2;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onPositionDiscontinuity(int i2) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onPositionDiscontinuity(InterfaceC2409b.a aVar, int i2) {
        notifyOnInfo(ON_POSITION_DISCOUNTINUITY, i2);
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onReadingStarted(InterfaceC2409b.a aVar) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onRenderedFirstFrame(InterfaceC2409b.a aVar, Surface surface) {
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onRepeatModeChanged(int i2) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onRepeatModeChanged(InterfaceC2409b.a aVar, int i2) {
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onSeekProcessed() {
        notifyOnSeekComplete();
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onSeekProcessed(InterfaceC2409b.a aVar) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onSeekStarted(InterfaceC2409b.a aVar) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onShuffleModeChanged(InterfaceC2409b.a aVar, boolean z) {
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onShuffleModeEnabledChanged(boolean z) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onSurfaceSizeChanged(InterfaceC2409b.a aVar, int i2, int i3) {
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public /* bridge */ /* synthetic */ void onTimelineChanged(AbstractC2404x0 abstractC2404x0, int i2) {
        C2336p0.m2294j(this, abstractC2404x0, i2);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onTimelineChanged(AbstractC2404x0 abstractC2404x0, Object obj, int i2) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onTimelineChanged(InterfaceC2409b.a aVar, int i2) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onTracksChanged(InterfaceC2409b.a aVar, TrackGroupArray trackGroupArray, C2258g c2258g) {
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onTracksChanged(TrackGroupArray trackGroupArray, C2258g c2258g) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onUpstreamDiscarded(InterfaceC2409b.a aVar, InterfaceC2203z.c cVar) {
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onVideoSizeChanged(InterfaceC2409b.a aVar, int i2, int i3, int i4, float f2) {
        int i5 = (int) (i2 * f2);
        this.mVideoWidth = i5;
        this.mVideoHeight = i3;
        notifyOnVideoSizeChanged(i5, i3, 1, 1);
        if (i4 > 0) {
            notifyOnInfo(10001, i4);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b
    public void onVolumeChanged(InterfaceC2409b.a aVar, float f2) {
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void pause() {
        C2402w0 c2402w0 = this.mInternalPlayer;
        if (c2402w0 == null) {
            return;
        }
        c2402w0.mo1368p(false);
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void prepareAsync() {
        if (this.mInternalPlayer != null) {
            throw new IllegalStateException("can't prepare a prepared player");
        }
        prepareAsyncInternal();
    }

    public void prepareAsyncInternal() {
        new Handler(Looper.getMainLooper()).post(new Runnable() { // from class: tv.danmaku.ijk.media.exo2.IjkExo2MediaPlayer.1
            @Override // java.lang.Runnable
            public void run() {
                C2326r c2326r;
                int i2;
                IjkExo2MediaPlayer ijkExo2MediaPlayer = IjkExo2MediaPlayer.this;
                if (ijkExo2MediaPlayer.mTrackSelector == null) {
                    ijkExo2MediaPlayer.mTrackSelector = new DefaultTrackSelector();
                }
                IjkExo2MediaPlayer.this.mEventLogger = new EventLogger(IjkExo2MediaPlayer.this.mTrackSelector);
                IjkExo2MediaPlayer ijkExo2MediaPlayer2 = IjkExo2MediaPlayer.this;
                if (ijkExo2MediaPlayer2.mRendererFactory == null) {
                    C1906a0 c1906a0 = new C1906a0(ijkExo2MediaPlayer2.mAppContext);
                    ijkExo2MediaPlayer2.mRendererFactory = c1906a0;
                    c1906a0.f3016b = 2;
                }
                if (ijkExo2MediaPlayer2.mLoadControl == null) {
                    ijkExo2MediaPlayer2.mLoadControl = new C2405y();
                }
                IjkExo2MediaPlayer ijkExo2MediaPlayer3 = IjkExo2MediaPlayer.this;
                Context context = ijkExo2MediaPlayer3.mAppContext;
                C1906a0 c1906a02 = ijkExo2MediaPlayer3.mRendererFactory;
                AbstractC2255d abstractC2255d = ijkExo2MediaPlayer3.mTrackSelector;
                InterfaceC2077h0 interfaceC2077h0 = ijkExo2MediaPlayer3.mLoadControl;
                Looper mainLooper = Looper.getMainLooper();
                InterfaceC2346f interfaceC2346f = InterfaceC2346f.f6053a;
                C2408a c2408a = new C2408a(interfaceC2346f);
                Map<String, int[]> map = C2326r.f5949a;
                synchronized (C2326r.class) {
                    if (C2326r.f5954f == null) {
                        C2326r.f5954f = new C2326r.a(context).m2275a();
                    }
                    c2326r = C2326r.f5954f;
                }
                ijkExo2MediaPlayer3.mInternalPlayer = new C2402w0(context, c1906a02, abstractC2255d, interfaceC2077h0, null, c2326r, c2408a, interfaceC2346f, mainLooper);
                IjkExo2MediaPlayer ijkExo2MediaPlayer4 = IjkExo2MediaPlayer.this;
                ijkExo2MediaPlayer4.mInternalPlayer.mo1364l(ijkExo2MediaPlayer4);
                IjkExo2MediaPlayer ijkExo2MediaPlayer5 = IjkExo2MediaPlayer.this;
                C2402w0 c2402w0 = ijkExo2MediaPlayer5.mInternalPlayer;
                c2402w0.m2684U();
                c2402w0.f6351m.f6402c.add(ijkExo2MediaPlayer5);
                IjkExo2MediaPlayer ijkExo2MediaPlayer6 = IjkExo2MediaPlayer.this;
                ijkExo2MediaPlayer6.mInternalPlayer.mo1364l(ijkExo2MediaPlayer6.mEventLogger);
                IjkExo2MediaPlayer ijkExo2MediaPlayer7 = IjkExo2MediaPlayer.this;
                C2262n0 c2262n0 = ijkExo2MediaPlayer7.mSpeedPlaybackParameters;
                if (c2262n0 != null) {
                    ijkExo2MediaPlayer7.mInternalPlayer.m2676M(c2262n0);
                }
                IjkExo2MediaPlayer ijkExo2MediaPlayer8 = IjkExo2MediaPlayer.this;
                Surface surface = ijkExo2MediaPlayer8.mSurface;
                if (surface != null) {
                    ijkExo2MediaPlayer8.mInternalPlayer.m2678O(surface);
                }
                IjkExo2MediaPlayer ijkExo2MediaPlayer9 = IjkExo2MediaPlayer.this;
                C2402w0 c2402w02 = ijkExo2MediaPlayer9.mInternalPlayer;
                InterfaceC2202y interfaceC2202y = ijkExo2MediaPlayer9.mMediaSource;
                c2402w02.m2684U();
                InterfaceC2202y interfaceC2202y2 = c2402w02.f6363y;
                if (interfaceC2202y2 != null) {
                    interfaceC2202y2.mo1994d(c2402w02.f6351m);
                    c2402w02.f6351m.m2708j();
                }
                c2402w02.f6363y = interfaceC2202y;
                interfaceC2202y.mo1993c(c2402w02.f6342d, c2402w02.f6351m);
                C2393s c2393s = c2402w02.f6353o;
                boolean mo1361h = c2402w02.mo1361h();
                Objects.requireNonNull(c2393s);
                if (mo1361h) {
                    if (c2393s.f6307d != 0) {
                        c2393s.m2649a(true);
                    }
                    i2 = 1;
                } else {
                    i2 = -1;
                }
                c2402w02.m2683T(c2402w02.mo1361h(), i2);
                C1940c0 c1940c0 = c2402w02.f6341c;
                c1940c0.f3259k = interfaceC2202y;
                C2251m0 m1346H = c1940c0.m1346H(true, true, true, 2);
                c1940c0.f3265q = true;
                c1940c0.f3264p++;
                c1940c0.f3254f.f3348j.f6024a.obtainMessage(0, 1, 1, interfaceC2202y).sendToTarget();
                c1940c0.m1353P(m1346H, false, 4, 1, false);
                IjkExo2MediaPlayer.this.mInternalPlayer.mo1368p(false);
            }
        });
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void release() {
        if (this.mInternalPlayer != null) {
            reset();
            this.mEventLogger = null;
        }
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void reset() {
        C2402w0 c2402w0 = this.mInternalPlayer;
        if (c2402w0 != null) {
            c2402w0.m2673J();
            this.mInternalPlayer = null;
        }
        ExoSourceManager exoSourceManager = this.mExoHelper;
        if (exoSourceManager != null) {
            exoSourceManager.release();
        }
        this.mSurface = null;
        this.mDataSource = null;
        this.mVideoWidth = 0;
        this.mVideoHeight = 0;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void seekTo(long j2) {
        C2402w0 c2402w0 = this.mInternalPlayer;
        if (c2402w0 == null) {
            return;
        }
        c2402w0.mo1360g(c2402w0.mo1367o(), j2);
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setAudioStreamType(int i2) {
    }

    public void setCache(boolean z) {
        this.isCache = z;
    }

    public void setCacheDir(File file) {
        this.mCacheDir = file;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setDataSource(Context context, Uri uri, Map<String, String> map) {
        if (map != null) {
            this.mHeaders.clear();
            this.mHeaders.putAll(map);
        }
        setDataSource(context, uri);
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setDisplay(SurfaceHolder surfaceHolder) {
        if (surfaceHolder == null) {
            setSurface(null);
        } else {
            setSurface(surfaceHolder.getSurface());
        }
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setKeepInBackground(boolean z) {
    }

    public void setLoadControl(InterfaceC2077h0 interfaceC2077h0) {
        this.mLoadControl = interfaceC2077h0;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setLogEnabled(boolean z) {
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setLooping(boolean z) {
        this.isLooping = z;
    }

    public void setMediaSource(InterfaceC2202y interfaceC2202y) {
        this.mMediaSource = interfaceC2202y;
    }

    public void setOverrideExtension(String str) {
        this.mOverrideExtension = str;
    }

    public void setPreview(boolean z) {
        this.isPreview = z;
    }

    public void setRendererFactory(C1906a0 c1906a0) {
        this.mRendererFactory = c1906a0;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setScreenOnWhilePlaying(boolean z) {
    }

    public void setSeekParameter(@Nullable C2400v0 c2400v0) {
        C2402w0 c2402w0 = this.mInternalPlayer;
        c2402w0.m2684U();
        C1940c0 c1940c0 = c2402w0.f6341c;
        Objects.requireNonNull(c1940c0);
        if (c2400v0 == null) {
            c2400v0 = C2400v0.f6333b;
        }
        if (c1940c0.f3269u.equals(c2400v0)) {
            return;
        }
        c1940c0.f3269u = c2400v0;
        c1940c0.f3254f.f3348j.m2298b(5, c2400v0).sendToTarget();
    }

    public void setSpeed(@Size(min = 0) float f2, @Size(min = 0) float f3) {
        C2262n0 c2262n0 = new C2262n0(f2, f3, false);
        this.mSpeedPlaybackParameters = c2262n0;
        C2402w0 c2402w0 = this.mInternalPlayer;
        if (c2402w0 != null) {
            c2402w0.m2676M(c2262n0);
        }
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setSurface(Surface surface) {
        this.mSurface = surface;
        if (this.mInternalPlayer != null) {
            if (surface != null && !surface.isValid()) {
                this.mSurface = null;
            }
            this.mInternalPlayer.m2678O(surface);
        }
    }

    public void setTrackSelector(AbstractC2255d abstractC2255d) {
        this.mTrackSelector = abstractC2255d;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setVolume(float f2, float f3) {
        C2402w0 c2402w0 = this.mInternalPlayer;
        if (c2402w0 != null) {
            c2402w0.m2684U();
            float m2328f = C2344d0.m2328f((f2 + f3) / 2.0f, 0.0f, 1.0f);
            if (c2402w0.f6362x == m2328f) {
                return;
            }
            c2402w0.f6362x = m2328f;
            c2402w0.m2675L();
            Iterator<InterfaceC1919k> it = c2402w0.f6345g.iterator();
            while (it.hasNext()) {
                it.next().mo1267a(m2328f);
            }
        }
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setWakeMode(Context context, int i2) {
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void start() {
        C2402w0 c2402w0 = this.mInternalPlayer;
        if (c2402w0 == null) {
            return;
        }
        c2402w0.mo1368p(true);
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void stop() {
        C2402w0 c2402w0 = this.mInternalPlayer;
        if (c2402w0 == null) {
            return;
        }
        c2402w0.m2673J();
    }

    public void stopPlayback() {
        this.mInternalPlayer.m2682S(false);
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setDataSource(String str) {
        setDataSource(this.mAppContext, Uri.parse(str));
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setDataSource(Context context, Uri uri) {
        String uri2 = uri.toString();
        this.mDataSource = uri2;
        this.mMediaSource = this.mExoHelper.getMediaSource(uri2, this.isPreview, this.isCache, this.isLooping, this.mCacheDir, this.mOverrideExtension);
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setDataSource(FileDescriptor fileDescriptor) {
        throw new UnsupportedOperationException("no support");
    }
}
