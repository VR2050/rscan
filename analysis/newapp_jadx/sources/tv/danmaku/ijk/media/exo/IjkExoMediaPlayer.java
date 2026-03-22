package tv.danmaku.ijk.media.exo;

import android.content.Context;
import android.net.Uri;
import android.view.Surface;
import android.view.SurfaceHolder;
import com.google.android.exoplayer.util.Util;
import java.io.FileDescriptor;
import java.util.Map;
import tv.danmaku.ijk.media.exo.demo.EventLogger;
import tv.danmaku.ijk.media.exo.demo.SmoothStreamingTestMediaDrmCallback;
import tv.danmaku.ijk.media.exo.demo.player.DemoPlayer;
import tv.danmaku.ijk.media.exo.demo.player.ExtractorRendererBuilder;
import tv.danmaku.ijk.media.exo.demo.player.HlsRendererBuilder;
import tv.danmaku.ijk.media.exo.demo.player.SmoothStreamingRendererBuilder;
import tv.danmaku.ijk.media.player.AbstractMediaPlayer;
import tv.danmaku.ijk.media.player.IMediaPlayer;
import tv.danmaku.ijk.media.player.MediaInfo;
import tv.danmaku.ijk.media.player.misc.IjkTrackInfo;

/* loaded from: classes3.dex */
public class IjkExoMediaPlayer extends AbstractMediaPlayer {
    private Context mAppContext;
    private String mDataSource;
    private DemoPlayerListener mDemoListener = new DemoPlayerListener();
    private EventLogger mEventLogger;
    private DemoPlayer mInternalPlayer;
    private DemoPlayer.RendererBuilder mRendererBuilder;
    private Surface mSurface;
    private int mVideoHeight;
    private int mVideoWidth;

    public class DemoPlayerListener implements DemoPlayer.Listener {
        private boolean mDidPrepare;
        private boolean mIsBuffering;
        private boolean mIsPrepareing;

        private DemoPlayerListener() {
            this.mIsPrepareing = false;
            this.mDidPrepare = false;
            this.mIsBuffering = false;
        }

        @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.Listener
        public void onError(Exception exc) {
            IjkExoMediaPlayer.this.notifyOnError(1, 1);
        }

        @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.Listener
        public void onStateChanged(boolean z, int i2) {
            if (this.mIsBuffering && (i2 == 4 || i2 == 5)) {
                IjkExoMediaPlayer ijkExoMediaPlayer = IjkExoMediaPlayer.this;
                ijkExoMediaPlayer.notifyOnInfo(IMediaPlayer.MEDIA_INFO_BUFFERING_END, ijkExoMediaPlayer.mInternalPlayer.getBufferedPercentage());
                this.mIsBuffering = false;
            }
            if (this.mIsPrepareing && i2 == 4) {
                IjkExoMediaPlayer.this.notifyOnPrepared();
                this.mIsPrepareing = false;
                this.mDidPrepare = false;
            }
            if (i2 == 1) {
                IjkExoMediaPlayer.this.notifyOnCompletion();
                return;
            }
            if (i2 == 2) {
                this.mIsPrepareing = true;
                return;
            }
            if (i2 != 3) {
                if (i2 != 5) {
                    return;
                }
                IjkExoMediaPlayer.this.notifyOnCompletion();
            } else {
                IjkExoMediaPlayer ijkExoMediaPlayer2 = IjkExoMediaPlayer.this;
                ijkExoMediaPlayer2.notifyOnInfo(IMediaPlayer.MEDIA_INFO_BUFFERING_START, ijkExoMediaPlayer2.mInternalPlayer.getBufferedPercentage());
                this.mIsBuffering = true;
            }
        }

        @Override // tv.danmaku.ijk.media.exo.demo.player.DemoPlayer.Listener
        public void onVideoSizeChanged(int i2, int i3, int i4, float f2) {
            IjkExoMediaPlayer.this.mVideoWidth = i2;
            IjkExoMediaPlayer.this.mVideoHeight = i3;
            IjkExoMediaPlayer.this.notifyOnVideoSizeChanged(i2, i3, 1, 1);
            if (i4 > 0) {
                IjkExoMediaPlayer.this.notifyOnInfo(10001, i4);
            }
        }
    }

    public IjkExoMediaPlayer(Context context) {
        this.mAppContext = context.getApplicationContext();
        EventLogger eventLogger = new EventLogger();
        this.mEventLogger = eventLogger;
        eventLogger.startSession();
    }

    private DemoPlayer.RendererBuilder getRendererBuilder() {
        Uri parse = Uri.parse(this.mDataSource);
        String userAgent = Util.getUserAgent(this.mAppContext, "IjkExoMediaPlayer");
        int inferContentType = inferContentType(parse);
        return inferContentType != 1 ? inferContentType != 2 ? new ExtractorRendererBuilder(this.mAppContext, userAgent, parse) : new HlsRendererBuilder(this.mAppContext, userAgent, parse.toString()) : new SmoothStreamingRendererBuilder(this.mAppContext, userAgent, parse.toString(), new SmoothStreamingTestMediaDrmCallback());
    }

    private static int inferContentType(Uri uri) {
        return Util.inferContentType(uri.getLastPathSegment());
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public int getAudioSessionId() {
        return 0;
    }

    public int getBufferedPercentage() {
        DemoPlayer demoPlayer = this.mInternalPlayer;
        if (demoPlayer == null) {
            return 0;
        }
        return demoPlayer.getBufferedPercentage();
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public long getCurrentPosition() {
        DemoPlayer demoPlayer = this.mInternalPlayer;
        if (demoPlayer == null) {
            return 0L;
        }
        return demoPlayer.getCurrentPosition();
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public String getDataSource() {
        return this.mDataSource;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public long getDuration() {
        DemoPlayer demoPlayer = this.mInternalPlayer;
        if (demoPlayer == null) {
            return 0L;
        }
        return demoPlayer.getDuration();
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public MediaInfo getMediaInfo() {
        return null;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public IjkTrackInfo[] getTrackInfo() {
        return null;
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

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public boolean isLooping() {
        return false;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public boolean isPlayable() {
        return true;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public boolean isPlaying() {
        DemoPlayer demoPlayer = this.mInternalPlayer;
        if (demoPlayer == null) {
            return false;
        }
        int playbackState = demoPlayer.getPlaybackState();
        if (playbackState == 3 || playbackState == 4) {
            return this.mInternalPlayer.getPlayWhenReady();
        }
        return false;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void pause() {
        DemoPlayer demoPlayer = this.mInternalPlayer;
        if (demoPlayer == null) {
            return;
        }
        demoPlayer.setPlayWhenReady(false);
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void prepareAsync() {
        if (this.mInternalPlayer != null) {
            throw new IllegalStateException("can't prepare a prepared player");
        }
        DemoPlayer demoPlayer = new DemoPlayer(this.mRendererBuilder);
        this.mInternalPlayer = demoPlayer;
        demoPlayer.addListener(this.mDemoListener);
        this.mInternalPlayer.addListener(this.mEventLogger);
        this.mInternalPlayer.setInfoListener(this.mEventLogger);
        this.mInternalPlayer.setInternalErrorListener(this.mEventLogger);
        Surface surface = this.mSurface;
        if (surface != null) {
            this.mInternalPlayer.setSurface(surface);
        }
        this.mInternalPlayer.prepare();
        this.mInternalPlayer.setPlayWhenReady(false);
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void release() {
        if (this.mInternalPlayer != null) {
            reset();
            this.mDemoListener = null;
            this.mEventLogger.endSession();
            this.mEventLogger = null;
        }
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void reset() {
        DemoPlayer demoPlayer = this.mInternalPlayer;
        if (demoPlayer != null) {
            demoPlayer.release();
            this.mInternalPlayer.removeListener(this.mDemoListener);
            this.mInternalPlayer.removeListener(this.mEventLogger);
            this.mInternalPlayer.setInfoListener(null);
            this.mInternalPlayer.setInternalErrorListener(null);
            this.mInternalPlayer = null;
        }
        this.mSurface = null;
        this.mDataSource = null;
        this.mVideoWidth = 0;
        this.mVideoHeight = 0;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void seekTo(long j2) {
        DemoPlayer demoPlayer = this.mInternalPlayer;
        if (demoPlayer == null) {
            return;
        }
        demoPlayer.seekTo(j2);
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setAudioStreamType(int i2) {
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setDataSource(Context context, Uri uri) {
        this.mDataSource = uri.toString();
        this.mRendererBuilder = getRendererBuilder();
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

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setLogEnabled(boolean z) {
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setLooping(boolean z) {
        throw new UnsupportedOperationException("no support");
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setScreenOnWhilePlaying(boolean z) {
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setSurface(Surface surface) {
        this.mSurface = surface;
        DemoPlayer demoPlayer = this.mInternalPlayer;
        if (demoPlayer != null) {
            demoPlayer.setSurface(surface);
        }
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setVolume(float f2, float f3) {
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setWakeMode(Context context, int i2) {
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void start() {
        DemoPlayer demoPlayer = this.mInternalPlayer;
        if (demoPlayer == null) {
            return;
        }
        demoPlayer.setPlayWhenReady(true);
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void stop() {
        DemoPlayer demoPlayer = this.mInternalPlayer;
        if (demoPlayer == null) {
            return;
        }
        demoPlayer.release();
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setDataSource(Context context, Uri uri, Map<String, String> map) {
        setDataSource(context, uri);
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setDataSource(String str) {
        setDataSource(this.mAppContext, Uri.parse(str));
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer
    public void setDataSource(FileDescriptor fileDescriptor) {
        throw new UnsupportedOperationException("no support");
    }
}
