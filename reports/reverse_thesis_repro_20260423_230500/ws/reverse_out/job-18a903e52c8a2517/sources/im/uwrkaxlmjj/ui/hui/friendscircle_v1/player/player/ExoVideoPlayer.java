package im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player;

import android.content.Context;
import android.graphics.SurfaceTexture;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.TextureView;
import com.google.android.exoplayer2.DefaultLoadControl;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.google.android.exoplayer2.ExoPlaybackException;
import com.google.android.exoplayer2.ExoPlayerFactory;
import com.google.android.exoplayer2.PlaybackParameters;
import com.google.android.exoplayer2.Player;
import com.google.android.exoplayer2.SimpleExoPlayer;
import com.google.android.exoplayer2.Timeline;
import com.google.android.exoplayer2.drm.DrmSessionManager;
import com.google.android.exoplayer2.drm.FrameworkMediaCrypto;
import com.google.android.exoplayer2.extractor.DefaultExtractorsFactory;
import com.google.android.exoplayer2.source.ExtractorMediaSource;
import com.google.android.exoplayer2.source.LoopingMediaSource;
import com.google.android.exoplayer2.source.MediaSource;
import com.google.android.exoplayer2.source.TrackGroupArray;
import com.google.android.exoplayer2.source.dash.DashMediaSource;
import com.google.android.exoplayer2.source.dash.DefaultDashChunkSource;
import com.google.android.exoplayer2.source.hls.HlsMediaSource;
import com.google.android.exoplayer2.source.smoothstreaming.DefaultSsChunkSource;
import com.google.android.exoplayer2.source.smoothstreaming.SsMediaSource;
import com.google.android.exoplayer2.text.Cue;
import com.google.android.exoplayer2.text.TextRenderer;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import com.google.android.exoplayer2.trackselection.DefaultTrackSelector;
import com.google.android.exoplayer2.trackselection.MappingTrackSelector;
import com.google.android.exoplayer2.trackselection.TrackSelection;
import com.google.android.exoplayer2.trackselection.TrackSelectionArray;
import com.google.android.exoplayer2.upstream.DataSource;
import com.google.android.exoplayer2.upstream.DefaultAllocator;
import com.google.android.exoplayer2.upstream.DefaultBandwidthMeter;
import com.google.android.exoplayer2.upstream.DefaultDataSourceFactory;
import com.google.android.exoplayer2.upstream.DefaultHttpDataSourceFactory;
import com.google.android.exoplayer2.upstream.HttpDataSource;
import com.google.android.exoplayer2.util.Util;
import com.google.android.exoplayer2.video.VideoListener;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.logger.ExoPlayerLogger;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class ExoVideoPlayer extends AbsBaseVideoPlayer implements SimpleExoPlayer.VideoListener, TextRenderer.Output, Player.EventListener {
    private static final DefaultBandwidthMeter BANDWIDTH_METER = new DefaultBandwidthMeter();
    private static final String TAG = "VideoExoPlayer";
    private Context mContext;
    private SimpleExoPlayer mExoPlayer;
    private ExoPlayerLogger mExoPlayerLogger;
    private Handler mMainHandler;
    private DataSource.Factory mMediaDataSourceFactory;
    private MappingTrackSelector mTrackSelector;

    @Override // com.google.android.exoplayer2.Player.EventListener
    public /* synthetic */ void onPositionDiscontinuity(int i) {
        Player.EventListener.CC.$default$onPositionDiscontinuity(this, i);
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public /* synthetic */ void onRepeatModeChanged(int i) {
        Player.EventListener.CC.$default$onRepeatModeChanged(this, i);
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public /* synthetic */ void onSeekProcessed() {
        Player.EventListener.CC.$default$onSeekProcessed(this);
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public /* synthetic */ void onShuffleModeEnabledChanged(boolean z) {
        Player.EventListener.CC.$default$onShuffleModeEnabledChanged(this, z);
    }

    @Override // com.google.android.exoplayer2.video.VideoListener
    public /* synthetic */ void onSurfaceSizeChanged(int i, int i2) {
        VideoListener.CC.$default$onSurfaceSizeChanged(this, i, i2);
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public /* synthetic */ void onTimelineChanged(Timeline timeline, Object obj, int i) {
        Player.EventListener.CC.$default$onTimelineChanged(this, timeline, obj, i);
    }

    public ExoVideoPlayer(Context context) {
        this.mContext = context.getApplicationContext();
        initExoPlayer();
    }

    public ExoVideoPlayer(Context context, boolean enableLog) {
        this.mContext = context.getApplicationContext();
        initExoPlayer();
        this.mEnableLog = enableLog;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.AbsBaseVideoPlayer, im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void setTextureView(TextureView textureView) {
        if (textureView == null) {
            this.mExoPlayer.clearVideoTextureView(this.mTextureView);
        }
        super.setTextureView(textureView);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.AbsBaseVideoPlayer, android.view.TextureView.SurfaceTextureListener
    public void onSurfaceTextureAvailable(SurfaceTexture surface, int width, int height) {
        SurfaceTexture surfaceTexture = this.mSurfaceTexture;
        this.mExoPlayer.setVideoTextureView(this.mTextureView);
        super.onSurfaceTextureAvailable(surface, width, height);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.AbsBaseVideoPlayer
    protected void prepare() {
        MediaSource source;
        this.mExoPlayer.stop();
        this.mExoPlayer.setVideoTextureView(this.mTextureView);
        MediaSource source2 = buildMediaSource(Uri.parse(this.mUrl), null);
        if (!this.blnLoop) {
            source = new LoopingMediaSource(source2, 1);
        } else {
            source = new LoopingMediaSource(source2);
        }
        this.mExoPlayer.prepare(source);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void start(String url) {
        this.mUrl = url;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void play() {
        if (this.mExoPlayer.getPlaybackState() == 3) {
            this.mExoPlayer.setPlayWhenReady(true);
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void pause() {
        if (this.mExoPlayer.getPlaybackState() == 3) {
            this.mExoPlayer.setPlayWhenReady(false);
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void resume() {
        if (this.mExoPlayer.getPlaybackState() == 3) {
            this.mExoPlayer.setPlayWhenReady(true);
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void stop() {
        pause();
        this.mExoPlayer.stop();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void reset() {
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void release() {
        pause();
        this.mExoPlayer.release(true);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void setPlayerState(int state) {
        this.mState = state;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public int getPlayerState() {
        return this.mState;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public int getCurrentPosition() {
        return (int) this.mExoPlayer.getCurrentPosition();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public int getDuration() {
        return (int) this.mExoPlayer.getDuration();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void seekTo(int position) {
        this.mExoPlayer.seekTo(position);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void setVolume(int volume) {
        this.mExoPlayer.setVolume(volume);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public int getVolume() {
        return Integer.valueOf((int) (this.mExoPlayer.getVolume() * 10.0f)).intValue();
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public void onPlayerStateChanged(boolean playWhenReady, int playbackState) {
        if (playbackState == 4) {
            onCompletion();
            return;
        }
        if (playbackState == 3) {
            if (getPlayerState() != 1) {
                if (getPlayerState() == 3) {
                    onSeekComplete();
                    return;
                }
                return;
            }
            onPrepared();
        }
    }

    public void onPrepared() {
        if (this.mPlayCallback != null) {
            this.mPlayCallback.onDurationChanged((int) this.mExoPlayer.getDuration());
            this.mPlayCallback.onPlayStateChanged(2);
        }
        play();
    }

    public void onCompletion() {
        if (this.mPlayCallback != null) {
            this.mPlayCallback.onComplete();
        }
    }

    public void onSeekComplete() {
        if (this.mPlayCallback != null) {
            this.mPlayCallback.onPlayStateChanged(2);
        }
        play();
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public void onPlayerError(ExoPlaybackException error) {
        if (this.mPlayCallback != null) {
            this.mPlayCallback.onError(error.getCause().toString());
        }
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public void onTracksChanged(TrackGroupArray trackGroups, TrackSelectionArray trackSelections) {
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public void onLoadingChanged(boolean isLoading) {
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public void onPlaybackParametersChanged(PlaybackParameters playbackParameters) {
    }

    @Override // com.google.android.exoplayer2.text.TextOutput
    public void onCues(List<Cue> cues) {
    }

    @Override // com.google.android.exoplayer2.video.VideoListener
    public void onVideoSizeChanged(int width, int height, int unappliedRotationDegrees, float pixelWidthHeightRatio) {
        this.miVideoHeight = height;
        this.miVideoWidth = width;
    }

    @Override // com.google.android.exoplayer2.video.VideoListener
    public void onRenderedFirstFrame() {
    }

    @Override // com.google.android.exoplayer2.video.VideoListener
    public boolean onSurfaceDestroyed(SurfaceTexture surfaceTexture) {
        return false;
    }

    private MediaSource buildMediaSource(Uri uri, String overrideExtension) {
        String lastPathSegment;
        if (TextUtils.isEmpty(overrideExtension)) {
            lastPathSegment = uri.getLastPathSegment();
        } else {
            lastPathSegment = "." + overrideExtension;
        }
        int type = Util.inferContentType(lastPathSegment);
        if (type == 0) {
            return new DashMediaSource(uri, buildDataSourceFactory(false), new DefaultDashChunkSource.Factory(this.mMediaDataSourceFactory), this.mMainHandler, this.mExoPlayerLogger);
        }
        if (type == 1) {
            return new SsMediaSource(uri, buildDataSourceFactory(false), new DefaultSsChunkSource.Factory(this.mMediaDataSourceFactory), this.mMainHandler, this.mExoPlayerLogger);
        }
        if (type == 2) {
            return new HlsMediaSource(uri, this.mMediaDataSourceFactory, this.mMainHandler, this.mExoPlayerLogger);
        }
        if (type == 3) {
            return new ExtractorMediaSource(uri, this.mMediaDataSourceFactory, new DefaultExtractorsFactory(), this.mMainHandler, this.mExoPlayerLogger);
        }
        throw new IllegalStateException("Unsupported type: " + type);
    }

    private void initExoPlayer() {
        this.mMediaDataSourceFactory = buildDataSourceFactory(true);
        TrackSelection.Factory videoTrackSelectionFactory = new AdaptiveTrackSelection.Factory(BANDWIDTH_METER);
        DefaultTrackSelector defaultTrackSelector = new DefaultTrackSelector(videoTrackSelectionFactory);
        this.mTrackSelector = defaultTrackSelector;
        this.mExoPlayerLogger = new ExoPlayerLogger(defaultTrackSelector);
        this.mMainHandler = new Handler(Looper.getMainLooper());
        new DefaultRenderersFactory(this.mContext, (DrmSessionManager<FrameworkMediaCrypto>) null, 0);
        DefaultLoadControl loadControl = new DefaultLoadControl(new DefaultAllocator(true, 65536), 15000, 50000, 100, 5000, -1, true);
        SimpleExoPlayer simpleExoPlayerNewSimpleInstance = ExoPlayerFactory.newSimpleInstance(ApplicationLoader.applicationContext, this.mTrackSelector, loadControl, (DrmSessionManager<FrameworkMediaCrypto>) null, 2);
        this.mExoPlayer = simpleExoPlayerNewSimpleInstance;
        simpleExoPlayerNewSimpleInstance.addListener(this.mExoPlayerLogger);
        this.mExoPlayer.setAudioDebugListener(this.mExoPlayerLogger);
        this.mExoPlayer.setVideoDebugListener(this.mExoPlayerLogger);
        this.mExoPlayer.setMetadataOutput(this.mExoPlayerLogger);
        this.mExoPlayer.setTextOutput(null);
        this.mExoPlayer.setVideoListener(null);
        this.mExoPlayer.removeListener(this);
        this.mExoPlayer.setVideoTextureView(null);
        this.mExoPlayer.setVideoListener(this);
        this.mExoPlayer.addListener(this);
        this.mExoPlayer.setTextOutput(this);
    }

    private DataSource.Factory buildDataSourceFactory(boolean useBandwidthMeter) {
        return buildDataSourceFactory(useBandwidthMeter ? BANDWIDTH_METER : null);
    }

    private DataSource.Factory buildDataSourceFactory(DefaultBandwidthMeter bandwidthMeter) {
        return new DefaultDataSourceFactory(this.mContext, bandwidthMeter, buildHttpDataSourceFactory(bandwidthMeter));
    }

    private HttpDataSource.Factory buildHttpDataSourceFactory(DefaultBandwidthMeter bandwidthMeter) {
        return new DefaultHttpDataSourceFactory(Util.getUserAgent(this.mContext, TAG), bandwidthMeter);
    }
}
