package im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player;

import android.graphics.SurfaceTexture;
import android.media.MediaPlayer;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.view.Surface;
import android.view.TextureView;

/* JADX INFO: loaded from: classes5.dex */
public class MediaVideoPlayer extends AbsBaseVideoPlayer implements MediaPlayer.OnPreparedListener, MediaPlayer.OnCompletionListener, MediaPlayer.OnBufferingUpdateListener, MediaPlayer.OnSeekCompleteListener, MediaPlayer.OnErrorListener, MediaPlayer.OnInfoListener {
    private static final int MSG_PREPARE = 1;
    private static final int MSG_RELEASE = 2;
    private static final String TAG = "VideoMediaPlayer";
    private MediaHandler mMediaHandler;
    private HandlerThread mMediaHandlerThread;
    private MediaPlayer mMediaPlayer;

    public MediaVideoPlayer() {
        this(false);
    }

    public MediaVideoPlayer(boolean enableLog) {
        this.mMediaPlayer = new MediaPlayer();
        HandlerThread handlerThread = new HandlerThread(TAG);
        this.mMediaHandlerThread = handlerThread;
        handlerThread.start();
        this.mMediaHandler = new MediaHandler(this.mMediaHandlerThread.getLooper());
        this.mEnableLog = enableLog;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.AbsBaseVideoPlayer, im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void setTextureView(TextureView textureView) {
        if (textureView == null && this.mSurfaceTexture != null) {
            this.mSurfaceTexture.release();
        }
        super.setTextureView(textureView);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.AbsBaseVideoPlayer, android.view.TextureView.SurfaceTextureListener
    public void onSurfaceTextureAvailable(SurfaceTexture surface, int width, int height) {
        try {
            this.mMediaPlayer.setSurface(new Surface(surface));
        } catch (Exception e) {
            e.printStackTrace();
        }
        super.onSurfaceTextureAvailable(surface, width, height);
    }

    class MediaHandler extends Handler {
        public MediaHandler(Looper looper) {
            super(looper);
        }

        @Override // android.os.Handler
        public void handleMessage(Message msg) {
            super.handleMessage(msg);
            int i = msg.what;
            if (i != 1) {
                if (i == 2) {
                    MediaVideoPlayer.this.mMediaPlayer.release();
                    return;
                }
                return;
            }
            try {
                MediaVideoPlayer.this.mMediaPlayer.release();
                MediaVideoPlayer.this.mMediaPlayer = new MediaPlayer();
                MediaVideoPlayer.this.mMediaPlayer.setAudioStreamType(3);
                MediaVideoPlayer.this.mMediaPlayer.setOnPreparedListener(MediaVideoPlayer.this);
                MediaVideoPlayer.this.mMediaPlayer.setOnCompletionListener(MediaVideoPlayer.this);
                MediaVideoPlayer.this.mMediaPlayer.setOnBufferingUpdateListener(MediaVideoPlayer.this);
                MediaVideoPlayer.this.mMediaPlayer.setScreenOnWhilePlaying(true);
                MediaVideoPlayer.this.mMediaPlayer.setOnSeekCompleteListener(MediaVideoPlayer.this);
                MediaVideoPlayer.this.mMediaPlayer.setOnErrorListener(MediaVideoPlayer.this);
                MediaVideoPlayer.this.mMediaPlayer.setOnInfoListener(MediaVideoPlayer.this);
                MediaVideoPlayer.this.mMediaPlayer.setDataSource(MediaVideoPlayer.this.mUrl);
                MediaVideoPlayer.this.mMediaPlayer.prepareAsync();
                MediaVideoPlayer.this.mMediaPlayer.setSurface(new Surface(MediaVideoPlayer.this.mSurfaceTexture));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.AbsBaseVideoPlayer
    protected void prepare() {
        this.mMediaHandler.obtainMessage(1).sendToTarget();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void start(String url) {
        this.mUrl = url;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void play() {
        this.mMediaPlayer.start();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void pause() {
        if (getPlayerState() == 2) {
            this.mMediaPlayer.pause();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void resume() {
        this.mMediaPlayer.start();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void stop() {
        this.mMediaHandler.obtainMessage(2).sendToTarget();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void reset() {
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void release() {
        this.mMediaHandler.obtainMessage(2).sendToTarget();
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
        return this.mMediaPlayer.getCurrentPosition();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public int getDuration() {
        return this.mMediaPlayer.getDuration();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void seekTo(int position) {
        this.mMediaPlayer.seekTo(position);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void setVolume(int volume) {
        this.mMediaPlayer.setVolume(volume, volume);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public int getVolume() {
        return 0;
    }

    @Override // android.media.MediaPlayer.OnSeekCompleteListener
    public void onSeekComplete(MediaPlayer mp) {
        if (this.mPlayCallback != null && isPlaying()) {
            this.mPlayCallback.onPlayStateChanged(2);
        }
    }

    @Override // android.media.MediaPlayer.OnBufferingUpdateListener
    public void onBufferingUpdate(MediaPlayer mp, int percent) {
    }

    @Override // android.media.MediaPlayer.OnCompletionListener
    public void onCompletion(MediaPlayer mp) {
        if (this.mPlayCallback != null) {
            this.mPlayCallback.onComplete();
        }
    }

    @Override // android.media.MediaPlayer.OnErrorListener
    public boolean onError(MediaPlayer mp, int what, int extra) {
        if (this.mPlayCallback != null) {
            this.mPlayCallback.onError("Play error, what=" + what + ", extra=" + extra);
            return false;
        }
        return false;
    }

    @Override // android.media.MediaPlayer.OnInfoListener
    public boolean onInfo(MediaPlayer mp, int what, int extra) {
        return false;
    }

    @Override // android.media.MediaPlayer.OnPreparedListener
    public void onPrepared(MediaPlayer mp) {
        if (this.mPlayCallback != null) {
            this.mPlayCallback.onDurationChanged(mp.getDuration());
            this.mPlayCallback.onPlayStateChanged(2);
        }
        play();
    }
}
