package im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player;

import android.graphics.SurfaceTexture;
import android.util.Log;
import android.view.TextureView;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer;

/* JADX INFO: loaded from: classes5.dex */
public abstract class AbsBaseVideoPlayer implements IVideoPlayer, TextureView.SurfaceTextureListener {
    protected boolean mEnableLog;
    protected IVideoPlayer.PlayCallback mPlayCallback;
    protected SurfaceTexture mSurfaceTexture;
    protected TextureView mTextureView;
    protected String mUrl;
    protected int miVideoHeight;
    protected int miVideoWidth;
    protected int mState = 0;
    protected boolean blnLoop = true;

    protected abstract void prepare();

    public int getMiVideoWidth() {
        return this.miVideoWidth;
    }

    public int getMiVideoHeight() {
        return this.miVideoHeight;
    }

    public void setLoopPlay(boolean blnLoop) {
        this.blnLoop = blnLoop;
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public void onSurfaceTextureAvailable(SurfaceTexture surface, int width, int height) {
        if (this.mEnableLog) {
            Log.i("ListVideoPlayer", "AbsBaseVideoPlayer onSurfaceTextureAvailable");
        }
        if (this.mSurfaceTexture == null && (getPlayerState() == 0 || getPlayerState() == 1)) {
            prepare();
        }
        this.mSurfaceTexture = surface;
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public void onSurfaceTextureSizeChanged(SurfaceTexture surface, int width, int height) {
        if (this.mEnableLog) {
            Log.i("ListVideoPlayer", "AbsBaseVideoPlayer onSurfaceTextureSizeChanged");
        }
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public boolean onSurfaceTextureDestroyed(SurfaceTexture surface) {
        if (this.mEnableLog) {
            Log.i("ListVideoPlayer", "AbsBaseVideoPlayer onSurfaceTextureDestroyed");
            return false;
        }
        return false;
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public void onSurfaceTextureUpdated(SurfaceTexture surface) {
        if (this.mEnableLog) {
            Log.i("ListVideoPlayer", "AbsBaseVideoPlayer onSurfaceTextureUpdated");
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public boolean isPlaying() {
        if (this.mEnableLog) {
            Log.i("ListVideoPlayer", "AbsBaseVideoPlayer isPlaying");
        }
        return (getPlayerState() == 2 || getPlayerState() == 3) && getCurrentPosition() < getDuration();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void setPlayCallback(IVideoPlayer.PlayCallback playCallback) {
        if (this.mEnableLog) {
            Log.i("ListVideoPlayer", "AbsBaseVideoPlayer setPlayCallback");
        }
        this.mPlayCallback = playCallback;
    }

    public void setEnableLog(boolean enableLog) {
        this.mEnableLog = enableLog;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.IVideoPlayer
    public void setTextureView(TextureView textureView) {
        if (this.mEnableLog) {
            Log.i("ListVideoPlayer", "AbsBaseVideoPlayer setTextureView");
        }
        TextureView textureView2 = this.mTextureView;
        if (textureView2 != null) {
            textureView2.setSurfaceTextureListener(null);
        }
        this.mSurfaceTexture = null;
        this.mTextureView = textureView;
        if (textureView != null) {
            textureView.setSurfaceTextureListener(this);
        }
    }
}
