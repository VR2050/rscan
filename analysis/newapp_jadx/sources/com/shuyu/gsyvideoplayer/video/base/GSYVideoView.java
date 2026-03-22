package com.shuyu.gsyvideoplayer.video.base;

import android.app.Activity;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import android.media.AudioManager;
import android.os.Handler;
import android.os.Looper;
import android.util.AttributeSet;
import android.view.InflateException;
import android.view.Surface;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.AttrRes;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.shuyu.gsyvideoplayer.R$id;
import com.shuyu.gsyvideoplayer.utils.CommonUtil;
import com.shuyu.gsyvideoplayer.utils.Debuger;
import com.shuyu.gsyvideoplayer.utils.NetInfoModule;
import java.io.File;
import java.util.HashMap;
import java.util.Map;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p362y.p363a.p366f.InterfaceC2925a;
import p005b.p362y.p363a.p366f.InterfaceC2931g;
import p005b.p362y.p363a.p369i.C2939a;
import p005b.p362y.p363a.p369i.p372d.InterfaceC2944a;

/* loaded from: classes2.dex */
public abstract class GSYVideoView extends GSYTextureRenderView implements InterfaceC2925a {
    public static final int CHANGE_DELAY_TIME = 2000;
    public static final int CURRENT_STATE_AUTO_COMPLETE = 6;
    public static final int CURRENT_STATE_ERROR = 7;
    public static final int CURRENT_STATE_NORMAL = 0;
    public static final int CURRENT_STATE_PAUSE = 5;
    public static final int CURRENT_STATE_PLAYING = 2;
    public static final int CURRENT_STATE_PLAYING_BUFFERING_START = 3;
    public static final int CURRENT_STATE_PREPAREING = 1;
    public AudioManager mAudioManager;
    public int mBackUpPlayingBufferState;
    public int mBufferPoint;
    public boolean mCache;
    public File mCachePath;
    public Context mContext;
    public long mCurrentPosition;
    public int mCurrentState;
    public boolean mHadPlay;
    public boolean mHadPrepared;
    public boolean mIfCurrentIsFullscreen;
    public boolean mLooping;
    public Map<String, String> mMapHeadData;
    public boolean mNetChanged;
    public NetInfoModule mNetInfoModule;
    public String mNetSate;
    public String mOriginUrl;
    public String mOverrideExtension;
    public boolean mPauseBeforePrepared;
    public int mPlayPosition;
    public String mPlayTag;
    public boolean mReleaseWhenLossAudio;
    public long mSaveChangeViewTIme;
    public int mScreenHeight;
    public int mScreenWidth;
    public long mSeekOnStart;
    public boolean mShowPauseCover;
    public boolean mSoundTouch;
    public float mSpeed;
    public boolean mStartAfterPrepared;
    public String mTitle;
    public String mUrl;
    public InterfaceC2931g mVideoAllCallBack;
    public AudioManager.OnAudioFocusChangeListener onAudioFocusChangeListener;

    public GSYVideoView(@NonNull Context context) {
        super(context);
        this.mCurrentState = -1;
        this.mPlayPosition = -22;
        this.mBackUpPlayingBufferState = -1;
        this.mSeekOnStart = -1L;
        this.mSaveChangeViewTIme = 0L;
        this.mSpeed = 1.0f;
        this.mCache = false;
        this.mIfCurrentIsFullscreen = false;
        this.mLooping = false;
        this.mHadPlay = false;
        this.mNetChanged = false;
        this.mSoundTouch = false;
        this.mShowPauseCover = false;
        this.mPauseBeforePrepared = false;
        this.mStartAfterPrepared = true;
        this.mHadPrepared = false;
        this.mReleaseWhenLossAudio = true;
        this.mPlayTag = "";
        this.mNetSate = "NORMAL";
        this.mMapHeadData = new HashMap();
        this.onAudioFocusChangeListener = new AudioManager.OnAudioFocusChangeListener() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoView.1
            @Override // android.media.AudioManager.OnAudioFocusChangeListener
            public void onAudioFocusChange(int i2) {
                if (i2 == -3) {
                    GSYVideoView.this.onLossTransientCanDuck();
                    return;
                }
                if (i2 == -2) {
                    GSYVideoView.this.onLossTransientAudio();
                } else if (i2 == -1) {
                    GSYVideoView.this.onLossAudio();
                } else {
                    if (i2 != 1) {
                        return;
                    }
                    GSYVideoView.this.onGankAudio();
                }
            }
        };
        init(context);
    }

    public abstract boolean backFromFull(Context context);

    public void clearCurrentCache() {
        if (!getGSYVideoManager().isCacheFile() || !this.mCache) {
            if (this.mUrl.contains("127.0.0.1")) {
                getGSYVideoManager().clearCache(getContext(), this.mCachePath, this.mOriginUrl);
            }
        } else {
            StringBuilder m586H = C1499a.m586H("Play Error ");
            m586H.append(this.mUrl);
            Debuger.printfError(m586H.toString());
            this.mUrl = this.mOriginUrl;
            getGSYVideoManager().clearCache(this.mContext, this.mCachePath, this.mOriginUrl);
        }
    }

    public void createNetWorkState() {
        if (this.mNetInfoModule == null) {
            NetInfoModule netInfoModule = new NetInfoModule(this.mContext.getApplicationContext(), new NetInfoModule.NetChangeListener() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoView.4
                @Override // com.shuyu.gsyvideoplayer.utils.NetInfoModule.NetChangeListener
                public void changed(String str) {
                    if (!GSYVideoView.this.mNetSate.equals(str)) {
                        Debuger.printfError("******* change network state ******* " + str);
                        GSYVideoView.this.mNetChanged = true;
                    }
                    GSYVideoView.this.mNetSate = str;
                }
            });
            this.mNetInfoModule = netInfoModule;
            this.mNetSate = netInfoModule.getCurrentConnectionType();
        }
    }

    public void deleteCacheFileWhenError() {
        clearCurrentCache();
        Debuger.printfError("Link Or mCache Error, Please Try Again " + this.mOriginUrl);
        if (this.mCache) {
            StringBuilder m586H = C1499a.m586H("mCache Link ");
            m586H.append(this.mUrl);
            Debuger.printfError(m586H.toString());
        }
        this.mUrl = this.mOriginUrl;
    }

    public Context getActivityContext() {
        return CommonUtil.getActivityContext(getContext());
    }

    public int getBuffterPoint() {
        return this.mBufferPoint;
    }

    public int getCurrentPositionWhenPlaying() {
        int i2 = this.mCurrentState;
        int i3 = 0;
        if (i2 == 2 || i2 == 5) {
            try {
                i3 = (int) getGSYVideoManager().getCurrentPosition();
            } catch (Exception e2) {
                e2.printStackTrace();
                return 0;
            }
        }
        if (i3 == 0) {
            long j2 = this.mCurrentPosition;
            if (j2 > 0) {
                return (int) j2;
            }
        }
        return i3;
    }

    public int getCurrentState() {
        return this.mCurrentState;
    }

    @Override // com.shuyu.gsyvideoplayer.utils.MeasureHelper.MeasureFormVideoParamsListener
    public int getCurrentVideoHeight() {
        if (getGSYVideoManager() != null) {
            return getGSYVideoManager().getVideoHeight();
        }
        return 0;
    }

    @Override // com.shuyu.gsyvideoplayer.utils.MeasureHelper.MeasureFormVideoParamsListener
    public int getCurrentVideoWidth() {
        if (getGSYVideoManager() != null) {
            return getGSYVideoManager().getVideoWidth();
        }
        return 0;
    }

    public int getDuration() {
        try {
            return (int) getGSYVideoManager().getDuration();
        } catch (Exception e2) {
            e2.printStackTrace();
            return 0;
        }
    }

    public abstract GSYVideoViewBridge getGSYVideoManager();

    public abstract int getLayoutId();

    public Map<String, String> getMapHeadData() {
        return this.mMapHeadData;
    }

    public long getNetSpeed() {
        return getGSYVideoManager().getNetSpeed();
    }

    public String getNetSpeedText() {
        return CommonUtil.getTextSpeed(getNetSpeed());
    }

    public String getOverrideExtension() {
        return this.mOverrideExtension;
    }

    public int getPlayPosition() {
        return this.mPlayPosition;
    }

    public String getPlayTag() {
        return this.mPlayTag;
    }

    public long getSeekOnStart() {
        return this.mSeekOnStart;
    }

    public float getSpeed() {
        return this.mSpeed;
    }

    @Override // com.shuyu.gsyvideoplayer.utils.MeasureHelper.MeasureFormVideoParamsListener
    public int getVideoSarDen() {
        if (getGSYVideoManager() != null) {
            return getGSYVideoManager().getVideoSarDen();
        }
        return 0;
    }

    @Override // com.shuyu.gsyvideoplayer.utils.MeasureHelper.MeasureFormVideoParamsListener
    public int getVideoSarNum() {
        if (getGSYVideoManager() != null) {
            return getGSYVideoManager().getVideoSarNum();
        }
        return 0;
    }

    public void init(Context context) {
        if (getActivityContext() != null) {
            this.mContext = getActivityContext();
        } else {
            this.mContext = context;
        }
        initInflate(this.mContext);
        this.mTextureViewContainer = (ViewGroup) findViewById(R$id.surface_container);
        if (isInEditMode()) {
            return;
        }
        this.mScreenWidth = this.mContext.getResources().getDisplayMetrics().widthPixels;
        this.mScreenHeight = this.mContext.getResources().getDisplayMetrics().heightPixels;
        this.mAudioManager = (AudioManager) this.mContext.getApplicationContext().getSystemService("audio");
    }

    public void initInflate(Context context) {
        try {
            View.inflate(context, getLayoutId(), this);
        } catch (InflateException e2) {
            if (!e2.toString().contains("GSYImageCover")) {
                e2.printStackTrace();
            } else {
                Debuger.printfError("********************\n*****   注意   *************************\n*该版本需要清除布局文件中的GSYImageCover\n****  Attention  ***\n*Please remove GSYImageCover from Layout in this Version\n********************\n");
                e2.printStackTrace();
                throw new InflateException("该版本需要清除布局文件中的GSYImageCover，please remove GSYImageCover from your layout");
            }
        }
    }

    public boolean isCurrentMediaListener() {
        return getGSYVideoManager().listener() != null && getGSYVideoManager().listener() == this;
    }

    public boolean isIfCurrentIsFullscreen() {
        return this.mIfCurrentIsFullscreen;
    }

    public boolean isInPlayingState() {
        int i2 = this.mCurrentState;
        return (i2 < 0 || i2 == 0 || i2 == 6 || i2 == 7) ? false : true;
    }

    public boolean isLooping() {
        return this.mLooping;
    }

    public boolean isReleaseWhenLossAudio() {
        return this.mReleaseWhenLossAudio;
    }

    public boolean isShowPauseCover() {
        return this.mShowPauseCover;
    }

    public boolean isStartAfterPrepared() {
        return this.mStartAfterPrepared;
    }

    public void listenerNetWorkState() {
        NetInfoModule netInfoModule = this.mNetInfoModule;
        if (netInfoModule != null) {
            netInfoModule.onHostResume();
        }
    }

    public void netWorkErrorLogic() {
        final long currentPositionWhenPlaying = getCurrentPositionWhenPlaying();
        Debuger.printfError("******* Net State Changed. renew player to connect *******" + currentPositionWhenPlaying);
        getGSYVideoManager().releaseMediaPlayer();
        postDelayed(new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoView.3
            @Override // java.lang.Runnable
            public void run() {
                GSYVideoView.this.setSeekOnStart(currentPositionWhenPlaying);
                GSYVideoView.this.startPlayLogic();
            }
        }, 500L);
    }

    public void onAutoCompletion() {
        setStateAndUi(6);
        this.mSaveChangeViewTIme = 0L;
        this.mCurrentPosition = 0L;
        if (this.mTextureViewContainer.getChildCount() > 0) {
            this.mTextureViewContainer.removeAllViews();
        }
        if (!this.mIfCurrentIsFullscreen) {
            getGSYVideoManager().setLastListener(null);
        }
        this.mAudioManager.abandonAudioFocus(this.onAudioFocusChangeListener);
        Context context = this.mContext;
        if (context instanceof Activity) {
            try {
                ((Activity) context).getWindow().clearFlags(128);
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        releaseNetWorkState();
        if (this.mVideoAllCallBack == null || !isCurrentMediaListener()) {
            return;
        }
        Debuger.printfLog("onAutoComplete");
        this.mVideoAllCallBack.onAutoComplete(this.mOriginUrl, this.mTitle, this);
    }

    public abstract /* synthetic */ void onBackFullscreen();

    public abstract /* synthetic */ void onBufferingUpdate(int i2);

    public void onCompletion() {
        setStateAndUi(0);
        this.mSaveChangeViewTIme = 0L;
        this.mCurrentPosition = 0L;
        if (this.mTextureViewContainer.getChildCount() > 0) {
            this.mTextureViewContainer.removeAllViews();
        }
        if (!this.mIfCurrentIsFullscreen) {
            getGSYVideoManager().setListener(null);
            getGSYVideoManager().setLastListener(null);
        }
        getGSYVideoManager().setCurrentVideoHeight(0);
        getGSYVideoManager().setCurrentVideoWidth(0);
        this.mAudioManager.abandonAudioFocus(this.onAudioFocusChangeListener);
        Context context = this.mContext;
        if (context instanceof Activity) {
            try {
                ((Activity) context).getWindow().clearFlags(128);
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        releaseNetWorkState();
    }

    public void onError(int i2, int i3) {
        if (this.mNetChanged) {
            this.mNetChanged = false;
            netWorkErrorLogic();
            InterfaceC2931g interfaceC2931g = this.mVideoAllCallBack;
            if (interfaceC2931g != null) {
                interfaceC2931g.onPlayError(this.mOriginUrl, this.mTitle, this);
                return;
            }
            return;
        }
        if (i2 == 38 || i2 == -38) {
            return;
        }
        setStateAndUi(7);
        deleteCacheFileWhenError();
        InterfaceC2931g interfaceC2931g2 = this.mVideoAllCallBack;
        if (interfaceC2931g2 != null) {
            interfaceC2931g2.onPlayError(this.mOriginUrl, this.mTitle, this);
        }
    }

    public void onGankAudio() {
    }

    public void onInfo(int i2, int i3) {
        int i4;
        if (i2 == 701) {
            int i5 = this.mCurrentState;
            this.mBackUpPlayingBufferState = i5;
            if (!this.mHadPlay || i5 == 1 || i5 <= 0) {
                return;
            }
            setStateAndUi(3);
            return;
        }
        if (i2 == 702) {
            int i6 = this.mBackUpPlayingBufferState;
            if (i6 != -1) {
                if (i6 == 3) {
                    this.mBackUpPlayingBufferState = 2;
                }
                if (this.mHadPlay && (i4 = this.mCurrentState) != 1 && i4 > 0) {
                    setStateAndUi(this.mBackUpPlayingBufferState);
                }
                this.mBackUpPlayingBufferState = -1;
                return;
            }
            return;
        }
        if (i2 == getGSYVideoManager().getRotateInfoFlag()) {
            this.mRotate = i3;
            Debuger.printfLog("Video Rotate Info " + i3);
            C2939a c2939a = this.mTextureView;
            if (c2939a != null) {
                float f2 = this.mRotate;
                InterfaceC2944a interfaceC2944a = c2939a.f8046a;
                if (interfaceC2944a != null) {
                    interfaceC2944a.getRenderView().setRotation(f2);
                }
            }
        }
    }

    public void onLossAudio() {
        new Handler(Looper.getMainLooper()).post(new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoView.2
            @Override // java.lang.Runnable
            public void run() {
                GSYVideoView gSYVideoView = GSYVideoView.this;
                if (gSYVideoView.mReleaseWhenLossAudio) {
                    gSYVideoView.releaseVideos();
                } else {
                    gSYVideoView.onVideoPause();
                }
            }
        });
    }

    public void onLossTransientAudio() {
        try {
            onVideoPause();
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public void onLossTransientCanDuck() {
    }

    public void onPrepared() {
        if (this.mCurrentState != 1) {
            return;
        }
        this.mHadPrepared = true;
        if (this.mVideoAllCallBack != null && isCurrentMediaListener()) {
            Debuger.printfLog("onPrepared");
            this.mVideoAllCallBack.onPrepared(this.mOriginUrl, this.mTitle, this);
        }
        if (this.mStartAfterPrepared) {
            startAfterPrepared();
        } else {
            setStateAndUi(5);
            onVideoPause();
        }
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onSeekComplete() {
        Debuger.printfLog("onSeekComplete");
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onVideoPause() {
        if (this.mCurrentState == 1) {
            this.mPauseBeforePrepared = true;
        }
        try {
            if (getGSYVideoManager() == null || !getGSYVideoManager().isPlaying()) {
                return;
            }
            setStateAndUi(5);
            this.mCurrentPosition = getGSYVideoManager().getCurrentPosition();
            if (getGSYVideoManager() != null) {
                getGSYVideoManager().pause();
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public void onVideoReset() {
        setStateAndUi(0);
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onVideoResume() {
        onVideoResume(true);
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onVideoSizeChanged() {
        C2939a c2939a;
        InterfaceC2944a interfaceC2944a;
        int currentVideoWidth = getGSYVideoManager().getCurrentVideoWidth();
        int currentVideoHeight = getGSYVideoManager().getCurrentVideoHeight();
        if (currentVideoWidth == 0 || currentVideoHeight == 0 || (c2939a = this.mTextureView) == null || (interfaceC2944a = c2939a.f8046a) == null) {
            return;
        }
        interfaceC2944a.getRenderView().requestLayout();
    }

    public void prepareVideo() {
        startPrepare();
    }

    public void release() {
        this.mSaveChangeViewTIme = 0L;
        if (!isCurrentMediaListener() || System.currentTimeMillis() - this.mSaveChangeViewTIme <= 2000) {
            return;
        }
        releaseVideos();
    }

    public void releaseNetWorkState() {
        NetInfoModule netInfoModule = this.mNetInfoModule;
        if (netInfoModule != null) {
            netInfoModule.onHostPause();
            this.mNetInfoModule = null;
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYTextureRenderView
    public void releasePauseCover() {
        Bitmap bitmap;
        try {
            if (this.mCurrentState == 5 || (bitmap = this.mFullPauseBitmap) == null || bitmap.isRecycled() || !this.mShowPauseCover) {
                return;
            }
            this.mFullPauseBitmap.recycle();
            this.mFullPauseBitmap = null;
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYTextureRenderView
    public void releaseSurface(Surface surface) {
        getGSYVideoManager().releaseSurface(surface);
    }

    public abstract void releaseVideos();

    public void seekTo(long j2) {
        try {
            if (getGSYVideoManager() == null || j2 <= 0) {
                return;
            }
            getGSYVideoManager().seekTo(j2);
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYTextureRenderView
    public void setDisplay(Surface surface) {
        getGSYVideoManager().setDisplay(surface);
    }

    public void setIfCurrentIsFullscreen(boolean z) {
        this.mIfCurrentIsFullscreen = z;
    }

    public void setLooping(boolean z) {
        this.mLooping = z;
    }

    public void setMapHeadData(Map<String, String> map) {
        if (map != null) {
            this.mMapHeadData = map;
        }
    }

    public void setOverrideExtension(String str) {
        this.mOverrideExtension = str;
    }

    public void setPlayPosition(int i2) {
        this.mPlayPosition = i2;
    }

    public void setPlayTag(String str) {
        this.mPlayTag = str;
    }

    public void setReleaseWhenLossAudio(boolean z) {
        this.mReleaseWhenLossAudio = z;
    }

    public void setSeekOnStart(long j2) {
        this.mSeekOnStart = j2;
    }

    public void setShowPauseCover(boolean z) {
        this.mShowPauseCover = z;
    }

    public void setSpeed(float f2) {
        setSpeed(f2, false);
    }

    public void setSpeedPlaying(float f2, boolean z) {
        setSpeed(f2, z);
        getGSYVideoManager().setSpeedPlaying(f2, z);
    }

    public void setStartAfterPrepared(boolean z) {
        this.mStartAfterPrepared = z;
    }

    public abstract void setStateAndUi(int i2);

    public boolean setUp(String str, boolean z, String str2) {
        return setUp(str, z, null, str2);
    }

    public void setVideoAllCallBack(InterfaceC2931g interfaceC2931g) {
        this.mVideoAllCallBack = interfaceC2931g;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYTextureRenderView
    public void showPauseCover() {
        Bitmap bitmap;
        Surface surface;
        if (this.mCurrentState == 5 && (bitmap = this.mFullPauseBitmap) != null && !bitmap.isRecycled() && this.mShowPauseCover && (surface = this.mSurface) != null && surface.isValid() && getGSYVideoManager().isSurfaceSupportLockCanvas()) {
            try {
                InterfaceC2944a interfaceC2944a = this.mTextureView.f8046a;
                RectF rectF = new RectF(0.0f, 0.0f, interfaceC2944a != null ? interfaceC2944a.getRenderView().getWidth() : 0, this.mTextureView.f8046a != null ? r3.getRenderView().getHeight() : 0);
                Surface surface2 = this.mSurface;
                InterfaceC2944a interfaceC2944a2 = this.mTextureView.f8046a;
                int width = interfaceC2944a2 != null ? interfaceC2944a2.getRenderView().getWidth() : 0;
                InterfaceC2944a interfaceC2944a3 = this.mTextureView.f8046a;
                Canvas lockCanvas = surface2.lockCanvas(new Rect(0, 0, width, interfaceC2944a3 != null ? interfaceC2944a3.getRenderView().getHeight() : 0));
                if (lockCanvas != null) {
                    lockCanvas.drawBitmap(this.mFullPauseBitmap, (Rect) null, rectF, (Paint) null);
                    this.mSurface.unlockCanvasAndPost(lockCanvas);
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }

    public void startAfterPrepared() {
        InterfaceC2944a interfaceC2944a;
        if (!this.mHadPrepared) {
            prepareVideo();
        }
        try {
            if (getGSYVideoManager() != null) {
                getGSYVideoManager().start();
            }
            setStateAndUi(2);
            if (getGSYVideoManager() != null && this.mSeekOnStart > 0) {
                getGSYVideoManager().seekTo(this.mSeekOnStart);
                this.mSeekOnStart = 0L;
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        addTextureView();
        createNetWorkState();
        listenerNetWorkState();
        this.mHadPlay = true;
        C2939a c2939a = this.mTextureView;
        if (c2939a != null && (interfaceC2944a = c2939a.f8046a) != null) {
            interfaceC2944a.mo3410c();
        }
        if (this.mPauseBeforePrepared) {
            onVideoPause();
            this.mPauseBeforePrepared = false;
        }
    }

    public void startButtonLogic() {
        InterfaceC2931g interfaceC2931g = this.mVideoAllCallBack;
        if (interfaceC2931g != null && this.mCurrentState == 0) {
            Debuger.printfLog("onClickStartIcon");
            this.mVideoAllCallBack.onClickStartIcon(this.mOriginUrl, this.mTitle, this);
        } else if (interfaceC2931g != null) {
            Debuger.printfLog("onClickStartError");
            this.mVideoAllCallBack.onClickStartError(this.mOriginUrl, this.mTitle, this);
        }
        prepareVideo();
    }

    public abstract void startPlayLogic();

    public void startPrepare() {
        if (getGSYVideoManager().listener() != null) {
            getGSYVideoManager().listener().onCompletion();
        }
        if (this.mVideoAllCallBack != null) {
            Debuger.printfLog("onStartPrepared");
            this.mVideoAllCallBack.onStartPrepared(this.mOriginUrl, this.mTitle, this);
        }
        getGSYVideoManager().setListener(this);
        getGSYVideoManager().setPlayTag(this.mPlayTag);
        getGSYVideoManager().setPlayPosition(this.mPlayPosition);
        this.mAudioManager.requestAudioFocus(this.onAudioFocusChangeListener, 3, 2);
        try {
            Context context = this.mContext;
            if (context instanceof Activity) {
                ((Activity) context).getWindow().addFlags(128);
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        this.mBackUpPlayingBufferState = -1;
        GSYVideoViewBridge gSYVideoManager = getGSYVideoManager();
        String str = this.mUrl;
        Map<String, String> map = this.mMapHeadData;
        if (map == null) {
            map = new HashMap<>();
        }
        gSYVideoManager.prepare(str, map, this.mLooping, this.mSpeed, this.mCache, this.mCachePath, this.mOverrideExtension);
        setStateAndUi(1);
    }

    public void unListenerNetWorkState() {
        NetInfoModule netInfoModule = this.mNetInfoModule;
        if (netInfoModule != null) {
            netInfoModule.onHostPause();
        }
    }

    public void updatePauseCover() {
        Bitmap bitmap = this.mFullPauseBitmap;
        if ((bitmap == null || bitmap.isRecycled()) && this.mShowPauseCover) {
            try {
                initCover();
            } catch (Exception e2) {
                e2.printStackTrace();
                this.mFullPauseBitmap = null;
            }
        }
    }

    public void onVideoResume(boolean z) {
        this.mPauseBeforePrepared = false;
        if (this.mCurrentState == 5) {
            try {
                if (this.mCurrentPosition < 0 || getGSYVideoManager() == null) {
                    return;
                }
                if (z) {
                    getGSYVideoManager().seekTo(this.mCurrentPosition);
                }
                getGSYVideoManager().start();
                setStateAndUi(2);
                AudioManager audioManager = this.mAudioManager;
                if (audioManager != null && !this.mReleaseWhenLossAudio) {
                    audioManager.requestAudioFocus(this.onAudioFocusChangeListener, 3, 2);
                }
                this.mCurrentPosition = 0L;
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }

    public void setSpeed(float f2, boolean z) {
        this.mSpeed = f2;
        this.mSoundTouch = z;
        if (getGSYVideoManager() != null) {
            getGSYVideoManager().setSpeed(f2, z);
        }
    }

    public boolean setUp(String str, boolean z, File file, Map<String, String> map, String str2) {
        if (!setUp(str, z, file, str2)) {
            return false;
        }
        Map<String, String> map2 = this.mMapHeadData;
        if (map2 != null) {
            map2.clear();
        } else {
            this.mMapHeadData = new HashMap();
        }
        if (map == null) {
            return true;
        }
        this.mMapHeadData.putAll(map);
        return true;
    }

    public boolean setUp(String str, boolean z, File file, String str2) {
        return setUp(str, z, file, str2, true);
    }

    public boolean setUp(String str, boolean z, File file, String str2, boolean z2) {
        this.mCache = z;
        this.mCachePath = file;
        this.mOriginUrl = str;
        if (isCurrentMediaListener() && System.currentTimeMillis() - this.mSaveChangeViewTIme < 2000) {
            return false;
        }
        this.mCurrentState = 0;
        this.mUrl = str;
        this.mTitle = str2;
        if (!z2) {
            return true;
        }
        setStateAndUi(0);
        return true;
    }

    public GSYVideoView(@NonNull Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        this.mCurrentState = -1;
        this.mPlayPosition = -22;
        this.mBackUpPlayingBufferState = -1;
        this.mSeekOnStart = -1L;
        this.mSaveChangeViewTIme = 0L;
        this.mSpeed = 1.0f;
        this.mCache = false;
        this.mIfCurrentIsFullscreen = false;
        this.mLooping = false;
        this.mHadPlay = false;
        this.mNetChanged = false;
        this.mSoundTouch = false;
        this.mShowPauseCover = false;
        this.mPauseBeforePrepared = false;
        this.mStartAfterPrepared = true;
        this.mHadPrepared = false;
        this.mReleaseWhenLossAudio = true;
        this.mPlayTag = "";
        this.mNetSate = "NORMAL";
        this.mMapHeadData = new HashMap();
        this.onAudioFocusChangeListener = new AudioManager.OnAudioFocusChangeListener() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoView.1
            @Override // android.media.AudioManager.OnAudioFocusChangeListener
            public void onAudioFocusChange(int i2) {
                if (i2 == -3) {
                    GSYVideoView.this.onLossTransientCanDuck();
                    return;
                }
                if (i2 == -2) {
                    GSYVideoView.this.onLossTransientAudio();
                } else if (i2 == -1) {
                    GSYVideoView.this.onLossAudio();
                } else {
                    if (i2 != 1) {
                        return;
                    }
                    GSYVideoView.this.onGankAudio();
                }
            }
        };
        init(context);
    }

    public GSYVideoView(@NonNull Context context, @Nullable AttributeSet attributeSet, @AttrRes int i2) {
        super(context, attributeSet, i2);
        this.mCurrentState = -1;
        this.mPlayPosition = -22;
        this.mBackUpPlayingBufferState = -1;
        this.mSeekOnStart = -1L;
        this.mSaveChangeViewTIme = 0L;
        this.mSpeed = 1.0f;
        this.mCache = false;
        this.mIfCurrentIsFullscreen = false;
        this.mLooping = false;
        this.mHadPlay = false;
        this.mNetChanged = false;
        this.mSoundTouch = false;
        this.mShowPauseCover = false;
        this.mPauseBeforePrepared = false;
        this.mStartAfterPrepared = true;
        this.mHadPrepared = false;
        this.mReleaseWhenLossAudio = true;
        this.mPlayTag = "";
        this.mNetSate = "NORMAL";
        this.mMapHeadData = new HashMap();
        this.onAudioFocusChangeListener = new AudioManager.OnAudioFocusChangeListener() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoView.1
            @Override // android.media.AudioManager.OnAudioFocusChangeListener
            public void onAudioFocusChange(int i22) {
                if (i22 == -3) {
                    GSYVideoView.this.onLossTransientCanDuck();
                    return;
                }
                if (i22 == -2) {
                    GSYVideoView.this.onLossTransientAudio();
                } else if (i22 == -1) {
                    GSYVideoView.this.onLossAudio();
                } else {
                    if (i22 != 1) {
                        return;
                    }
                    GSYVideoView.this.onGankAudio();
                }
            }
        };
        init(context);
    }

    public GSYVideoView(Context context, Boolean bool) {
        super(context);
        this.mCurrentState = -1;
        this.mPlayPosition = -22;
        this.mBackUpPlayingBufferState = -1;
        this.mSeekOnStart = -1L;
        this.mSaveChangeViewTIme = 0L;
        this.mSpeed = 1.0f;
        this.mCache = false;
        this.mIfCurrentIsFullscreen = false;
        this.mLooping = false;
        this.mHadPlay = false;
        this.mNetChanged = false;
        this.mSoundTouch = false;
        this.mShowPauseCover = false;
        this.mPauseBeforePrepared = false;
        this.mStartAfterPrepared = true;
        this.mHadPrepared = false;
        this.mReleaseWhenLossAudio = true;
        this.mPlayTag = "";
        this.mNetSate = "NORMAL";
        this.mMapHeadData = new HashMap();
        this.onAudioFocusChangeListener = new AudioManager.OnAudioFocusChangeListener() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoView.1
            @Override // android.media.AudioManager.OnAudioFocusChangeListener
            public void onAudioFocusChange(int i22) {
                if (i22 == -3) {
                    GSYVideoView.this.onLossTransientCanDuck();
                    return;
                }
                if (i22 == -2) {
                    GSYVideoView.this.onLossTransientAudio();
                } else if (i22 == -1) {
                    GSYVideoView.this.onLossAudio();
                } else {
                    if (i22 != 1) {
                        return;
                    }
                    GSYVideoView.this.onGankAudio();
                }
            }
        };
        this.mIfCurrentIsFullscreen = bool.booleanValue();
        init(context);
    }
}
