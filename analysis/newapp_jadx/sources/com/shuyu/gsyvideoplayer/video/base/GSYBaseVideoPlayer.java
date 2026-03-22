package com.shuyu.gsyvideoplayer.video.base;

import android.R;
import android.app.Activity;
import android.content.Context;
import android.content.res.Configuration;
import android.graphics.Bitmap;
import android.graphics.Point;
import android.os.Handler;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.SeekBar;
import android.widget.TextView;
import androidx.core.view.ViewCompat;
import androidx.transition.TransitionManager;
import com.shuyu.gsyvideoplayer.R$id;
import com.shuyu.gsyvideoplayer.utils.CommonUtil;
import com.shuyu.gsyvideoplayer.utils.Debuger;
import com.shuyu.gsyvideoplayer.utils.OrientationOption;
import com.shuyu.gsyvideoplayer.utils.OrientationUtils;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p362y.p363a.p374j.ViewOnTouchListenerC2948a;

/* loaded from: classes2.dex */
public abstract class GSYBaseVideoPlayer extends GSYVideoControlView {
    public boolean isNeedAutoAdaptation;
    public boolean mActionBar;
    public boolean mAutoFullWithSize;
    public View.OnClickListener mBackFromFullScreenListener;
    public Runnable mCheckoutTask;
    public boolean mFullAnimEnd;
    public Handler mInnerHandler;
    private boolean mIsOnlyRotateLand;
    public int[] mListItemRect;
    public int[] mListItemSize;
    public boolean mLockLand;
    public OrientationUtils mOrientationUtils;
    public boolean mRotateViewAuto;
    public boolean mRotateWithSystem;
    public boolean mShowFullAnimation;
    public View mSmallClose;
    public boolean mStatusBar;
    public int mSystemUiVisibility;

    public GSYBaseVideoPlayer(Context context, Boolean bool) {
        super(context, bool);
        this.mActionBar = false;
        this.mStatusBar = false;
        this.mShowFullAnimation = true;
        this.mRotateViewAuto = true;
        this.mRotateWithSystem = true;
        this.mLockLand = false;
        this.mAutoFullWithSize = false;
        this.isNeedAutoAdaptation = false;
        this.mFullAnimEnd = true;
        this.mIsOnlyRotateLand = false;
        this.mInnerHandler = new Handler();
        this.mCheckoutTask = new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer.5
            @Override // java.lang.Runnable
            public void run() {
                int i2;
                int i3;
                GSYVideoPlayer fullWindowPlayer = GSYBaseVideoPlayer.this.getFullWindowPlayer();
                if (fullWindowPlayer == null || (i2 = fullWindowPlayer.mCurrentState) == (i3 = GSYBaseVideoPlayer.this.mCurrentState) || i2 != 3 || i3 == 1) {
                    return;
                }
                fullWindowPlayer.setStateAndUi(i3);
            }
        };
    }

    private ViewGroup getViewGroup() {
        return (ViewGroup) CommonUtil.scanForActivity(getContext()).findViewById(R.id.content);
    }

    private void pauseFullBackCoverLogic(GSYBaseVideoPlayer gSYBaseVideoPlayer) {
        if (gSYBaseVideoPlayer.mCurrentState == 5 && gSYBaseVideoPlayer.mTextureView != null && this.mShowPauseCover) {
            Bitmap bitmap = gSYBaseVideoPlayer.mFullPauseBitmap;
            if (bitmap != null && !bitmap.isRecycled() && this.mShowPauseCover) {
                this.mFullPauseBitmap = gSYBaseVideoPlayer.mFullPauseBitmap;
                return;
            }
            if (this.mShowPauseCover) {
                try {
                    initCover();
                } catch (Exception e2) {
                    e2.printStackTrace();
                    this.mFullPauseBitmap = null;
                }
            }
        }
    }

    private void pauseFullCoverLogic() {
        if (this.mCurrentState != 5 || this.mTextureView == null) {
            return;
        }
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

    private void removeVideo(ViewGroup viewGroup, int i2) {
        View findViewById = viewGroup.findViewById(i2);
        if (findViewById == null || findViewById.getParent() == null) {
            return;
        }
        viewGroup.removeView((ViewGroup) findViewById.getParent());
    }

    private void saveLocationStatus(Context context, boolean z, boolean z2) {
        getLocationOnScreen(this.mListItemRect);
        if (context instanceof Activity) {
            int statusBarHeight = CommonUtil.getStatusBarHeight(context);
            Activity activity = (Activity) context;
            int actionBarHeight = CommonUtil.getActionBarHeight(activity);
            boolean z3 = (activity.getWindow().getAttributes().flags & 67108864) == 67108864;
            Debuger.printfLog("*************isTranslucent*************** " + z3);
            if (z && !z3) {
                int[] iArr = this.mListItemRect;
                iArr[1] = iArr[1] - statusBarHeight;
            }
            if (z2) {
                int[] iArr2 = this.mListItemRect;
                iArr2[1] = iArr2[1] - actionBarHeight;
            }
        }
        this.mListItemSize[0] = getWidth();
        this.mListItemSize[1] = getHeight();
    }

    public void autoAdaptation() {
        Context context = getContext();
        if (isVerticalVideo()) {
            int[] iArr = new int[2];
            getLocationOnScreen(iArr);
            if (iArr[1] == 0) {
                setPadding(0, CommonUtil.getStatusBarHeight(context), 0, 0);
                Debuger.printfLog("竖屏，系统未将布局下移");
            } else {
                StringBuilder m586H = C1499a.m586H("竖屏，系统将布局下移；y:");
                m586H.append(iArr[1]);
                Debuger.printfLog(m586H.toString());
            }
        }
    }

    public void backToNormal() {
        final ViewGroup viewGroup = getViewGroup();
        final View findViewById = viewGroup.findViewById(getFullId());
        if (findViewById == null) {
            resolveNormalVideoShow(null, viewGroup, null);
            return;
        }
        final GSYVideoPlayer gSYVideoPlayer = (GSYVideoPlayer) findViewById;
        pauseFullBackCoverLogic(gSYVideoPlayer);
        if (!this.mShowFullAnimation) {
            resolveNormalVideoShow(findViewById, viewGroup, gSYVideoPlayer);
            return;
        }
        TransitionManager.beginDelayedTransition(viewGroup);
        FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) gSYVideoPlayer.getLayoutParams();
        int[] iArr = this.mListItemRect;
        layoutParams.setMargins(iArr[0], iArr[1], 0, 0);
        int[] iArr2 = this.mListItemSize;
        layoutParams.width = iArr2[0];
        layoutParams.height = iArr2[1];
        layoutParams.gravity = 0;
        gSYVideoPlayer.setLayoutParams(layoutParams);
        this.mInnerHandler.postDelayed(new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer.4
            @Override // java.lang.Runnable
            public void run() {
                GSYBaseVideoPlayer.this.resolveNormalVideoShow(findViewById, viewGroup, gSYVideoPlayer);
            }
        }, 400L);
    }

    public void checkAutoFullSizeWhenFull() {
        OrientationUtils orientationUtils;
        if (this.mIfCurrentIsFullscreen) {
            boolean isVerticalFullByVideoSize = isVerticalFullByVideoSize();
            Debuger.printfLog("GSYVideoBase onPrepared isVerticalFullByVideoSize " + isVerticalFullByVideoSize);
            if (!isVerticalFullByVideoSize || (orientationUtils = this.mOrientationUtils) == null) {
                return;
            }
            orientationUtils.backToProtVideo();
            checkAutoFullWithSizeAndAdaptation(this);
        }
    }

    public void checkAutoFullWithSizeAndAdaptation(final GSYBaseVideoPlayer gSYBaseVideoPlayer) {
        if (gSYBaseVideoPlayer != null && this.isNeedAutoAdaptation && isAutoFullWithSize() && isVerticalVideo() && isFullHideStatusBar()) {
            this.mInnerHandler.postDelayed(new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer.9
                @Override // java.lang.Runnable
                public void run() {
                    gSYBaseVideoPlayer.getCurrentPlayer().autoAdaptation();
                }
            }, 100L);
        }
    }

    public void checkoutState() {
        removeCallbacks(this.mCheckoutTask);
        this.mInnerHandler.postDelayed(this.mCheckoutTask, 500L);
    }

    public void clearFullscreenLayout() {
        int i2;
        if (this.mFullAnimEnd) {
            this.mIfCurrentIsFullscreen = false;
            OrientationUtils orientationUtils = this.mOrientationUtils;
            if (orientationUtils != null) {
                i2 = orientationUtils.backToProtVideo();
                this.mOrientationUtils.setEnable(false);
                OrientationUtils orientationUtils2 = this.mOrientationUtils;
                if (orientationUtils2 != null) {
                    orientationUtils2.releaseListener();
                    this.mOrientationUtils = null;
                }
            } else {
                i2 = 0;
            }
            if (!this.mShowFullAnimation) {
                i2 = 0;
            }
            View findViewById = getViewGroup().findViewById(getFullId());
            if (findViewById != null) {
                ((GSYVideoPlayer) findViewById).mIfCurrentIsFullscreen = false;
            }
            this.mInnerHandler.postDelayed(new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer.3
                @Override // java.lang.Runnable
                public void run() {
                    GSYBaseVideoPlayer.this.backToNormal();
                }
            }, i2);
        }
    }

    public void cloneParams(GSYBaseVideoPlayer gSYBaseVideoPlayer, GSYBaseVideoPlayer gSYBaseVideoPlayer2) {
        gSYBaseVideoPlayer2.mHadPlay = gSYBaseVideoPlayer.mHadPlay;
        gSYBaseVideoPlayer2.mPlayTag = gSYBaseVideoPlayer.mPlayTag;
        gSYBaseVideoPlayer2.mPlayPosition = gSYBaseVideoPlayer.mPlayPosition;
        gSYBaseVideoPlayer2.mEffectFilter = gSYBaseVideoPlayer.mEffectFilter;
        gSYBaseVideoPlayer2.mFullPauseBitmap = gSYBaseVideoPlayer.mFullPauseBitmap;
        gSYBaseVideoPlayer2.mNeedShowWifiTip = gSYBaseVideoPlayer.mNeedShowWifiTip;
        gSYBaseVideoPlayer2.mShrinkImageRes = gSYBaseVideoPlayer.mShrinkImageRes;
        gSYBaseVideoPlayer2.mEnlargeImageRes = gSYBaseVideoPlayer.mEnlargeImageRes;
        gSYBaseVideoPlayer2.mRotate = gSYBaseVideoPlayer.mRotate;
        gSYBaseVideoPlayer2.mShowPauseCover = gSYBaseVideoPlayer.mShowPauseCover;
        gSYBaseVideoPlayer2.mDismissControlTime = gSYBaseVideoPlayer.mDismissControlTime;
        gSYBaseVideoPlayer2.mSeekRatio = gSYBaseVideoPlayer.mSeekRatio;
        gSYBaseVideoPlayer2.mNetChanged = gSYBaseVideoPlayer.mNetChanged;
        gSYBaseVideoPlayer2.mNetSate = gSYBaseVideoPlayer.mNetSate;
        gSYBaseVideoPlayer2.mRotateWithSystem = gSYBaseVideoPlayer.mRotateWithSystem;
        gSYBaseVideoPlayer2.mBackUpPlayingBufferState = gSYBaseVideoPlayer.mBackUpPlayingBufferState;
        gSYBaseVideoPlayer2.mRenderer = gSYBaseVideoPlayer.mRenderer;
        gSYBaseVideoPlayer2.mMode = gSYBaseVideoPlayer.mMode;
        gSYBaseVideoPlayer2.mBackFromFullScreenListener = gSYBaseVideoPlayer.mBackFromFullScreenListener;
        gSYBaseVideoPlayer2.mGSYVideoProgressListener = gSYBaseVideoPlayer.mGSYVideoProgressListener;
        gSYBaseVideoPlayer2.mHadPrepared = gSYBaseVideoPlayer.mHadPrepared;
        gSYBaseVideoPlayer2.mStartAfterPrepared = gSYBaseVideoPlayer.mStartAfterPrepared;
        gSYBaseVideoPlayer2.mPauseBeforePrepared = gSYBaseVideoPlayer.mPauseBeforePrepared;
        gSYBaseVideoPlayer2.mReleaseWhenLossAudio = gSYBaseVideoPlayer.mReleaseWhenLossAudio;
        gSYBaseVideoPlayer2.mVideoAllCallBack = gSYBaseVideoPlayer.mVideoAllCallBack;
        gSYBaseVideoPlayer2.mActionBar = gSYBaseVideoPlayer.mActionBar;
        gSYBaseVideoPlayer2.mStatusBar = gSYBaseVideoPlayer.mStatusBar;
        gSYBaseVideoPlayer2.mAutoFullWithSize = gSYBaseVideoPlayer.mAutoFullWithSize;
        gSYBaseVideoPlayer2.mOverrideExtension = gSYBaseVideoPlayer.mOverrideExtension;
        if (gSYBaseVideoPlayer.mSetUpLazy) {
            gSYBaseVideoPlayer2.setUpLazy(gSYBaseVideoPlayer.mOriginUrl, gSYBaseVideoPlayer.mCache, gSYBaseVideoPlayer.mCachePath, gSYBaseVideoPlayer.mMapHeadData, gSYBaseVideoPlayer.mTitle);
            gSYBaseVideoPlayer2.mUrl = gSYBaseVideoPlayer.mUrl;
        } else {
            gSYBaseVideoPlayer2.setUp(gSYBaseVideoPlayer.mOriginUrl, gSYBaseVideoPlayer.mCache, gSYBaseVideoPlayer.mCachePath, gSYBaseVideoPlayer.mMapHeadData, gSYBaseVideoPlayer.mTitle);
        }
        gSYBaseVideoPlayer2.setLooping(gSYBaseVideoPlayer.isLooping());
        gSYBaseVideoPlayer2.setIsTouchWigetFull(gSYBaseVideoPlayer.mIsTouchWigetFull);
        gSYBaseVideoPlayer2.setSpeed(gSYBaseVideoPlayer.getSpeed(), gSYBaseVideoPlayer.mSoundTouch);
        gSYBaseVideoPlayer2.setStateAndUi(gSYBaseVideoPlayer.mCurrentState);
    }

    public GSYBaseVideoPlayer getCurrentPlayer() {
        return getFullWindowPlayer() != null ? getFullWindowPlayer() : getSmallWindowPlayer() != null ? getSmallWindowPlayer() : this;
    }

    public abstract int getFullId();

    public GSYVideoPlayer getFullWindowPlayer() {
        View findViewById = ((ViewGroup) CommonUtil.scanForActivity(getContext()).findViewById(R.id.content)).findViewById(getFullId());
        if (findViewById != null) {
            return (GSYVideoPlayer) findViewById;
        }
        return null;
    }

    public OrientationOption getOrientationOption() {
        return null;
    }

    public int getSaveBeforeFullSystemUiVisibility() {
        return this.mSystemUiVisibility;
    }

    public abstract int getSmallId();

    public GSYVideoPlayer getSmallWindowPlayer() {
        View findViewById = ((ViewGroup) CommonUtil.scanForActivity(getContext()).findViewById(R.id.content)).findViewById(getSmallId());
        if (findViewById != null) {
            return (GSYVideoPlayer) findViewById;
        }
        return null;
    }

    public void hideSmallVideo() {
        ViewGroup viewGroup = getViewGroup();
        GSYVideoPlayer gSYVideoPlayer = (GSYVideoPlayer) viewGroup.findViewById(getSmallId());
        removeVideo(viewGroup, getSmallId());
        this.mCurrentState = getGSYVideoManager().getLastState();
        if (gSYVideoPlayer != null) {
            cloneParams(gSYVideoPlayer, this);
        }
        getGSYVideoManager().setListener(getGSYVideoManager().lastListener());
        getGSYVideoManager().setLastListener(null);
        setStateAndUi(this.mCurrentState);
        addTextureView();
        this.mSaveChangeViewTIme = System.currentTimeMillis();
        if (this.mVideoAllCallBack != null) {
            Debuger.printfLog("onQuitSmallWidget");
            this.mVideoAllCallBack.onQuitSmallWidget(this.mOriginUrl, this.mTitle, this);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public void init(Context context) {
        super.init(context);
        this.mSmallClose = findViewById(R$id.small_close);
    }

    public boolean isAutoFullWithSize() {
        return this.mAutoFullWithSize;
    }

    public boolean isFullHideActionBar() {
        return this.mActionBar;
    }

    public boolean isFullHideStatusBar() {
        return this.mStatusBar;
    }

    public boolean isLockLand() {
        return this.mLockLand;
    }

    public boolean isLockLandByAutoFullSize() {
        boolean z = this.mLockLand;
        if (isAutoFullWithSize()) {
            return true;
        }
        return z;
    }

    public boolean isNeedAutoAdaptation() {
        return this.isNeedAutoAdaptation;
    }

    public boolean isOnlyRotateLand() {
        return this.mIsOnlyRotateLand;
    }

    public boolean isRotateViewAuto() {
        if (this.mAutoFullWithSize) {
            return false;
        }
        return this.mRotateViewAuto;
    }

    public boolean isRotateWithSystem() {
        return this.mRotateWithSystem;
    }

    public boolean isShowFullAnimation() {
        return this.mShowFullAnimation;
    }

    public boolean isVerticalFullByVideoSize() {
        return isVerticalVideo() && isAutoFullWithSize();
    }

    public boolean isVerticalVideo() {
        int currentVideoHeight = getCurrentVideoHeight();
        int currentVideoWidth = getCurrentVideoWidth();
        Debuger.printfLog("GSYVideoBase isVerticalVideo  videoHeight " + currentVideoHeight + " videoWidth " + currentVideoWidth);
        StringBuilder sb = new StringBuilder();
        sb.append("GSYVideoBase isVerticalVideo  mRotate ");
        sb.append(this.mRotate);
        Debuger.printfLog(sb.toString());
        if (currentVideoHeight <= 0 || currentVideoWidth <= 0) {
            return false;
        }
        int i2 = this.mRotate;
        if (i2 == 90 || i2 == 270) {
            if (currentVideoWidth <= currentVideoHeight) {
                return false;
            }
        } else if (currentVideoHeight <= currentVideoWidth) {
            return false;
        }
        return true;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void lockTouchLogic() {
        super.lockTouchLogic();
        if (this.mLockCurScreen) {
            OrientationUtils orientationUtils = this.mOrientationUtils;
            if (orientationUtils != null) {
                orientationUtils.setEnable(false);
                return;
            }
            return;
        }
        OrientationUtils orientationUtils2 = this.mOrientationUtils;
        if (orientationUtils2 != null) {
            orientationUtils2.setEnable(isRotateViewAuto());
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, com.shuyu.gsyvideoplayer.video.base.GSYVideoView, p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onBackFullscreen() {
        clearFullscreenLayout();
    }

    public void onConfigurationChanged(Activity activity, Configuration configuration, OrientationUtils orientationUtils) {
        onConfigurationChanged(activity, configuration, orientationUtils, true, true);
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView, p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onInfo(int i2, int i3) {
        super.onInfo(i2, i3);
        if (i2 == getGSYVideoManager().getRotateInfoFlag()) {
            checkAutoFullSizeWhenFull();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, com.shuyu.gsyvideoplayer.video.base.GSYVideoView, p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onPrepared() {
        super.onPrepared();
        checkAutoFullSizeWhenFull();
    }

    public void resolveFullVideoShow(Context context, final GSYBaseVideoPlayer gSYBaseVideoPlayer, final FrameLayout frameLayout) {
        OrientationUtils orientationUtils;
        FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) gSYBaseVideoPlayer.getLayoutParams();
        layoutParams.setMargins(0, 0, 0, 0);
        layoutParams.height = -1;
        layoutParams.width = -1;
        layoutParams.gravity = 17;
        gSYBaseVideoPlayer.setLayoutParams(layoutParams);
        gSYBaseVideoPlayer.setIfCurrentIsFullscreen(true);
        OrientationUtils orientationUtils2 = new OrientationUtils((Activity) context, gSYBaseVideoPlayer, getOrientationOption());
        this.mOrientationUtils = orientationUtils2;
        orientationUtils2.setEnable(isRotateViewAuto());
        this.mOrientationUtils.setRotateWithSystem(this.mRotateWithSystem);
        this.mOrientationUtils.setOnlyRotateLand(this.mIsOnlyRotateLand);
        gSYBaseVideoPlayer.mOrientationUtils = this.mOrientationUtils;
        final boolean isVerticalFullByVideoSize = isVerticalFullByVideoSize();
        final boolean isLockLandByAutoFullSize = isLockLandByAutoFullSize();
        if (isShowFullAnimation()) {
            this.mInnerHandler.postDelayed(new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer.2
                @Override // java.lang.Runnable
                public void run() {
                    OrientationUtils orientationUtils3;
                    if (!isVerticalFullByVideoSize && isLockLandByAutoFullSize && (orientationUtils3 = GSYBaseVideoPlayer.this.mOrientationUtils) != null && orientationUtils3.getIsLand() != 1) {
                        GSYBaseVideoPlayer.this.mOrientationUtils.resolveByClick();
                    }
                    gSYBaseVideoPlayer.setVisibility(0);
                    frameLayout.setVisibility(0);
                }
            }, 300L);
        } else {
            if (!isVerticalFullByVideoSize && isLockLandByAutoFullSize && (orientationUtils = this.mOrientationUtils) != null) {
                orientationUtils.resolveByClick();
            }
            gSYBaseVideoPlayer.setVisibility(0);
            frameLayout.setVisibility(0);
        }
        if (this.mVideoAllCallBack != null) {
            Debuger.printfError("onEnterFullscreen");
            this.mVideoAllCallBack.onEnterFullscreen(this.mOriginUrl, this.mTitle, gSYBaseVideoPlayer);
        }
        this.mIfCurrentIsFullscreen = true;
        checkoutState();
        checkAutoFullWithSizeAndAdaptation(gSYBaseVideoPlayer);
    }

    public void resolveNormalVideoShow(View view, ViewGroup viewGroup, GSYVideoPlayer gSYVideoPlayer) {
        if (view != null && view.getParent() != null) {
            viewGroup.removeView((ViewGroup) view.getParent());
        }
        this.mCurrentState = getGSYVideoManager().getLastState();
        if (gSYVideoPlayer != null) {
            cloneParams(gSYVideoPlayer, this);
        }
        int i2 = this.mCurrentState;
        if (i2 != 0 || i2 != 6) {
            createNetWorkState();
        }
        getGSYVideoManager().setListener(getGSYVideoManager().lastListener());
        getGSYVideoManager().setLastListener(null);
        setStateAndUi(this.mCurrentState);
        addTextureView();
        this.mSaveChangeViewTIme = System.currentTimeMillis();
        if (this.mVideoAllCallBack != null) {
            Debuger.printfError("onQuitFullscreen");
            this.mVideoAllCallBack.onQuitFullscreen(this.mOriginUrl, this.mTitle, this);
        }
        this.mIfCurrentIsFullscreen = false;
        if (this.mHideKey) {
            CommonUtil.showNavKey(this.mContext, this.mSystemUiVisibility);
        }
        CommonUtil.showSupportActionBar(this.mContext, this.mActionBar, this.mStatusBar);
        if (getFullscreenButton() != null) {
            getFullscreenButton().setImageResource(getEnlargeImageRes());
        }
    }

    public void setAutoFullWithSize(boolean z) {
        this.mAutoFullWithSize = z;
    }

    public void setBackFromFullScreenListener(View.OnClickListener onClickListener) {
        this.mBackFromFullScreenListener = onClickListener;
    }

    public void setFullHideActionBar(boolean z) {
        this.mActionBar = z;
    }

    public void setFullHideStatusBar(boolean z) {
        this.mStatusBar = z;
    }

    public void setLockLand(boolean z) {
        this.mLockLand = z;
    }

    public void setNeedAutoAdaptation(boolean z) {
        this.isNeedAutoAdaptation = z;
    }

    public void setOnlyRotateLand(boolean z) {
        this.mIsOnlyRotateLand = z;
        OrientationUtils orientationUtils = this.mOrientationUtils;
        if (orientationUtils != null) {
            orientationUtils.setOnlyRotateLand(z);
        }
    }

    public void setRotateViewAuto(boolean z) {
        this.mRotateViewAuto = z;
        OrientationUtils orientationUtils = this.mOrientationUtils;
        if (orientationUtils != null) {
            orientationUtils.setEnable(z);
        }
    }

    public void setRotateWithSystem(boolean z) {
        this.mRotateWithSystem = z;
        OrientationUtils orientationUtils = this.mOrientationUtils;
        if (orientationUtils != null) {
            orientationUtils.setRotateWithSystem(z);
        }
    }

    public void setSaveBeforeFullSystemUiVisibility(int i2) {
        this.mSystemUiVisibility = i2;
    }

    public void setShowFullAnimation(boolean z) {
        this.mShowFullAnimation = z;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYTextureRenderView
    public void setSmallVideoTextureView() {
        SeekBar seekBar = this.mProgressBar;
        if (seekBar != null) {
            seekBar.setOnTouchListener(null);
            this.mProgressBar.setVisibility(4);
        }
        ImageView imageView = this.mFullscreenButton;
        if (imageView != null) {
            imageView.setOnTouchListener(null);
            this.mFullscreenButton.setVisibility(4);
        }
        TextView textView = this.mCurrentTimeTextView;
        if (textView != null) {
            textView.setVisibility(4);
        }
        ViewGroup viewGroup = this.mTextureViewContainer;
        if (viewGroup != null) {
            viewGroup.setOnClickListener(null);
        }
        View view = this.mSmallClose;
        if (view != null) {
            view.setVisibility(0);
            this.mSmallClose.setOnClickListener(new View.OnClickListener() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer.1
                @Override // android.view.View.OnClickListener
                public void onClick(View view2) {
                    GSYBaseVideoPlayer.this.hideSmallVideo();
                    GSYBaseVideoPlayer.this.releaseVideos();
                }
            });
        }
    }

    public GSYBaseVideoPlayer showSmallVideo(Point point, boolean z, boolean z2) {
        ViewGroup viewGroup = getViewGroup();
        removeVideo(viewGroup, getSmallId());
        if (this.mTextureViewContainer.getChildCount() > 0) {
            this.mTextureViewContainer.removeAllViews();
        }
        try {
            GSYBaseVideoPlayer gSYBaseVideoPlayer = (GSYBaseVideoPlayer) getClass().getConstructor(Context.class).newInstance(getActivityContext());
            gSYBaseVideoPlayer.setId(getSmallId());
            ViewGroup.LayoutParams layoutParams = new FrameLayout.LayoutParams(-1, -1);
            FrameLayout frameLayout = new FrameLayout(this.mContext);
            FrameLayout.LayoutParams layoutParams2 = new FrameLayout.LayoutParams(point.x, point.y);
            int screenWidth = CommonUtil.getScreenWidth(this.mContext) - point.x;
            int screenHeight = CommonUtil.getScreenHeight(this.mContext) - point.y;
            if (z) {
                screenHeight -= CommonUtil.getActionBarHeight((Activity) this.mContext);
            }
            if (z2) {
                screenHeight -= CommonUtil.getStatusBarHeight(this.mContext);
            }
            layoutParams2.setMargins(screenWidth, screenHeight, 0, 0);
            frameLayout.addView(gSYBaseVideoPlayer, layoutParams2);
            viewGroup.addView(frameLayout, layoutParams);
            cloneParams(this, gSYBaseVideoPlayer);
            gSYBaseVideoPlayer.setIsTouchWiget(false);
            gSYBaseVideoPlayer.addTextureView();
            gSYBaseVideoPlayer.onClickUiToggle();
            gSYBaseVideoPlayer.setVideoAllCallBack(this.mVideoAllCallBack);
            gSYBaseVideoPlayer.setSmallVideoTextureView(new ViewOnTouchListenerC2948a(gSYBaseVideoPlayer, screenWidth, screenHeight));
            getGSYVideoManager().setLastListener(this);
            getGSYVideoManager().setListener(gSYBaseVideoPlayer);
            if (this.mVideoAllCallBack != null) {
                Debuger.printfError("onEnterSmallWidget");
                this.mVideoAllCallBack.onEnterSmallWidget(this.mOriginUrl, this.mTitle, gSYBaseVideoPlayer);
            }
            return gSYBaseVideoPlayer;
        } catch (Exception e2) {
            e2.printStackTrace();
            return null;
        }
    }

    public GSYBaseVideoPlayer startWindowFullscreen(final Context context, boolean z, boolean z2) {
        boolean z3;
        this.mSystemUiVisibility = ((Activity) context).getWindow().getDecorView().getSystemUiVisibility();
        CommonUtil.hideSupportActionBar(context, z, z2);
        if (this.mHideKey) {
            CommonUtil.hideNavKey(context);
        }
        this.mActionBar = z;
        this.mStatusBar = z2;
        this.mListItemRect = new int[2];
        this.mListItemSize = new int[2];
        final ViewGroup viewGroup = getViewGroup();
        removeVideo(viewGroup, getFullId());
        pauseFullCoverLogic();
        if (this.mTextureViewContainer.getChildCount() > 0) {
            this.mTextureViewContainer.removeAllViews();
        }
        saveLocationStatus(context, z2, z);
        cancelProgressTimer();
        try {
            getClass().getConstructor(Context.class, Boolean.class);
            z3 = true;
        } catch (Exception unused) {
            z3 = false;
        }
        try {
            GSYBaseVideoPlayer gSYBaseVideoPlayer = !z3 ? (GSYBaseVideoPlayer) getClass().getConstructor(Context.class).newInstance(this.mContext) : (GSYBaseVideoPlayer) getClass().getConstructor(Context.class, Boolean.class).newInstance(this.mContext, Boolean.TRUE);
            gSYBaseVideoPlayer.setId(getFullId());
            gSYBaseVideoPlayer.setIfCurrentIsFullscreen(true);
            gSYBaseVideoPlayer.setVideoAllCallBack(this.mVideoAllCallBack);
            cloneParams(this, gSYBaseVideoPlayer);
            if (gSYBaseVideoPlayer.getFullscreenButton() != null) {
                gSYBaseVideoPlayer.getFullscreenButton().setImageResource(getShrinkImageRes());
                gSYBaseVideoPlayer.getFullscreenButton().setOnClickListener(new View.OnClickListener() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer.6
                    @Override // android.view.View.OnClickListener
                    public void onClick(View view) {
                        GSYBaseVideoPlayer gSYBaseVideoPlayer2 = GSYBaseVideoPlayer.this;
                        View.OnClickListener onClickListener = gSYBaseVideoPlayer2.mBackFromFullScreenListener;
                        if (onClickListener == null) {
                            gSYBaseVideoPlayer2.clearFullscreenLayout();
                        } else {
                            onClickListener.onClick(view);
                        }
                    }
                });
            }
            if (gSYBaseVideoPlayer.getBackButton() != null) {
                gSYBaseVideoPlayer.getBackButton().setVisibility(0);
                gSYBaseVideoPlayer.getBackButton().setOnClickListener(new View.OnClickListener() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer.7
                    @Override // android.view.View.OnClickListener
                    public void onClick(View view) {
                        GSYBaseVideoPlayer gSYBaseVideoPlayer2 = GSYBaseVideoPlayer.this;
                        View.OnClickListener onClickListener = gSYBaseVideoPlayer2.mBackFromFullScreenListener;
                        if (onClickListener == null) {
                            gSYBaseVideoPlayer2.clearFullscreenLayout();
                        } else {
                            onClickListener.onClick(view);
                        }
                    }
                });
            }
            ViewGroup.LayoutParams layoutParams = new FrameLayout.LayoutParams(-1, -1);
            final FrameLayout frameLayout = new FrameLayout(context);
            frameLayout.setBackgroundColor(ViewCompat.MEASURED_STATE_MASK);
            if (this.mShowFullAnimation) {
                this.mFullAnimEnd = false;
                FrameLayout.LayoutParams layoutParams2 = new FrameLayout.LayoutParams(getWidth(), getHeight());
                int[] iArr = this.mListItemRect;
                layoutParams2.setMargins(iArr[0], iArr[1], 0, 0);
                frameLayout.addView(gSYBaseVideoPlayer, layoutParams2);
                viewGroup.addView(frameLayout, layoutParams);
                final GSYBaseVideoPlayer gSYBaseVideoPlayer2 = gSYBaseVideoPlayer;
                this.mInnerHandler.postDelayed(new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer.8
                    @Override // java.lang.Runnable
                    public void run() {
                        TransitionManager.beginDelayedTransition(viewGroup);
                        GSYBaseVideoPlayer.this.resolveFullVideoShow(context, gSYBaseVideoPlayer2, frameLayout);
                        GSYBaseVideoPlayer.this.mFullAnimEnd = true;
                    }
                }, 300L);
            } else {
                frameLayout.addView(gSYBaseVideoPlayer, new FrameLayout.LayoutParams(getWidth(), getHeight()));
                viewGroup.addView(frameLayout, layoutParams);
                gSYBaseVideoPlayer.setVisibility(4);
                frameLayout.setVisibility(4);
                resolveFullVideoShow(context, gSYBaseVideoPlayer, frameLayout);
            }
            gSYBaseVideoPlayer.addTextureView();
            gSYBaseVideoPlayer.startProgressTimer();
            getGSYVideoManager().setLastListener(this);
            getGSYVideoManager().setListener(gSYBaseVideoPlayer);
            checkoutState();
            return gSYBaseVideoPlayer;
        } catch (Exception e2) {
            e2.printStackTrace();
            return null;
        }
    }

    public void onConfigurationChanged(Activity activity, Configuration configuration, OrientationUtils orientationUtils, boolean z, boolean z2) {
        super.onConfigurationChanged(configuration);
        if (configuration.orientation == 2) {
            if (isIfCurrentIsFullscreen()) {
                return;
            }
            startWindowFullscreen(activity, z, z2);
        } else {
            if (isIfCurrentIsFullscreen() && !isVerticalFullByVideoSize()) {
                backFromFull(activity);
            }
            if (orientationUtils != null) {
                orientationUtils.setEnable(true);
            }
        }
    }

    public GSYBaseVideoPlayer(Context context) {
        super(context);
        this.mActionBar = false;
        this.mStatusBar = false;
        this.mShowFullAnimation = true;
        this.mRotateViewAuto = true;
        this.mRotateWithSystem = true;
        this.mLockLand = false;
        this.mAutoFullWithSize = false;
        this.isNeedAutoAdaptation = false;
        this.mFullAnimEnd = true;
        this.mIsOnlyRotateLand = false;
        this.mInnerHandler = new Handler();
        this.mCheckoutTask = new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer.5
            @Override // java.lang.Runnable
            public void run() {
                int i2;
                int i3;
                GSYVideoPlayer fullWindowPlayer = GSYBaseVideoPlayer.this.getFullWindowPlayer();
                if (fullWindowPlayer == null || (i2 = fullWindowPlayer.mCurrentState) == (i3 = GSYBaseVideoPlayer.this.mCurrentState) || i2 != 3 || i3 == 1) {
                    return;
                }
                fullWindowPlayer.setStateAndUi(i3);
            }
        };
    }

    public GSYBaseVideoPlayer(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.mActionBar = false;
        this.mStatusBar = false;
        this.mShowFullAnimation = true;
        this.mRotateViewAuto = true;
        this.mRotateWithSystem = true;
        this.mLockLand = false;
        this.mAutoFullWithSize = false;
        this.isNeedAutoAdaptation = false;
        this.mFullAnimEnd = true;
        this.mIsOnlyRotateLand = false;
        this.mInnerHandler = new Handler();
        this.mCheckoutTask = new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer.5
            @Override // java.lang.Runnable
            public void run() {
                int i2;
                int i3;
                GSYVideoPlayer fullWindowPlayer = GSYBaseVideoPlayer.this.getFullWindowPlayer();
                if (fullWindowPlayer == null || (i2 = fullWindowPlayer.mCurrentState) == (i3 = GSYBaseVideoPlayer.this.mCurrentState) || i2 != 3 || i3 == 1) {
                    return;
                }
                fullWindowPlayer.setStateAndUi(i3);
            }
        };
    }

    public GSYBaseVideoPlayer(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.mActionBar = false;
        this.mStatusBar = false;
        this.mShowFullAnimation = true;
        this.mRotateViewAuto = true;
        this.mRotateWithSystem = true;
        this.mLockLand = false;
        this.mAutoFullWithSize = false;
        this.isNeedAutoAdaptation = false;
        this.mFullAnimEnd = true;
        this.mIsOnlyRotateLand = false;
        this.mInnerHandler = new Handler();
        this.mCheckoutTask = new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer.5
            @Override // java.lang.Runnable
            public void run() {
                int i22;
                int i3;
                GSYVideoPlayer fullWindowPlayer = GSYBaseVideoPlayer.this.getFullWindowPlayer();
                if (fullWindowPlayer == null || (i22 = fullWindowPlayer.mCurrentState) == (i3 = GSYBaseVideoPlayer.this.mCurrentState) || i22 != 3 || i3 == 1) {
                    return;
                }
                fullWindowPlayer.setStateAndUi(i3);
            }
        };
    }
}
