package com.shuyu.gsyvideoplayer.video.base;

import android.app.Activity;
import android.content.Context;
import android.media.AudioManager;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import android.widget.SeekBar;
import android.widget.TextView;
import androidx.annotation.AttrRes;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.shuyu.gsyvideoplayer.R$drawable;
import com.shuyu.gsyvideoplayer.R$id;
import com.shuyu.gsyvideoplayer.R$string;
import com.shuyu.gsyvideoplayer.utils.CommonUtil;
import com.shuyu.gsyvideoplayer.utils.Debuger;
import java.io.File;
import java.util.Map;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p362y.p363a.p366f.InterfaceC2927c;
import p005b.p362y.p363a.p366f.InterfaceC2930f;

/* loaded from: classes2.dex */
public abstract class GSYVideoControlView extends GSYVideoView implements View.OnClickListener, View.OnTouchListener, SeekBar.OnSeekBarChangeListener {
    public Runnable dismissControlTask;
    public GestureDetector gestureDetector;
    public boolean isShowDragProgressTextOnSeekBar;
    public ImageView mBackButton;
    public ViewGroup mBottomContainer;
    public ProgressBar mBottomProgressBar;
    public boolean mBrightness;
    public float mBrightnessData;
    public boolean mChangePosition;
    public boolean mChangeVolume;
    public TextView mCurrentTimeTextView;
    public int mDismissControlTime;
    public int mDownPosition;
    public float mDownX;
    public float mDownY;
    public int mEnlargeImageRes;
    public boolean mFirstTouch;
    public ImageView mFullscreenButton;
    public InterfaceC2927c mGSYVideoProgressListener;
    public int mGestureDownVolume;
    public boolean mHadSeekTouch;
    public boolean mHideKey;
    public boolean mIsTouchWiget;
    public boolean mIsTouchWigetFull;
    public View mLoadingProgressBar;
    public InterfaceC2930f mLockClickListener;
    public boolean mLockCurScreen;
    public ImageView mLockScreen;
    public float mMoveY;
    public boolean mNeedLockFull;
    public boolean mNeedShowWifiTip;
    public boolean mPostDismiss;
    public boolean mPostProgress;
    public SeekBar mProgressBar;
    public int mSeekEndOffset;
    public float mSeekRatio;
    public int mSeekTimePosition;
    public boolean mSetUpLazy;
    public boolean mShowVKey;
    public int mShrinkImageRes;
    public View mStartButton;
    public int mThreshold;
    public View mThumbImageView;
    public RelativeLayout mThumbImageViewLayout;
    public boolean mThumbPlay;
    public TextView mTitleTextView;
    public ViewGroup mTopContainer;
    public TextView mTotalTimeTextView;
    public boolean mTouchingProgressBar;
    public Runnable progressTask;

    public GSYVideoControlView(@NonNull Context context) {
        super(context);
        this.mThreshold = 80;
        this.mShrinkImageRes = -1;
        this.mEnlargeImageRes = -1;
        this.mDismissControlTime = 2500;
        this.mBrightnessData = -1.0f;
        this.mSeekRatio = 1.0f;
        this.mTouchingProgressBar = false;
        this.mChangeVolume = false;
        this.mChangePosition = false;
        this.mShowVKey = false;
        this.mBrightness = false;
        this.mFirstTouch = false;
        this.mHideKey = true;
        this.mNeedShowWifiTip = true;
        this.mIsTouchWiget = true;
        this.mIsTouchWigetFull = true;
        this.mSetUpLazy = false;
        this.mHadSeekTouch = false;
        this.mPostProgress = false;
        this.mPostDismiss = false;
        this.isShowDragProgressTextOnSeekBar = false;
        this.gestureDetector = new GestureDetector(getContext().getApplicationContext(), new GestureDetector.SimpleOnGestureListener() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView.2
            @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnDoubleTapListener
            public boolean onDoubleTap(MotionEvent motionEvent) {
                GSYVideoControlView.this.touchDoubleUp();
                return super.onDoubleTap(motionEvent);
            }

            @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnDoubleTapListener
            public boolean onSingleTapConfirmed(MotionEvent motionEvent) {
                GSYVideoControlView gSYVideoControlView = GSYVideoControlView.this;
                if (!gSYVideoControlView.mChangePosition && !gSYVideoControlView.mChangeVolume && !gSYVideoControlView.mBrightness) {
                    gSYVideoControlView.onClickUiToggle();
                }
                return super.onSingleTapConfirmed(motionEvent);
            }
        });
        this.progressTask = new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView.4
            @Override // java.lang.Runnable
            public void run() {
                GSYVideoControlView gSYVideoControlView = GSYVideoControlView.this;
                int i2 = gSYVideoControlView.mCurrentState;
                if (i2 == 2 || i2 == 5) {
                    gSYVideoControlView.setTextAndProgress(0);
                }
                GSYVideoControlView gSYVideoControlView2 = GSYVideoControlView.this;
                if (gSYVideoControlView2.mPostProgress) {
                    gSYVideoControlView2.postDelayed(this, 1000L);
                }
            }
        };
        this.dismissControlTask = new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView.5
            @Override // java.lang.Runnable
            public void run() {
                GSYVideoControlView gSYVideoControlView = GSYVideoControlView.this;
                int i2 = gSYVideoControlView.mCurrentState;
                if (i2 == 0 || i2 == 7 || i2 == 6) {
                    return;
                }
                if (gSYVideoControlView.getActivityContext() != null) {
                    GSYVideoControlView.this.hideAllWidget();
                    GSYVideoControlView gSYVideoControlView2 = GSYVideoControlView.this;
                    gSYVideoControlView2.setViewShowState(gSYVideoControlView2.mLockScreen, 8);
                    GSYVideoControlView gSYVideoControlView3 = GSYVideoControlView.this;
                    if (gSYVideoControlView3.mHideKey && gSYVideoControlView3.mIfCurrentIsFullscreen && gSYVideoControlView3.mShowVKey) {
                        CommonUtil.hideNavKey(gSYVideoControlView3.mContext);
                    }
                }
                GSYVideoControlView gSYVideoControlView4 = GSYVideoControlView.this;
                if (gSYVideoControlView4.mPostDismiss) {
                    gSYVideoControlView4.postDelayed(this, gSYVideoControlView4.mDismissControlTime);
                }
            }
        };
    }

    public void cancelDismissControlViewTimer() {
        this.mPostDismiss = false;
        removeCallbacks(this.dismissControlTask);
    }

    public void cancelProgressTimer() {
        this.mPostProgress = false;
        removeCallbacks(this.progressTask);
    }

    public abstract void changeUiToCompleteShow();

    public abstract void changeUiToError();

    public abstract void changeUiToNormal();

    public abstract void changeUiToPauseShow();

    public abstract void changeUiToPlayingBufferingShow();

    public abstract void changeUiToPlayingShow();

    public abstract void changeUiToPreparingShow();

    public void clearThumbImageView() {
        RelativeLayout relativeLayout = this.mThumbImageViewLayout;
        if (relativeLayout != null) {
            relativeLayout.removeAllViews();
        }
    }

    public void clickStartIcon() {
        if (TextUtils.isEmpty(this.mUrl)) {
            StringBuilder m586H = C1499a.m586H("********");
            m586H.append(getResources().getString(R$string.no_url));
            Debuger.printfError(m586H.toString());
            return;
        }
        int i2 = this.mCurrentState;
        if (i2 == 0 || i2 == 7) {
            if (isShowNetConfirm()) {
                showWifiDialog();
                return;
            } else {
                startButtonLogic();
                return;
            }
        }
        if (i2 == 2) {
            try {
                onVideoPause();
            } catch (Exception e2) {
                e2.printStackTrace();
            }
            setStateAndUi(5);
            if (this.mVideoAllCallBack == null || !isCurrentMediaListener()) {
                return;
            }
            if (this.mIfCurrentIsFullscreen) {
                Debuger.printfLog("onClickStopFullscreen");
                this.mVideoAllCallBack.onClickStopFullscreen(this.mOriginUrl, this.mTitle, this);
                return;
            } else {
                Debuger.printfLog("onClickStop");
                this.mVideoAllCallBack.onClickStop(this.mOriginUrl, this.mTitle, this);
                return;
            }
        }
        if (i2 != 5) {
            if (i2 == 6) {
                startButtonLogic();
                return;
            }
            return;
        }
        if (this.mVideoAllCallBack != null && isCurrentMediaListener()) {
            if (this.mIfCurrentIsFullscreen) {
                Debuger.printfLog("onClickResumeFullscreen");
                this.mVideoAllCallBack.onClickResumeFullscreen(this.mOriginUrl, this.mTitle, this);
            } else {
                Debuger.printfLog("onClickResume");
                this.mVideoAllCallBack.onClickResume(this.mOriginUrl, this.mTitle, this);
            }
        }
        if (!this.mHadPlay && !this.mStartAfterPrepared) {
            startAfterPrepared();
        }
        try {
            getGSYVideoManager().start();
        } catch (Exception e3) {
            e3.printStackTrace();
        }
        setStateAndUi(2);
    }

    public abstract void dismissBrightnessDialog();

    public abstract void dismissProgressDialog();

    public abstract void dismissVolumeDialog();

    public ImageView getBackButton() {
        return this.mBackButton;
    }

    public int getDismissControlTime() {
        return this.mDismissControlTime;
    }

    public int getEnlargeImageRes() {
        int i2 = this.mEnlargeImageRes;
        return i2 == -1 ? R$drawable.video_enlarge : i2;
    }

    public ImageView getFullscreenButton() {
        return this.mFullscreenButton;
    }

    public float getSeekRatio() {
        return this.mSeekRatio;
    }

    public int getShrinkImageRes() {
        int i2 = this.mShrinkImageRes;
        return i2 == -1 ? R$drawable.video_shrink : i2;
    }

    public View getStartButton() {
        return this.mStartButton;
    }

    public View getThumbImageView() {
        return this.mThumbImageView;
    }

    public RelativeLayout getThumbImageViewLayout() {
        return this.mThumbImageViewLayout;
    }

    public TextView getTitleTextView() {
        return this.mTitleTextView;
    }

    public abstract void hideAllWidget();

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public void init(Context context) {
        RelativeLayout relativeLayout;
        super.init(context);
        this.mStartButton = findViewById(R$id.start);
        this.mTitleTextView = (TextView) findViewById(R$id.title);
        this.mBackButton = (ImageView) findViewById(R$id.back);
        this.mFullscreenButton = (ImageView) findViewById(R$id.fullscreen);
        this.mProgressBar = (SeekBar) findViewById(R$id.progress);
        this.mCurrentTimeTextView = (TextView) findViewById(R$id.current);
        this.mTotalTimeTextView = (TextView) findViewById(R$id.total);
        this.mBottomContainer = (ViewGroup) findViewById(R$id.layout_bottom);
        this.mTopContainer = (ViewGroup) findViewById(R$id.layout_top);
        this.mBottomProgressBar = (ProgressBar) findViewById(R$id.bottom_progressbar);
        this.mThumbImageViewLayout = (RelativeLayout) findViewById(R$id.thumb);
        this.mLockScreen = (ImageView) findViewById(R$id.lock_screen);
        this.mLoadingProgressBar = findViewById(R$id.loading);
        if (isInEditMode()) {
            return;
        }
        View view = this.mStartButton;
        if (view != null) {
            view.setOnClickListener(this);
        }
        ImageView imageView = this.mFullscreenButton;
        if (imageView != null) {
            imageView.setOnClickListener(this);
            this.mFullscreenButton.setOnTouchListener(this);
        }
        SeekBar seekBar = this.mProgressBar;
        if (seekBar != null) {
            seekBar.setOnSeekBarChangeListener(this);
        }
        ViewGroup viewGroup = this.mBottomContainer;
        if (viewGroup != null) {
            viewGroup.setOnClickListener(this);
        }
        ViewGroup viewGroup2 = this.mTextureViewContainer;
        if (viewGroup2 != null) {
            viewGroup2.setOnClickListener(this);
            this.mTextureViewContainer.setOnTouchListener(this);
        }
        SeekBar seekBar2 = this.mProgressBar;
        if (seekBar2 != null) {
            seekBar2.setOnTouchListener(this);
        }
        RelativeLayout relativeLayout2 = this.mThumbImageViewLayout;
        if (relativeLayout2 != null) {
            relativeLayout2.setVisibility(8);
            this.mThumbImageViewLayout.setOnClickListener(this);
        }
        if (this.mThumbImageView != null && !this.mIfCurrentIsFullscreen && (relativeLayout = this.mThumbImageViewLayout) != null) {
            relativeLayout.removeAllViews();
            resolveThumbImage(this.mThumbImageView);
        }
        ImageView imageView2 = this.mBackButton;
        if (imageView2 != null) {
            imageView2.setOnClickListener(this);
        }
        ImageView imageView3 = this.mLockScreen;
        if (imageView3 != null) {
            imageView3.setVisibility(8);
            this.mLockScreen.setOnClickListener(new View.OnClickListener() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView.1
                @Override // android.view.View.OnClickListener
                public void onClick(View view2) {
                    GSYVideoControlView gSYVideoControlView = GSYVideoControlView.this;
                    int i2 = gSYVideoControlView.mCurrentState;
                    if (i2 == 6 || i2 == 7) {
                        return;
                    }
                    gSYVideoControlView.lockTouchLogic();
                    GSYVideoControlView gSYVideoControlView2 = GSYVideoControlView.this;
                    InterfaceC2930f interfaceC2930f = gSYVideoControlView2.mLockClickListener;
                    if (interfaceC2930f != null) {
                        interfaceC2930f.m3402a(view2, gSYVideoControlView2.mLockCurScreen);
                    }
                }
            });
        }
        if (getActivityContext() != null) {
            this.mSeekEndOffset = CommonUtil.dip2px(getActivityContext(), 50.0f);
        }
    }

    public void initUIState() {
        setStateAndUi(0);
    }

    public boolean isHideKey() {
        return this.mHideKey;
    }

    public boolean isNeedLockFull() {
        return this.mNeedLockFull;
    }

    public boolean isNeedShowWifiTip() {
        return this.mNeedShowWifiTip;
    }

    public boolean isShowDragProgressTextOnSeekBar() {
        return this.isShowDragProgressTextOnSeekBar;
    }

    public boolean isShowNetConfirm() {
        return (this.mOriginUrl.startsWith("file") || this.mOriginUrl.startsWith("android.resource") || CommonUtil.isWifiConnected(getContext()) || !this.mNeedShowWifiTip || getGSYVideoManager().cachePreview(this.mContext.getApplicationContext(), this.mCachePath, this.mOriginUrl)) ? false : true;
    }

    public boolean isTouchWiget() {
        return this.mIsTouchWiget;
    }

    public boolean isTouchWigetFull() {
        return this.mIsTouchWigetFull;
    }

    public void lockTouchLogic() {
        if (this.mLockCurScreen) {
            this.mLockScreen.setImageResource(R$drawable.unlock);
            this.mLockCurScreen = false;
        } else {
            this.mLockScreen.setImageResource(R$drawable.lock);
            this.mLockCurScreen = true;
            hideAllWidget();
        }
    }

    public void loopSetProgressAndTime() {
        SeekBar seekBar = this.mProgressBar;
        if (seekBar == null || this.mTotalTimeTextView == null || this.mCurrentTimeTextView == null) {
            return;
        }
        seekBar.setProgress(0);
        this.mProgressBar.setSecondaryProgress(0);
        this.mCurrentTimeTextView.setText(CommonUtil.stringForTime(0));
        ProgressBar progressBar = this.mBottomProgressBar;
        if (progressBar != null) {
            progressBar.setProgress(0);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView, p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onAutoCompletion() {
        super.onAutoCompletion();
        if (this.mLockCurScreen) {
            lockTouchLogic();
            this.mLockScreen.setVisibility(8);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView, p005b.p362y.p363a.p366f.InterfaceC2925a
    public abstract /* synthetic */ void onBackFullscreen();

    public void onBrightnessSlide(float f2) {
        float f3 = ((Activity) this.mContext).getWindow().getAttributes().screenBrightness;
        this.mBrightnessData = f3;
        if (f3 <= 0.0f) {
            this.mBrightnessData = 0.5f;
        } else if (f3 < 0.01f) {
            this.mBrightnessData = 0.01f;
        }
        WindowManager.LayoutParams attributes = ((Activity) this.mContext).getWindow().getAttributes();
        float f4 = this.mBrightnessData + f2;
        attributes.screenBrightness = f4;
        if (f4 > 1.0f) {
            attributes.screenBrightness = 1.0f;
        } else if (f4 < 0.01f) {
            attributes.screenBrightness = 0.01f;
        }
        showBrightnessDialog(attributes.screenBrightness);
        ((Activity) this.mContext).getWindow().setAttributes(attributes);
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView, p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onBufferingUpdate(final int i2) {
        post(new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView.3
            @Override // java.lang.Runnable
            public void run() {
                GSYVideoControlView gSYVideoControlView = GSYVideoControlView.this;
                int i3 = gSYVideoControlView.mCurrentState;
                if (i3 == 0 || i3 == 1) {
                    return;
                }
                int i4 = i2;
                if (i4 != 0) {
                    gSYVideoControlView.setTextAndProgress(i4);
                    GSYVideoControlView.this.mBufferPoint = i2;
                    StringBuilder m586H = C1499a.m586H("Net speed: ");
                    m586H.append(GSYVideoControlView.this.getNetSpeedText());
                    m586H.append(" percent ");
                    m586H.append(i2);
                    Debuger.printfLog(m586H.toString());
                }
                GSYVideoControlView gSYVideoControlView2 = GSYVideoControlView.this;
                SeekBar seekBar = gSYVideoControlView2.mProgressBar;
                if (seekBar != null && gSYVideoControlView2.mLooping && gSYVideoControlView2.mHadPlay && i2 == 0 && seekBar.getProgress() >= GSYVideoControlView.this.mProgressBar.getMax() - 1) {
                    GSYVideoControlView.this.loopSetProgressAndTime();
                }
            }
        });
    }

    public void onClick(View view) {
        int id = view.getId();
        if (this.mHideKey && this.mIfCurrentIsFullscreen) {
            CommonUtil.hideNavKey(this.mContext);
        }
        if (id == R$id.start) {
            clickStartIcon();
            return;
        }
        int i2 = R$id.surface_container;
        if (id == i2 && this.mCurrentState == 7) {
            if (this.mVideoAllCallBack != null) {
                Debuger.printfLog("onClickStartError");
                this.mVideoAllCallBack.onClickStartError(this.mOriginUrl, this.mTitle, this);
            }
            prepareVideo();
            return;
        }
        if (id != R$id.thumb) {
            if (id == i2) {
                if (this.mVideoAllCallBack != null && isCurrentMediaListener()) {
                    if (this.mIfCurrentIsFullscreen) {
                        Debuger.printfLog("onClickBlankFullscreen");
                        this.mVideoAllCallBack.onClickBlankFullscreen(this.mOriginUrl, this.mTitle, this);
                    } else {
                        Debuger.printfLog("onClickBlank");
                        this.mVideoAllCallBack.onClickBlank(this.mOriginUrl, this.mTitle, this);
                    }
                }
                startDismissControlViewTimer();
                return;
            }
            return;
        }
        if (this.mThumbPlay) {
            if (TextUtils.isEmpty(this.mUrl)) {
                StringBuilder m586H = C1499a.m586H("********");
                m586H.append(getResources().getString(R$string.no_url));
                Debuger.printfError(m586H.toString());
                return;
            }
            int i3 = this.mCurrentState;
            if (i3 != 0) {
                if (i3 == 6) {
                    onClickUiToggle();
                }
            } else if (isShowNetConfirm()) {
                showWifiDialog();
            } else {
                startPlayLogic();
            }
        }
    }

    public abstract void onClickUiToggle();

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        Debuger.printfLog(hashCode() + "------------------------------ dismiss onDetachedFromWindow");
        cancelProgressTimer();
        cancelDismissControlViewTimer();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView, p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onError(int i2, int i3) {
        super.onError(i2, i3);
        if (this.mLockCurScreen) {
            lockTouchLogic();
            this.mLockScreen.setVisibility(8);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView, p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onPrepared() {
        setTextAndProgress(0, true);
        super.onPrepared();
        if (this.mCurrentState != 1) {
            return;
        }
        startProgressTimer();
        Debuger.printfLog(hashCode() + "------------------------------ surface_container onPrepared");
    }

    @Override // android.widget.SeekBar.OnSeekBarChangeListener
    public void onProgressChanged(SeekBar seekBar, int i2, boolean z) {
        showDragProgressTextOnSeekBar(z, i2);
    }

    @Override // android.widget.SeekBar.OnSeekBarChangeListener
    public void onStartTrackingTouch(SeekBar seekBar) {
        this.mHadSeekTouch = true;
    }

    @Override // android.widget.SeekBar.OnSeekBarChangeListener
    public void onStopTrackingTouch(SeekBar seekBar) {
        if (this.mVideoAllCallBack != null && isCurrentMediaListener()) {
            if (isIfCurrentIsFullscreen()) {
                Debuger.printfLog("onClickSeekbarFullscreen");
                this.mVideoAllCallBack.onClickSeekbarFullscreen(this.mOriginUrl, this.mTitle, this);
            } else {
                Debuger.printfLog("onClickSeekbar");
                this.mVideoAllCallBack.onClickSeekbar(this.mOriginUrl, this.mTitle, this);
            }
        }
        if (getGSYVideoManager() != null && this.mHadPlay) {
            try {
                getGSYVideoManager().seekTo((seekBar.getProgress() * getDuration()) / 100);
            } catch (Exception e2) {
                Debuger.printfWarning(e2.toString());
            }
        }
        this.mHadSeekTouch = false;
    }

    /* JADX WARN: Code restructure failed: missing block: B:47:0x00a5, code lost:
    
        if (r8 != 2) goto L57;
     */
    @Override // android.view.View.OnTouchListener
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouch(android.view.View r8, android.view.MotionEvent r9) {
        /*
            r7 = this;
            int r8 = r8.getId()
            float r0 = r9.getX()
            float r1 = r9.getY()
            boolean r2 = r7.mIfCurrentIsFullscreen
            r3 = 1
            if (r2 == 0) goto L20
            boolean r2 = r7.mLockCurScreen
            if (r2 == 0) goto L20
            boolean r2 = r7.mNeedLockFull
            if (r2 == 0) goto L20
            r7.onClickUiToggle()
            r7.startDismissControlViewTimer()
            return r3
        L20:
            int r2 = com.shuyu.gsyvideoplayer.R$id.fullscreen
            r4 = 0
            if (r8 != r2) goto L26
            return r4
        L26:
            int r2 = com.shuyu.gsyvideoplayer.R$id.surface_container
            r5 = 2
            if (r8 != r2) goto L99
            int r8 = r9.getAction()
            if (r8 == 0) goto L90
            if (r8 == r3) goto L66
            if (r8 == r5) goto L36
            goto L93
        L36:
            float r8 = r7.mDownX
            float r0 = r0 - r8
            float r8 = r7.mDownY
            float r8 = r1 - r8
            float r2 = java.lang.Math.abs(r0)
            float r3 = java.lang.Math.abs(r8)
            boolean r5 = r7.mIfCurrentIsFullscreen
            if (r5 == 0) goto L4d
            boolean r6 = r7.mIsTouchWigetFull
            if (r6 != 0) goto L53
        L4d:
            boolean r6 = r7.mIsTouchWiget
            if (r6 == 0) goto L62
            if (r5 != 0) goto L62
        L53:
            boolean r5 = r7.mChangePosition
            if (r5 != 0) goto L62
            boolean r5 = r7.mChangeVolume
            if (r5 != 0) goto L62
            boolean r5 = r7.mBrightness
            if (r5 != 0) goto L62
            r7.touchSurfaceMoveFullLogic(r2, r3)
        L62:
            r7.touchSurfaceMove(r0, r8, r1)
            goto L93
        L66:
            r7.startDismissControlViewTimer()
            r7.touchSurfaceUp()
            java.lang.StringBuilder r8 = new java.lang.StringBuilder
            r8.<init>()
            int r0 = r7.hashCode()
            r8.append(r0)
            java.lang.String r0 = "------------------------------ surface_container ACTION_UP"
            r8.append(r0)
            java.lang.String r8 = r8.toString()
            com.shuyu.gsyvideoplayer.utils.Debuger.printfLog(r8)
            r7.startProgressTimer()
            boolean r8 = r7.mHideKey
            if (r8 == 0) goto L93
            boolean r8 = r7.mShowVKey
            if (r8 == 0) goto L93
            return r3
        L90:
            r7.touchSurfaceDown(r0, r1)
        L93:
            android.view.GestureDetector r8 = r7.gestureDetector
            r8.onTouchEvent(r9)
            goto Led
        L99:
            int r0 = com.shuyu.gsyvideoplayer.R$id.progress
            if (r8 != r0) goto Led
            int r8 = r9.getAction()
            if (r8 == 0) goto Ld9
            if (r8 == r3) goto La8
            if (r8 == r5) goto Ldc
            goto Led
        La8:
            r7.startDismissControlViewTimer()
            java.lang.StringBuilder r8 = new java.lang.StringBuilder
            r8.<init>()
            int r9 = r7.hashCode()
            r8.append(r9)
            java.lang.String r9 = "------------------------------ progress ACTION_UP"
            r8.append(r9)
            java.lang.String r8 = r8.toString()
            com.shuyu.gsyvideoplayer.utils.Debuger.printfLog(r8)
            r7.startProgressTimer()
            android.view.ViewParent r8 = r7.getParent()
        Lca:
            if (r8 == 0) goto Ld4
            r8.requestDisallowInterceptTouchEvent(r4)
            android.view.ViewParent r8 = r8.getParent()
            goto Lca
        Ld4:
            r8 = -1082130432(0xffffffffbf800000, float:-1.0)
            r7.mBrightnessData = r8
            goto Led
        Ld9:
            r7.cancelDismissControlViewTimer()
        Ldc:
            r7.cancelProgressTimer()
            android.view.ViewParent r8 = r7.getParent()
        Le3:
            if (r8 == 0) goto Led
            r8.requestDisallowInterceptTouchEvent(r3)
            android.view.ViewParent r8 = r8.getParent()
            goto Le3
        Led:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView.onTouch(android.view.View, android.view.MotionEvent):boolean");
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public void prepareVideo() {
        if (this.mSetUpLazy) {
            super.setUp(this.mOriginUrl, this.mCache, this.mCachePath, this.mMapHeadData, this.mTitle);
        }
        super.prepareVideo();
    }

    public void resetProgressAndTime() {
        SeekBar seekBar = this.mProgressBar;
        if (seekBar == null || this.mTotalTimeTextView == null || this.mCurrentTimeTextView == null) {
            return;
        }
        seekBar.setProgress(0);
        this.mProgressBar.setSecondaryProgress(0);
        this.mCurrentTimeTextView.setText(CommonUtil.stringForTime(0));
        this.mTotalTimeTextView.setText(CommonUtil.stringForTime(0));
        ProgressBar progressBar = this.mBottomProgressBar;
        if (progressBar != null) {
            progressBar.setProgress(0);
            this.mBottomProgressBar.setSecondaryProgress(0);
        }
    }

    public void resolveThumbImage(View view) {
        RelativeLayout relativeLayout = this.mThumbImageViewLayout;
        if (relativeLayout != null) {
            relativeLayout.removeAllViews();
            this.mThumbImageViewLayout.addView(view);
            ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
            layoutParams.height = -1;
            layoutParams.width = -1;
            view.setLayoutParams(layoutParams);
        }
    }

    public void resolveUIState(int i2) {
        if (i2 == 0) {
            changeUiToNormal();
            cancelDismissControlViewTimer();
            return;
        }
        if (i2 == 1) {
            changeUiToPreparingShow();
            startDismissControlViewTimer();
            return;
        }
        if (i2 == 2) {
            changeUiToPlayingShow();
            startDismissControlViewTimer();
            return;
        }
        if (i2 == 3) {
            changeUiToPlayingBufferingShow();
            return;
        }
        if (i2 == 5) {
            changeUiToPauseShow();
            cancelDismissControlViewTimer();
        } else if (i2 == 6) {
            changeUiToCompleteShow();
            cancelDismissControlViewTimer();
        } else {
            if (i2 != 7) {
                return;
            }
            changeUiToError();
        }
    }

    public void setDismissControlTime(int i2) {
        this.mDismissControlTime = i2;
    }

    public void setEnlargeImageRes(int i2) {
        this.mEnlargeImageRes = i2;
    }

    public void setGSYVideoProgressListener(InterfaceC2927c interfaceC2927c) {
        this.mGSYVideoProgressListener = interfaceC2927c;
    }

    public void setHideKey(boolean z) {
        this.mHideKey = z;
    }

    public void setIsTouchWiget(boolean z) {
        this.mIsTouchWiget = z;
    }

    public void setIsTouchWigetFull(boolean z) {
        this.mIsTouchWigetFull = z;
    }

    public void setLockClickListener(InterfaceC2930f interfaceC2930f) {
        this.mLockClickListener = interfaceC2930f;
    }

    public void setNeedLockFull(boolean z) {
        this.mNeedLockFull = z;
    }

    public void setNeedShowWifiTip(boolean z) {
        this.mNeedShowWifiTip = z;
    }

    public void setProgressAndTime(int i2, int i3, int i4, int i5, boolean z) {
        InterfaceC2927c interfaceC2927c = this.mGSYVideoProgressListener;
        if (interfaceC2927c != null && this.mCurrentState == 2) {
            interfaceC2927c.mo301a(i2, i3, i4, i5);
        }
        SeekBar seekBar = this.mProgressBar;
        if (seekBar == null || this.mTotalTimeTextView == null || this.mCurrentTimeTextView == null || this.mHadSeekTouch) {
            return;
        }
        if (!this.mTouchingProgressBar && (i2 != 0 || z)) {
            seekBar.setProgress(i2);
        }
        if (getGSYVideoManager().getBufferedPercentage() > 0) {
            i3 = getGSYVideoManager().getBufferedPercentage();
        }
        if (i3 > 94) {
            i3 = 100;
        }
        setSecondaryProgress(i3);
        this.mTotalTimeTextView.setText(CommonUtil.stringForTime(i5));
        if (i4 > 0) {
            this.mCurrentTimeTextView.setText(CommonUtil.stringForTime(i4));
        }
        ProgressBar progressBar = this.mBottomProgressBar;
        if (progressBar != null) {
            if (i2 != 0 || z) {
                progressBar.setProgress(i2);
            }
            setSecondaryProgress(i3);
        }
    }

    public void setSecondaryProgress(int i2) {
        if (this.mProgressBar != null && i2 != 0 && !getGSYVideoManager().isCacheFile()) {
            this.mProgressBar.setSecondaryProgress(i2);
        }
        if (this.mBottomProgressBar == null || i2 == 0 || getGSYVideoManager().isCacheFile()) {
            return;
        }
        this.mBottomProgressBar.setSecondaryProgress(i2);
    }

    public void setSeekRatio(float f2) {
        if (f2 < 0.0f) {
            return;
        }
        this.mSeekRatio = f2;
    }

    public void setShowDragProgressTextOnSeekBar(boolean z) {
        this.isShowDragProgressTextOnSeekBar = z;
    }

    public void setShrinkImageRes(int i2) {
        this.mShrinkImageRes = i2;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYTextureRenderView
    public void setSmallVideoTextureView(View.OnTouchListener onTouchListener) {
        super.setSmallVideoTextureView(onTouchListener);
        RelativeLayout relativeLayout = this.mThumbImageViewLayout;
        if (relativeLayout != null) {
            relativeLayout.setOnTouchListener(onTouchListener);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public void setStateAndUi(int i2) {
        TextView textView;
        this.mCurrentState = i2;
        if ((i2 == 0 && isCurrentMediaListener()) || i2 == 6 || i2 == 7) {
            this.mHadPrepared = false;
        }
        int i3 = this.mCurrentState;
        if (i3 == 0) {
            if (isCurrentMediaListener()) {
                Debuger.printfLog(hashCode() + "------------------------------ dismiss CURRENT_STATE_NORMAL");
                cancelProgressTimer();
                getGSYVideoManager().releaseMediaPlayer();
                releasePauseCover();
                this.mBufferPoint = 0;
                this.mSaveChangeViewTIme = 0L;
                AudioManager audioManager = this.mAudioManager;
                if (audioManager != null) {
                    audioManager.abandonAudioFocus(this.onAudioFocusChangeListener);
                }
            }
            releaseNetWorkState();
        } else if (i3 == 1) {
            resetProgressAndTime();
        } else if (i3 != 2) {
            if (i3 == 5) {
                Debuger.printfLog(hashCode() + "------------------------------ CURRENT_STATE_PAUSE");
                startProgressTimer();
            } else if (i3 == 6) {
                Debuger.printfLog(hashCode() + "------------------------------ dismiss CURRENT_STATE_AUTO_COMPLETE");
                cancelProgressTimer();
                SeekBar seekBar = this.mProgressBar;
                if (seekBar != null) {
                    seekBar.setProgress(100);
                }
                TextView textView2 = this.mCurrentTimeTextView;
                if (textView2 != null && (textView = this.mTotalTimeTextView) != null) {
                    textView2.setText(textView.getText());
                }
                ProgressBar progressBar = this.mBottomProgressBar;
                if (progressBar != null) {
                    progressBar.setProgress(100);
                }
            } else if (i3 == 7 && isCurrentMediaListener()) {
                getGSYVideoManager().releaseMediaPlayer();
            }
        } else if (isCurrentMediaListener()) {
            Debuger.printfLog(hashCode() + "------------------------------ CURRENT_STATE_PLAYING");
            startProgressTimer();
        }
        resolveUIState(i2);
    }

    public void setTextAndProgress(int i2) {
        setTextAndProgress(i2, false);
    }

    public void setThumbImageView(View view) {
        if (this.mThumbImageViewLayout != null) {
            this.mThumbImageView = view;
            resolveThumbImage(view);
        }
    }

    public void setThumbPlay(boolean z) {
        this.mThumbPlay = z;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public boolean setUp(String str, boolean z, String str2) {
        return setUp(str, z, null, str2);
    }

    public boolean setUpLazy(String str, boolean z, File file, Map<String, String> map, String str2) {
        this.mOriginUrl = str;
        this.mCache = z;
        this.mCachePath = file;
        this.mSetUpLazy = true;
        this.mTitle = str2;
        this.mMapHeadData = map;
        if (isCurrentMediaListener() && System.currentTimeMillis() - this.mSaveChangeViewTIme < 2000) {
            return false;
        }
        this.mUrl = "waiting";
        this.mCurrentState = 0;
        return true;
    }

    public void setViewShowState(View view, int i2) {
        if (view != null) {
            view.setVisibility(i2);
        }
    }

    public abstract void showBrightnessDialog(float f2);

    public void showDragProgressTextOnSeekBar(boolean z, int i2) {
        if (z && this.isShowDragProgressTextOnSeekBar) {
            int duration = getDuration();
            TextView textView = this.mCurrentTimeTextView;
            if (textView != null) {
                textView.setText(CommonUtil.stringForTime((i2 * duration) / 100));
            }
        }
    }

    public abstract void showProgressDialog(float f2, String str, int i2, String str2, int i3);

    public abstract void showVolumeDialog(float f2, int i2);

    public abstract void showWifiDialog();

    public void startDismissControlViewTimer() {
        cancelDismissControlViewTimer();
        this.mPostDismiss = true;
        postDelayed(this.dismissControlTask, this.mDismissControlTime);
    }

    public void startProgressTimer() {
        cancelProgressTimer();
        this.mPostProgress = true;
        postDelayed(this.progressTask, 300L);
    }

    public void touchDoubleUp() {
        if (this.mHadPlay) {
            clickStartIcon();
        }
    }

    public void touchSurfaceDown(float f2, float f3) {
        this.mTouchingProgressBar = true;
        this.mDownX = f2;
        this.mDownY = f3;
        this.mMoveY = 0.0f;
        this.mChangeVolume = false;
        this.mChangePosition = false;
        this.mShowVKey = false;
        this.mBrightness = false;
        this.mFirstTouch = true;
    }

    public void touchSurfaceMove(float f2, float f3, float f4) {
        int i2;
        int i3;
        if (getActivityContext() != null) {
            i2 = CommonUtil.getCurrentScreenLand((Activity) getActivityContext()) ? this.mScreenHeight : this.mScreenWidth;
            i3 = CommonUtil.getCurrentScreenLand((Activity) getActivityContext()) ? this.mScreenWidth : this.mScreenHeight;
        } else {
            i2 = 0;
            i3 = 0;
        }
        if (this.mChangePosition) {
            int duration = getDuration();
            int i4 = (int) ((((duration * f2) / i2) / this.mSeekRatio) + this.mDownPosition);
            this.mSeekTimePosition = i4;
            if (i4 > duration) {
                this.mSeekTimePosition = duration;
            }
            showProgressDialog(f2, CommonUtil.stringForTime(this.mSeekTimePosition), this.mSeekTimePosition, CommonUtil.stringForTime(duration), duration);
            return;
        }
        if (!this.mChangeVolume) {
            if (!this.mBrightness || Math.abs(f3) <= this.mThreshold) {
                return;
            }
            onBrightnessSlide((-f3) / i3);
            this.mDownY = f4;
            return;
        }
        float f5 = -f3;
        float f6 = i3;
        this.mAudioManager.setStreamVolume(3, this.mGestureDownVolume + ((int) (((this.mAudioManager.getStreamMaxVolume(3) * f5) * 3.0f) / f6)), 0);
        showVolumeDialog(-f5, (int) ((((3.0f * f5) * 100.0f) / f6) + ((this.mGestureDownVolume * 100) / r12)));
    }

    public void touchSurfaceMoveFullLogic(float f2, float f3) {
        int i2 = getActivityContext() != null ? CommonUtil.getCurrentScreenLand((Activity) getActivityContext()) ? this.mScreenHeight : this.mScreenWidth : 0;
        int i3 = this.mThreshold;
        if (f2 > i3 || f3 > i3) {
            cancelProgressTimer();
            if (f2 >= this.mThreshold) {
                if (Math.abs(CommonUtil.getScreenWidth(getContext()) - this.mDownX) <= this.mSeekEndOffset) {
                    this.mShowVKey = true;
                    return;
                } else {
                    this.mChangePosition = true;
                    this.mDownPosition = getCurrentPositionWhenPlaying();
                    return;
                }
            }
            boolean z = Math.abs(((float) CommonUtil.getScreenHeight(getContext())) - this.mDownY) > ((float) this.mSeekEndOffset);
            if (this.mFirstTouch) {
                this.mBrightness = this.mDownX < ((float) i2) * 0.5f && z;
                this.mFirstTouch = false;
            }
            if (!this.mBrightness) {
                this.mChangeVolume = z;
                this.mGestureDownVolume = this.mAudioManager.getStreamVolume(3);
            }
            this.mShowVKey = !z;
        }
    }

    public void touchSurfaceUp() {
        int i2;
        if (this.mChangePosition) {
            int duration = getDuration();
            int i3 = this.mSeekTimePosition * 100;
            if (duration == 0) {
                duration = 1;
            }
            int i4 = i3 / duration;
            ProgressBar progressBar = this.mBottomProgressBar;
            if (progressBar != null) {
                progressBar.setProgress(i4);
            }
        }
        this.mTouchingProgressBar = false;
        dismissProgressDialog();
        dismissVolumeDialog();
        dismissBrightnessDialog();
        if (!this.mChangePosition || getGSYVideoManager() == null || ((i2 = this.mCurrentState) != 2 && i2 != 5)) {
            if (this.mBrightness) {
                if (this.mVideoAllCallBack == null || !isCurrentMediaListener()) {
                    return;
                }
                Debuger.printfLog("onTouchScreenSeekLight");
                this.mVideoAllCallBack.onTouchScreenSeekLight(this.mOriginUrl, this.mTitle, this);
                return;
            }
            if (this.mChangeVolume && this.mVideoAllCallBack != null && isCurrentMediaListener()) {
                Debuger.printfLog("onTouchScreenSeekVolume");
                this.mVideoAllCallBack.onTouchScreenSeekVolume(this.mOriginUrl, this.mTitle, this);
                return;
            }
            return;
        }
        try {
            getGSYVideoManager().seekTo(this.mSeekTimePosition);
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        int duration2 = getDuration();
        int i5 = this.mSeekTimePosition * 100;
        if (duration2 == 0) {
            duration2 = 1;
        }
        int i6 = i5 / duration2;
        SeekBar seekBar = this.mProgressBar;
        if (seekBar != null) {
            seekBar.setProgress(i6);
        }
        if (this.mVideoAllCallBack == null || !isCurrentMediaListener()) {
            return;
        }
        Debuger.printfLog("onTouchScreenSeekPosition");
        this.mVideoAllCallBack.onTouchScreenSeekPosition(this.mOriginUrl, this.mTitle, this);
    }

    public void setTextAndProgress(int i2, boolean z) {
        int currentPositionWhenPlaying = getCurrentPositionWhenPlaying();
        int duration = getDuration();
        setProgressAndTime((currentPositionWhenPlaying * 100) / (duration == 0 ? 1 : duration), i2, currentPositionWhenPlaying, duration, z);
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public boolean setUp(String str, boolean z, File file, String str2) {
        TextView textView;
        if (!super.setUp(str, z, file, str2)) {
            return false;
        }
        if (str2 != null && (textView = this.mTitleTextView) != null) {
            textView.setText(str2);
        }
        if (this.mIfCurrentIsFullscreen) {
            ImageView imageView = this.mFullscreenButton;
            if (imageView == null) {
                return true;
            }
            imageView.setImageResource(getShrinkImageRes());
            return true;
        }
        ImageView imageView2 = this.mFullscreenButton;
        if (imageView2 == null) {
            return true;
        }
        imageView2.setImageResource(getEnlargeImageRes());
        return true;
    }

    public GSYVideoControlView(@NonNull Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        this.mThreshold = 80;
        this.mShrinkImageRes = -1;
        this.mEnlargeImageRes = -1;
        this.mDismissControlTime = 2500;
        this.mBrightnessData = -1.0f;
        this.mSeekRatio = 1.0f;
        this.mTouchingProgressBar = false;
        this.mChangeVolume = false;
        this.mChangePosition = false;
        this.mShowVKey = false;
        this.mBrightness = false;
        this.mFirstTouch = false;
        this.mHideKey = true;
        this.mNeedShowWifiTip = true;
        this.mIsTouchWiget = true;
        this.mIsTouchWigetFull = true;
        this.mSetUpLazy = false;
        this.mHadSeekTouch = false;
        this.mPostProgress = false;
        this.mPostDismiss = false;
        this.isShowDragProgressTextOnSeekBar = false;
        this.gestureDetector = new GestureDetector(getContext().getApplicationContext(), new GestureDetector.SimpleOnGestureListener() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView.2
            @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnDoubleTapListener
            public boolean onDoubleTap(MotionEvent motionEvent) {
                GSYVideoControlView.this.touchDoubleUp();
                return super.onDoubleTap(motionEvent);
            }

            @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnDoubleTapListener
            public boolean onSingleTapConfirmed(MotionEvent motionEvent) {
                GSYVideoControlView gSYVideoControlView = GSYVideoControlView.this;
                if (!gSYVideoControlView.mChangePosition && !gSYVideoControlView.mChangeVolume && !gSYVideoControlView.mBrightness) {
                    gSYVideoControlView.onClickUiToggle();
                }
                return super.onSingleTapConfirmed(motionEvent);
            }
        });
        this.progressTask = new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView.4
            @Override // java.lang.Runnable
            public void run() {
                GSYVideoControlView gSYVideoControlView = GSYVideoControlView.this;
                int i2 = gSYVideoControlView.mCurrentState;
                if (i2 == 2 || i2 == 5) {
                    gSYVideoControlView.setTextAndProgress(0);
                }
                GSYVideoControlView gSYVideoControlView2 = GSYVideoControlView.this;
                if (gSYVideoControlView2.mPostProgress) {
                    gSYVideoControlView2.postDelayed(this, 1000L);
                }
            }
        };
        this.dismissControlTask = new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView.5
            @Override // java.lang.Runnable
            public void run() {
                GSYVideoControlView gSYVideoControlView = GSYVideoControlView.this;
                int i2 = gSYVideoControlView.mCurrentState;
                if (i2 == 0 || i2 == 7 || i2 == 6) {
                    return;
                }
                if (gSYVideoControlView.getActivityContext() != null) {
                    GSYVideoControlView.this.hideAllWidget();
                    GSYVideoControlView gSYVideoControlView2 = GSYVideoControlView.this;
                    gSYVideoControlView2.setViewShowState(gSYVideoControlView2.mLockScreen, 8);
                    GSYVideoControlView gSYVideoControlView3 = GSYVideoControlView.this;
                    if (gSYVideoControlView3.mHideKey && gSYVideoControlView3.mIfCurrentIsFullscreen && gSYVideoControlView3.mShowVKey) {
                        CommonUtil.hideNavKey(gSYVideoControlView3.mContext);
                    }
                }
                GSYVideoControlView gSYVideoControlView4 = GSYVideoControlView.this;
                if (gSYVideoControlView4.mPostDismiss) {
                    gSYVideoControlView4.postDelayed(this, gSYVideoControlView4.mDismissControlTime);
                }
            }
        };
    }

    public GSYVideoControlView(@NonNull Context context, @Nullable AttributeSet attributeSet, @AttrRes int i2) {
        super(context, attributeSet, i2);
        this.mThreshold = 80;
        this.mShrinkImageRes = -1;
        this.mEnlargeImageRes = -1;
        this.mDismissControlTime = 2500;
        this.mBrightnessData = -1.0f;
        this.mSeekRatio = 1.0f;
        this.mTouchingProgressBar = false;
        this.mChangeVolume = false;
        this.mChangePosition = false;
        this.mShowVKey = false;
        this.mBrightness = false;
        this.mFirstTouch = false;
        this.mHideKey = true;
        this.mNeedShowWifiTip = true;
        this.mIsTouchWiget = true;
        this.mIsTouchWigetFull = true;
        this.mSetUpLazy = false;
        this.mHadSeekTouch = false;
        this.mPostProgress = false;
        this.mPostDismiss = false;
        this.isShowDragProgressTextOnSeekBar = false;
        this.gestureDetector = new GestureDetector(getContext().getApplicationContext(), new GestureDetector.SimpleOnGestureListener() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView.2
            @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnDoubleTapListener
            public boolean onDoubleTap(MotionEvent motionEvent) {
                GSYVideoControlView.this.touchDoubleUp();
                return super.onDoubleTap(motionEvent);
            }

            @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnDoubleTapListener
            public boolean onSingleTapConfirmed(MotionEvent motionEvent) {
                GSYVideoControlView gSYVideoControlView = GSYVideoControlView.this;
                if (!gSYVideoControlView.mChangePosition && !gSYVideoControlView.mChangeVolume && !gSYVideoControlView.mBrightness) {
                    gSYVideoControlView.onClickUiToggle();
                }
                return super.onSingleTapConfirmed(motionEvent);
            }
        });
        this.progressTask = new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView.4
            @Override // java.lang.Runnable
            public void run() {
                GSYVideoControlView gSYVideoControlView = GSYVideoControlView.this;
                int i22 = gSYVideoControlView.mCurrentState;
                if (i22 == 2 || i22 == 5) {
                    gSYVideoControlView.setTextAndProgress(0);
                }
                GSYVideoControlView gSYVideoControlView2 = GSYVideoControlView.this;
                if (gSYVideoControlView2.mPostProgress) {
                    gSYVideoControlView2.postDelayed(this, 1000L);
                }
            }
        };
        this.dismissControlTask = new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView.5
            @Override // java.lang.Runnable
            public void run() {
                GSYVideoControlView gSYVideoControlView = GSYVideoControlView.this;
                int i22 = gSYVideoControlView.mCurrentState;
                if (i22 == 0 || i22 == 7 || i22 == 6) {
                    return;
                }
                if (gSYVideoControlView.getActivityContext() != null) {
                    GSYVideoControlView.this.hideAllWidget();
                    GSYVideoControlView gSYVideoControlView2 = GSYVideoControlView.this;
                    gSYVideoControlView2.setViewShowState(gSYVideoControlView2.mLockScreen, 8);
                    GSYVideoControlView gSYVideoControlView3 = GSYVideoControlView.this;
                    if (gSYVideoControlView3.mHideKey && gSYVideoControlView3.mIfCurrentIsFullscreen && gSYVideoControlView3.mShowVKey) {
                        CommonUtil.hideNavKey(gSYVideoControlView3.mContext);
                    }
                }
                GSYVideoControlView gSYVideoControlView4 = GSYVideoControlView.this;
                if (gSYVideoControlView4.mPostDismiss) {
                    gSYVideoControlView4.postDelayed(this, gSYVideoControlView4.mDismissControlTime);
                }
            }
        };
    }

    public GSYVideoControlView(Context context, Boolean bool) {
        super(context, bool);
        this.mThreshold = 80;
        this.mShrinkImageRes = -1;
        this.mEnlargeImageRes = -1;
        this.mDismissControlTime = 2500;
        this.mBrightnessData = -1.0f;
        this.mSeekRatio = 1.0f;
        this.mTouchingProgressBar = false;
        this.mChangeVolume = false;
        this.mChangePosition = false;
        this.mShowVKey = false;
        this.mBrightness = false;
        this.mFirstTouch = false;
        this.mHideKey = true;
        this.mNeedShowWifiTip = true;
        this.mIsTouchWiget = true;
        this.mIsTouchWigetFull = true;
        this.mSetUpLazy = false;
        this.mHadSeekTouch = false;
        this.mPostProgress = false;
        this.mPostDismiss = false;
        this.isShowDragProgressTextOnSeekBar = false;
        this.gestureDetector = new GestureDetector(getContext().getApplicationContext(), new GestureDetector.SimpleOnGestureListener() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView.2
            @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnDoubleTapListener
            public boolean onDoubleTap(MotionEvent motionEvent) {
                GSYVideoControlView.this.touchDoubleUp();
                return super.onDoubleTap(motionEvent);
            }

            @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnDoubleTapListener
            public boolean onSingleTapConfirmed(MotionEvent motionEvent) {
                GSYVideoControlView gSYVideoControlView = GSYVideoControlView.this;
                if (!gSYVideoControlView.mChangePosition && !gSYVideoControlView.mChangeVolume && !gSYVideoControlView.mBrightness) {
                    gSYVideoControlView.onClickUiToggle();
                }
                return super.onSingleTapConfirmed(motionEvent);
            }
        });
        this.progressTask = new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView.4
            @Override // java.lang.Runnable
            public void run() {
                GSYVideoControlView gSYVideoControlView = GSYVideoControlView.this;
                int i22 = gSYVideoControlView.mCurrentState;
                if (i22 == 2 || i22 == 5) {
                    gSYVideoControlView.setTextAndProgress(0);
                }
                GSYVideoControlView gSYVideoControlView2 = GSYVideoControlView.this;
                if (gSYVideoControlView2.mPostProgress) {
                    gSYVideoControlView2.postDelayed(this, 1000L);
                }
            }
        };
        this.dismissControlTask = new Runnable() { // from class: com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView.5
            @Override // java.lang.Runnable
            public void run() {
                GSYVideoControlView gSYVideoControlView = GSYVideoControlView.this;
                int i22 = gSYVideoControlView.mCurrentState;
                if (i22 == 0 || i22 == 7 || i22 == 6) {
                    return;
                }
                if (gSYVideoControlView.getActivityContext() != null) {
                    GSYVideoControlView.this.hideAllWidget();
                    GSYVideoControlView gSYVideoControlView2 = GSYVideoControlView.this;
                    gSYVideoControlView2.setViewShowState(gSYVideoControlView2.mLockScreen, 8);
                    GSYVideoControlView gSYVideoControlView3 = GSYVideoControlView.this;
                    if (gSYVideoControlView3.mHideKey && gSYVideoControlView3.mIfCurrentIsFullscreen && gSYVideoControlView3.mShowVKey) {
                        CommonUtil.hideNavKey(gSYVideoControlView3.mContext);
                    }
                }
                GSYVideoControlView gSYVideoControlView4 = GSYVideoControlView.this;
                if (gSYVideoControlView4.mPostDismiss) {
                    gSYVideoControlView4.postDelayed(this, gSYVideoControlView4.mDismissControlTime);
                }
            }
        };
    }
}
