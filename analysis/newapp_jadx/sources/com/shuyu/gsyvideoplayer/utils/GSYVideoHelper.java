package com.shuyu.gsyvideoplayer.utils;

import android.R;
import android.app.Activity;
import android.content.Context;
import android.graphics.Point;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.core.view.ViewCompat;
import androidx.transition.TransitionManager;
import com.shuyu.gsyvideoplayer.render.view.GSYVideoGLView;
import com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer;
import com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer;
import com.shuyu.gsyvideoplayer.video.base.GSYVideoPlayer;
import java.io.File;
import java.util.Map;
import java.util.Objects;
import p005b.p362y.p363a.p364d.C2921a;
import p005b.p362y.p363a.p366f.InterfaceC2927c;
import p005b.p362y.p363a.p366f.InterfaceC2930f;
import p005b.p362y.p363a.p366f.InterfaceC2931g;

/* loaded from: classes2.dex */
public class GSYVideoHelper {
    private String TAG;
    private boolean isFull;
    private boolean isSmall;
    private Context mContext;
    private ViewGroup mFullViewContainer;
    private StandardGSYVideoPlayer mGsyVideoPlayer;
    private Handler mHandler;
    private int[] mNormalItemRect;
    private int[] mNormalItemSize;
    private ViewGroup.LayoutParams mNormalParams;
    private OrientationOption mOrientationOption;
    private OrientationUtils mOrientationUtils;
    private ViewGroup mParent;
    private int mPlayPosition;
    private int mSystemUiVisibility;
    private GSYVideoHelperBuilder mVideoOptionBuilder;
    private ViewGroup mWindowViewContainer;

    public static class GSYVideoHelperBuilder extends C2921a {
        public boolean mHideActionBar;
        public boolean mHideStatusBar;

        public Drawable getBottomProgressDrawable() {
            return this.mBottomProgressDrawable;
        }

        public Drawable getBottomShowProgressDrawable() {
            return this.mBottomShowProgressDrawable;
        }

        public Drawable getBottomShowProgressThumbDrawable() {
            return this.mBottomShowProgressThumbDrawable;
        }

        public File getCachePath() {
            return this.mCachePath;
        }

        public Drawable getDialogProgressBarDrawable() {
            return this.mDialogProgressBarDrawable;
        }

        public int getDialogProgressHighLightColor() {
            return this.mDialogProgressHighLightColor;
        }

        public int getDialogProgressNormalColor() {
            return this.mDialogProgressNormalColor;
        }

        public int getDismissControlTime() {
            return this.mDismissControlTime;
        }

        public GSYVideoGLView.InterfaceC4091c getEffectFilter() {
            return this.mEffectFilter;
        }

        public int getEnlargeImageRes() {
            return this.mEnlargeImageRes;
        }

        public InterfaceC2927c getGSYVideoProgressListener() {
            return this.mGSYVideoProgressListener;
        }

        public InterfaceC2930f getLockClickListener() {
            return this.mLockClickListener;
        }

        public Map<String, String> getMapHeadData() {
            return this.mMapHeadData;
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

        public float getSeekRatio() {
            return this.mSeekRatio;
        }

        public int getShrinkImageRes() {
            return this.mShrinkImageRes;
        }

        public float getSpeed() {
            return this.mSpeed;
        }

        public View getThumbImageView() {
            return this.mThumbImageView;
        }

        public String getUrl() {
            return this.mUrl;
        }

        public InterfaceC2931g getVideoAllCallBack() {
            return this.mVideoAllCallBack;
        }

        public String getVideoTitle() {
            return this.mVideoTitle;
        }

        public Drawable getVolumeProgressDrawable() {
            return this.mVolumeProgressDrawable;
        }

        public boolean isCacheWithPlay() {
            return this.mCacheWithPlay;
        }

        public boolean isHideActionBar() {
            return this.mHideActionBar;
        }

        public boolean isHideKey() {
            return this.mHideKey;
        }

        public boolean isHideStatusBar() {
            return this.mHideStatusBar;
        }

        public boolean isIsTouchWiget() {
            return this.mIsTouchWiget;
        }

        public boolean isIsTouchWigetFull() {
            return this.mIsTouchWigetFull;
        }

        public boolean isLockLand() {
            return this.mLockLand;
        }

        public boolean isLooping() {
            return this.mLooping;
        }

        public boolean isNeedLockFull() {
            return this.mNeedLockFull;
        }

        public boolean isNeedShowWifiTip() {
            return this.mNeedShowWifiTip;
        }

        public boolean isRotateViewAuto() {
            return this.mRotateViewAuto;
        }

        public boolean isRotateWithSystem() {
            return this.mRotateWithSystem;
        }

        public boolean isSetUpLazy() {
            return this.mSetUpLazy;
        }

        public boolean isShowFullAnimation() {
            return this.mShowFullAnimation;
        }

        public boolean isShowPauseCover() {
            return this.mShowPauseCover;
        }

        public boolean isSounchTouch() {
            return this.mSounchTouch;
        }

        public boolean isThumbPlay() {
            return this.mThumbPlay;
        }

        public GSYVideoHelperBuilder setHideActionBar(boolean z) {
            this.mHideActionBar = z;
            return this;
        }

        public GSYVideoHelperBuilder setHideStatusBar(boolean z) {
            this.mHideStatusBar = z;
            return this;
        }
    }

    public GSYVideoHelper(Context context) {
        this(context, new StandardGSYVideoPlayer(context));
    }

    private boolean isCurrentViewPlaying(int i2, String str) {
        return isPlayView(i2, str);
    }

    private boolean isPlayView(int i2, String str) {
        return this.mPlayPosition == i2 && this.TAG.equals(str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean removeWindowContainer() {
        ViewGroup viewGroup = this.mWindowViewContainer;
        if (viewGroup == null || viewGroup.indexOfChild(this.mGsyVideoPlayer) == -1) {
            return false;
        }
        this.mWindowViewContainer.removeView(this.mGsyVideoPlayer);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void resolveChangeFirstLogic(int i2) {
        if (this.mVideoOptionBuilder.isLockLand()) {
            if (i2 > 0) {
                this.mHandler.postDelayed(new Runnable() { // from class: com.shuyu.gsyvideoplayer.utils.GSYVideoHelper.5
                    @Override // java.lang.Runnable
                    public void run() {
                        if (GSYVideoHelper.this.mOrientationUtils.getIsLand() != 1) {
                            if (GSYVideoHelper.this.mFullViewContainer != null) {
                                GSYVideoHelper.this.mFullViewContainer.setBackgroundColor(ViewCompat.MEASURED_STATE_MASK);
                            }
                            GSYVideoHelper.this.mOrientationUtils.resolveByClick();
                        }
                    }
                }, i2);
            } else if (this.mOrientationUtils.getIsLand() != 1) {
                ViewGroup viewGroup = this.mFullViewContainer;
                if (viewGroup != null) {
                    viewGroup.setBackgroundColor(ViewCompat.MEASURED_STATE_MASK);
                }
                this.mOrientationUtils.resolveByClick();
            }
        }
        this.mGsyVideoPlayer.setIfCurrentIsFullscreen(true);
        this.mGsyVideoPlayer.restartTimerTask();
        if (this.mVideoOptionBuilder.getVideoAllCallBack() != null) {
            Debuger.printfLog("onEnterFullscreen");
            this.mVideoOptionBuilder.getVideoAllCallBack().onEnterFullscreen(this.mVideoOptionBuilder.getUrl(), this.mVideoOptionBuilder.getVideoTitle(), this.mGsyVideoPlayer);
        }
    }

    private void resolveFullAdd() {
        ViewGroup viewGroup;
        if (this.mVideoOptionBuilder.isShowFullAnimation() && (viewGroup = this.mFullViewContainer) != null) {
            viewGroup.setBackgroundColor(ViewCompat.MEASURED_STATE_MASK);
        }
        resolveChangeFirstLogic(0);
        ViewGroup viewGroup2 = this.mFullViewContainer;
        if (viewGroup2 != null) {
            viewGroup2.addView(this.mGsyVideoPlayer);
        } else {
            this.mWindowViewContainer.addView(this.mGsyVideoPlayer);
        }
    }

    private void resolveMaterialAnimation() {
        this.mNormalItemRect = new int[2];
        this.mNormalItemSize = new int[2];
        saveLocationStatus(this.mContext, this.mVideoOptionBuilder.isHideActionBar(), this.mVideoOptionBuilder.isHideStatusBar());
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-1, -1);
        FrameLayout frameLayout = new FrameLayout(this.mContext);
        frameLayout.setBackgroundColor(ViewCompat.MEASURED_STATE_MASK);
        int[] iArr = this.mNormalItemSize;
        FrameLayout.LayoutParams layoutParams2 = new FrameLayout.LayoutParams(iArr[0], iArr[1]);
        int[] iArr2 = this.mNormalItemRect;
        layoutParams2.setMargins(iArr2[0], iArr2[1], 0, 0);
        frameLayout.addView(this.mGsyVideoPlayer, layoutParams2);
        ViewGroup viewGroup = this.mFullViewContainer;
        if (viewGroup != null) {
            viewGroup.addView(frameLayout, layoutParams);
        } else {
            this.mWindowViewContainer.addView(frameLayout, layoutParams);
        }
        this.mHandler.postDelayed(new Runnable() { // from class: com.shuyu.gsyvideoplayer.utils.GSYVideoHelper.2
            @Override // java.lang.Runnable
            public void run() {
                if (GSYVideoHelper.this.mFullViewContainer != null) {
                    TransitionManager.beginDelayedTransition(GSYVideoHelper.this.mFullViewContainer);
                } else {
                    TransitionManager.beginDelayedTransition(GSYVideoHelper.this.mWindowViewContainer);
                }
                GSYVideoHelper gSYVideoHelper = GSYVideoHelper.this;
                gSYVideoHelper.resolveMaterialFullVideoShow(gSYVideoHelper.mGsyVideoPlayer);
                GSYVideoHelper.this.resolveChangeFirstLogic(600);
            }
        }, 300L);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void resolveMaterialFullVideoShow(GSYBaseVideoPlayer gSYBaseVideoPlayer) {
        FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) gSYBaseVideoPlayer.getLayoutParams();
        layoutParams.setMargins(0, 0, 0, 0);
        layoutParams.height = -1;
        layoutParams.width = -1;
        layoutParams.gravity = 17;
        gSYBaseVideoPlayer.setLayoutParams(layoutParams);
        gSYBaseVideoPlayer.setIfCurrentIsFullscreen(true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void resolveMaterialToNormal(final GSYVideoPlayer gSYVideoPlayer) {
        if (!this.mVideoOptionBuilder.isShowFullAnimation() || !(this.mFullViewContainer instanceof FrameLayout)) {
            resolveToNormal();
        } else {
            this.mHandler.postDelayed(new Runnable() { // from class: com.shuyu.gsyvideoplayer.utils.GSYVideoHelper.4
                @Override // java.lang.Runnable
                public void run() {
                    TransitionManager.beginDelayedTransition(GSYVideoHelper.this.mFullViewContainer);
                    FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) gSYVideoPlayer.getLayoutParams();
                    layoutParams.setMargins(GSYVideoHelper.this.mNormalItemRect[0], GSYVideoHelper.this.mNormalItemRect[1], 0, 0);
                    layoutParams.width = GSYVideoHelper.this.mNormalItemSize[0];
                    layoutParams.height = GSYVideoHelper.this.mNormalItemSize[1];
                    layoutParams.gravity = 0;
                    gSYVideoPlayer.setLayoutParams(layoutParams);
                    GSYVideoHelper.this.mHandler.postDelayed(new Runnable() { // from class: com.shuyu.gsyvideoplayer.utils.GSYVideoHelper.4.1
                        @Override // java.lang.Runnable
                        public void run() {
                            GSYVideoHelper.this.resolveToNormal();
                        }
                    }, 400L);
                }
            }, this.mOrientationUtils.backToProtVideo());
        }
    }

    private void resolveToFull() {
        this.mSystemUiVisibility = ((Activity) this.mContext).getWindow().getDecorView().getSystemUiVisibility();
        CommonUtil.hideSupportActionBar(this.mContext, this.mVideoOptionBuilder.isHideActionBar(), this.mVideoOptionBuilder.isHideStatusBar());
        if (this.mVideoOptionBuilder.isHideKey()) {
            CommonUtil.hideNavKey(this.mContext);
        }
        this.isFull = true;
        ViewGroup viewGroup = (ViewGroup) this.mGsyVideoPlayer.getParent();
        this.mNormalParams = this.mGsyVideoPlayer.getLayoutParams();
        if (viewGroup != null) {
            this.mParent = viewGroup;
            viewGroup.removeView(this.mGsyVideoPlayer);
        }
        this.mGsyVideoPlayer.setIfCurrentIsFullscreen(true);
        this.mGsyVideoPlayer.getFullscreenButton().setImageResource(this.mGsyVideoPlayer.getShrinkImageRes());
        this.mGsyVideoPlayer.getBackButton().setVisibility(0);
        OrientationUtils orientationUtils = new OrientationUtils((Activity) this.mContext, this.mGsyVideoPlayer, this.mOrientationOption);
        this.mOrientationUtils = orientationUtils;
        orientationUtils.setEnable(this.mVideoOptionBuilder.isRotateViewAuto());
        this.mGsyVideoPlayer.getBackButton().setOnClickListener(new View.OnClickListener() { // from class: com.shuyu.gsyvideoplayer.utils.GSYVideoHelper.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                GSYVideoHelper gSYVideoHelper = GSYVideoHelper.this;
                gSYVideoHelper.resolveMaterialToNormal(gSYVideoHelper.mGsyVideoPlayer);
            }
        });
        if (!this.mVideoOptionBuilder.isShowFullAnimation()) {
            resolveFullAdd();
        } else if (this.mFullViewContainer instanceof FrameLayout) {
            resolveMaterialAnimation();
        } else {
            resolveFullAdd();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void resolveToNormal() {
        int backToProtVideo = this.mOrientationUtils.backToProtVideo();
        if (!this.mVideoOptionBuilder.isShowFullAnimation()) {
            backToProtVideo = 0;
        }
        this.mHandler.postDelayed(new Runnable() { // from class: com.shuyu.gsyvideoplayer.utils.GSYVideoHelper.3
            @Override // java.lang.Runnable
            public void run() {
                GSYVideoHelper.this.isFull = false;
                GSYVideoHelper.this.removeWindowContainer();
                if (GSYVideoHelper.this.mFullViewContainer != null) {
                    GSYVideoHelper.this.mFullViewContainer.removeAllViews();
                }
                if (GSYVideoHelper.this.mGsyVideoPlayer.getParent() != null) {
                    ((ViewGroup) GSYVideoHelper.this.mGsyVideoPlayer.getParent()).removeView(GSYVideoHelper.this.mGsyVideoPlayer);
                }
                GSYVideoHelper.this.mOrientationUtils.setEnable(false);
                GSYVideoHelper.this.mGsyVideoPlayer.setIfCurrentIsFullscreen(false);
                if (GSYVideoHelper.this.mFullViewContainer != null) {
                    GSYVideoHelper.this.mFullViewContainer.setBackgroundColor(0);
                }
                GSYVideoHelper.this.mParent.addView(GSYVideoHelper.this.mGsyVideoPlayer, GSYVideoHelper.this.mNormalParams);
                GSYVideoHelper.this.mGsyVideoPlayer.getFullscreenButton().setImageResource(GSYVideoHelper.this.mGsyVideoPlayer.getEnlargeImageRes());
                GSYVideoHelper.this.mGsyVideoPlayer.getBackButton().setVisibility(8);
                GSYVideoHelper.this.mGsyVideoPlayer.setIfCurrentIsFullscreen(false);
                GSYVideoHelper.this.mGsyVideoPlayer.restartTimerTask();
                if (GSYVideoHelper.this.mVideoOptionBuilder.getVideoAllCallBack() != null) {
                    Debuger.printfLog("onQuitFullscreen");
                    GSYVideoHelper.this.mVideoOptionBuilder.getVideoAllCallBack().onQuitFullscreen(GSYVideoHelper.this.mVideoOptionBuilder.getUrl(), GSYVideoHelper.this.mVideoOptionBuilder.getVideoTitle(), GSYVideoHelper.this.mGsyVideoPlayer);
                }
                if (GSYVideoHelper.this.mVideoOptionBuilder.isHideKey()) {
                    CommonUtil.showNavKey(GSYVideoHelper.this.mContext, GSYVideoHelper.this.mSystemUiVisibility);
                }
                CommonUtil.showSupportActionBar(GSYVideoHelper.this.mContext, GSYVideoHelper.this.mVideoOptionBuilder.isHideActionBar(), GSYVideoHelper.this.mVideoOptionBuilder.isHideStatusBar());
            }
        }, backToProtVideo);
    }

    private void saveLocationStatus(Context context, boolean z, boolean z2) {
        this.mParent.getLocationOnScreen(this.mNormalItemRect);
        int statusBarHeight = CommonUtil.getStatusBarHeight(context);
        int actionBarHeight = CommonUtil.getActionBarHeight((Activity) context);
        if (z) {
            int[] iArr = this.mNormalItemRect;
            iArr[1] = iArr[1] - statusBarHeight;
        }
        if (z2) {
            int[] iArr2 = this.mNormalItemRect;
            iArr2[1] = iArr2[1] - actionBarHeight;
        }
        this.mNormalItemSize[0] = this.mParent.getWidth();
        this.mNormalItemSize[1] = this.mParent.getHeight();
    }

    public void addVideoPlayer(int i2, View view, String str, ViewGroup viewGroup, View view2) {
        viewGroup.removeAllViews();
        if (!isCurrentViewPlaying(i2, str)) {
            view2.setVisibility(0);
            viewGroup.removeAllViews();
            viewGroup.addView(view);
        } else {
            if (this.isFull) {
                return;
            }
            ViewGroup viewGroup2 = (ViewGroup) this.mGsyVideoPlayer.getParent();
            if (viewGroup2 != null) {
                viewGroup2.removeAllViews();
            }
            viewGroup.addView(this.mGsyVideoPlayer);
            view2.setVisibility(4);
        }
    }

    public boolean backFromFull() {
        ViewGroup viewGroup = this.mFullViewContainer;
        if (viewGroup != null && viewGroup.getChildCount() > 0) {
            resolveMaterialToNormal(this.mGsyVideoPlayer);
            return true;
        }
        ViewGroup viewGroup2 = this.mWindowViewContainer;
        if (viewGroup2 == null || viewGroup2.indexOfChild(this.mGsyVideoPlayer) == -1) {
            return false;
        }
        resolveMaterialToNormal(this.mGsyVideoPlayer);
        return true;
    }

    public void doFullBtnLogic() {
        if (this.isFull) {
            resolveMaterialToNormal(this.mGsyVideoPlayer);
        } else {
            resolveToFull();
        }
    }

    public C2921a getGsyVideoOptionBuilder() {
        return this.mVideoOptionBuilder;
    }

    public StandardGSYVideoPlayer getGsyVideoPlayer() {
        return this.mGsyVideoPlayer;
    }

    public int getPlayPosition() {
        return this.mPlayPosition;
    }

    public String getPlayTAG() {
        return this.TAG;
    }

    public boolean isFull() {
        return this.isFull;
    }

    public boolean isSmall() {
        return this.isSmall;
    }

    public void releaseVideoPlayer() {
        removeWindowContainer();
        ViewGroup viewGroup = (ViewGroup) this.mGsyVideoPlayer.getParent();
        if (viewGroup != null) {
            viewGroup.removeAllViews();
        }
        this.mPlayPosition = -1;
        this.TAG = "NULL";
        OrientationUtils orientationUtils = this.mOrientationUtils;
        if (orientationUtils != null) {
            orientationUtils.releaseListener();
        }
    }

    public void setFullViewContainer(ViewGroup viewGroup) {
        this.mFullViewContainer = viewGroup;
    }

    public void setGsyVideoOptionBuilder(GSYVideoHelperBuilder gSYVideoHelperBuilder) {
        this.mVideoOptionBuilder = gSYVideoHelperBuilder;
    }

    public void setOrientationOption(OrientationOption orientationOption) {
        this.mOrientationOption = orientationOption;
    }

    public void setPlayPositionAndTag(int i2, String str) {
        this.mPlayPosition = i2;
        this.TAG = str;
    }

    public void showSmallVideo(Point point, boolean z, boolean z2) {
        if (this.mGsyVideoPlayer.getCurrentState() == 2) {
            this.mGsyVideoPlayer.showSmallVideo(point, z, z2);
            this.isSmall = true;
        }
    }

    public void smallVideoToNormal() {
        this.isSmall = false;
        this.mGsyVideoPlayer.hideSmallVideo();
    }

    public void startPlay() {
        if (isSmall()) {
            smallVideoToNormal();
        }
        this.mGsyVideoPlayer.release();
        GSYVideoHelperBuilder gSYVideoHelperBuilder = this.mVideoOptionBuilder;
        Objects.requireNonNull(gSYVideoHelperBuilder, "mVideoOptionBuilder can't be null");
        gSYVideoHelperBuilder.build(this.mGsyVideoPlayer);
        if (this.mGsyVideoPlayer.getTitleTextView() != null) {
            this.mGsyVideoPlayer.getTitleTextView().setVisibility(8);
        }
        if (this.mGsyVideoPlayer.getBackButton() != null) {
            this.mGsyVideoPlayer.getBackButton().setVisibility(8);
        }
        if (this.mGsyVideoPlayer.getFullscreenButton() != null) {
            this.mGsyVideoPlayer.getFullscreenButton().setOnClickListener(new View.OnClickListener() { // from class: com.shuyu.gsyvideoplayer.utils.GSYVideoHelper.6
                @Override // android.view.View.OnClickListener
                public void onClick(View view) {
                    GSYVideoHelper.this.doFullBtnLogic();
                }
            });
        }
        this.mGsyVideoPlayer.startPlayLogic();
    }

    public GSYVideoHelper(Context context, StandardGSYVideoPlayer standardGSYVideoPlayer) {
        this.TAG = "NULL";
        this.mPlayPosition = -1;
        this.mHandler = new Handler();
        this.mGsyVideoPlayer = standardGSYVideoPlayer;
        this.mContext = context;
        this.mWindowViewContainer = (ViewGroup) CommonUtil.scanForActivity(context).findViewById(R.id.content);
    }
}
