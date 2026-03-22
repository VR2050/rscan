package com.shuyu.gsyvideoplayer.utils;

import android.app.Activity;
import android.content.Context;
import android.graphics.Point;
import android.os.Handler;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.core.view.ViewCompat;
import androidx.transition.TransitionManager;
import com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer;
import com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer;
import com.shuyu.gsyvideoplayer.video.base.GSYVideoPlayer;
import java.io.File;
import java.util.Map;
import p005b.p362y.p363a.p366f.InterfaceC2931g;

@Deprecated
/* loaded from: classes2.dex */
public class ListVideoUtil {
    private File cachePath;
    private Context context;
    private ViewGroup fullViewContainer;
    private StandardGSYVideoPlayer gsyVideoPlayer;
    private boolean hideActionBar;
    private boolean hideStatusBar;
    private boolean isFull;
    private boolean isLoop;
    private boolean isSmall;
    private int[] listItemRect;
    private int[] listItemSize;
    private ViewGroup.LayoutParams listParams;
    private ViewGroup listParent;
    private String mTitle;
    private Map<String, String> mapHeadData;
    private OrientationUtils orientationUtils;
    private int systemUiVisibility;
    private String url;
    private InterfaceC2931g videoAllCallBack;
    private String TAG = "NULL";
    private int playPosition = -1;
    private int speed = 1;
    private boolean hideKey = true;
    private boolean needLockFull = true;
    public boolean needShowWifiTip = true;
    private boolean fullLandFrist = true;
    private boolean autoRotation = true;
    private boolean showFullAnimation = true;
    private Handler handler = new Handler();

    public ListVideoUtil(Context context) {
        this.gsyVideoPlayer = new StandardGSYVideoPlayer(context);
        this.context = context;
    }

    private boolean isCurrentViewPlaying(int i2, String str) {
        return isPlayView(i2, str);
    }

    private boolean isPlayView(int i2, String str) {
        return this.playPosition == i2 && this.TAG.equals(str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void resolveChangeFirstLogic(int i2) {
        if (isFullLandFrist()) {
            this.handler.postDelayed(new Runnable() { // from class: com.shuyu.gsyvideoplayer.utils.ListVideoUtil.6
                @Override // java.lang.Runnable
                public void run() {
                    if (ListVideoUtil.this.orientationUtils.getIsLand() != 1) {
                        ListVideoUtil.this.orientationUtils.resolveByClick();
                    }
                }
            }, i2);
        }
        this.gsyVideoPlayer.setIfCurrentIsFullscreen(true);
        if (this.videoAllCallBack != null) {
            Debuger.printfLog("onEnterFullscreen");
            this.videoAllCallBack.onEnterFullscreen(this.url, this.mTitle, this.gsyVideoPlayer);
        }
    }

    private void resolveFullAdd() {
        this.fullViewContainer.setBackgroundColor(ViewCompat.MEASURED_STATE_MASK);
        this.fullViewContainer.addView(this.gsyVideoPlayer);
        resolveChangeFirstLogic(50);
    }

    private void resolveMaterialAnimation() {
        this.listItemRect = new int[2];
        this.listItemSize = new int[2];
        saveLocationStatus(this.context, this.hideStatusBar, this.hideActionBar);
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-1, -1);
        FrameLayout frameLayout = new FrameLayout(this.context);
        frameLayout.setBackgroundColor(ViewCompat.MEASURED_STATE_MASK);
        int[] iArr = this.listItemSize;
        FrameLayout.LayoutParams layoutParams2 = new FrameLayout.LayoutParams(iArr[0], iArr[1]);
        int[] iArr2 = this.listItemRect;
        layoutParams2.setMargins(iArr2[0], iArr2[1], 0, 0);
        frameLayout.addView(this.gsyVideoPlayer, layoutParams2);
        this.fullViewContainer.addView(frameLayout, layoutParams);
        this.handler.postDelayed(new Runnable() { // from class: com.shuyu.gsyvideoplayer.utils.ListVideoUtil.3
            @Override // java.lang.Runnable
            public void run() {
                TransitionManager.beginDelayedTransition(ListVideoUtil.this.fullViewContainer);
                ListVideoUtil listVideoUtil = ListVideoUtil.this;
                listVideoUtil.resolveMaterialFullVideoShow(listVideoUtil.gsyVideoPlayer);
                ListVideoUtil.this.resolveChangeFirstLogic(600);
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
        if (!this.showFullAnimation || !(this.fullViewContainer instanceof FrameLayout)) {
            resolveToNormal();
        } else {
            this.handler.postDelayed(new Runnable() { // from class: com.shuyu.gsyvideoplayer.utils.ListVideoUtil.5
                @Override // java.lang.Runnable
                public void run() {
                    TransitionManager.beginDelayedTransition(ListVideoUtil.this.fullViewContainer);
                    FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) gSYVideoPlayer.getLayoutParams();
                    layoutParams.setMargins(ListVideoUtil.this.listItemRect[0], ListVideoUtil.this.listItemRect[1], 0, 0);
                    layoutParams.width = ListVideoUtil.this.listItemSize[0];
                    layoutParams.height = ListVideoUtil.this.listItemSize[1];
                    layoutParams.gravity = 0;
                    gSYVideoPlayer.setLayoutParams(layoutParams);
                    ListVideoUtil.this.handler.postDelayed(new Runnable() { // from class: com.shuyu.gsyvideoplayer.utils.ListVideoUtil.5.1
                        @Override // java.lang.Runnable
                        public void run() {
                            ListVideoUtil.this.resolveToNormal();
                        }
                    }, 400L);
                }
            }, this.orientationUtils.backToProtVideo());
        }
    }

    private void resolveToFull() {
        this.systemUiVisibility = ((Activity) this.context).getWindow().getDecorView().getSystemUiVisibility();
        CommonUtil.hideSupportActionBar(this.context, this.hideActionBar, this.hideStatusBar);
        if (this.hideKey) {
            CommonUtil.hideNavKey(this.context);
        }
        this.isFull = true;
        ViewGroup viewGroup = (ViewGroup) this.gsyVideoPlayer.getParent();
        this.listParams = this.gsyVideoPlayer.getLayoutParams();
        if (viewGroup != null) {
            this.listParent = viewGroup;
            viewGroup.removeView(this.gsyVideoPlayer);
        }
        this.gsyVideoPlayer.setIfCurrentIsFullscreen(true);
        this.gsyVideoPlayer.getFullscreenButton().setImageResource(this.gsyVideoPlayer.getShrinkImageRes());
        this.gsyVideoPlayer.getBackButton().setVisibility(0);
        OrientationUtils orientationUtils = new OrientationUtils((Activity) this.context, this.gsyVideoPlayer);
        this.orientationUtils = orientationUtils;
        orientationUtils.setEnable(isAutoRotation());
        this.gsyVideoPlayer.getBackButton().setOnClickListener(new View.OnClickListener() { // from class: com.shuyu.gsyvideoplayer.utils.ListVideoUtil.2
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                ListVideoUtil listVideoUtil = ListVideoUtil.this;
                listVideoUtil.resolveMaterialToNormal(listVideoUtil.gsyVideoPlayer);
            }
        });
        if (!this.showFullAnimation) {
            resolveFullAdd();
        } else if (this.fullViewContainer instanceof FrameLayout) {
            resolveMaterialAnimation();
        } else {
            resolveFullAdd();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void resolveToNormal() {
        this.handler.postDelayed(new Runnable() { // from class: com.shuyu.gsyvideoplayer.utils.ListVideoUtil.4
            @Override // java.lang.Runnable
            public void run() {
                ListVideoUtil.this.isFull = false;
                ListVideoUtil.this.fullViewContainer.removeAllViews();
                if (ListVideoUtil.this.gsyVideoPlayer.getParent() != null) {
                    ((ViewGroup) ListVideoUtil.this.gsyVideoPlayer.getParent()).removeView(ListVideoUtil.this.gsyVideoPlayer);
                }
                ListVideoUtil.this.orientationUtils.setEnable(false);
                ListVideoUtil.this.gsyVideoPlayer.setIfCurrentIsFullscreen(false);
                ListVideoUtil.this.fullViewContainer.setBackgroundColor(0);
                ListVideoUtil.this.listParent.addView(ListVideoUtil.this.gsyVideoPlayer, ListVideoUtil.this.listParams);
                ListVideoUtil.this.gsyVideoPlayer.getFullscreenButton().setImageResource(ListVideoUtil.this.gsyVideoPlayer.getEnlargeImageRes());
                ListVideoUtil.this.gsyVideoPlayer.getBackButton().setVisibility(8);
                ListVideoUtil.this.gsyVideoPlayer.setIfCurrentIsFullscreen(false);
                if (ListVideoUtil.this.videoAllCallBack != null) {
                    Debuger.printfLog("onQuitFullscreen");
                    ListVideoUtil.this.videoAllCallBack.onQuitFullscreen(ListVideoUtil.this.url, ListVideoUtil.this.mTitle, ListVideoUtil.this.gsyVideoPlayer);
                }
                if (ListVideoUtil.this.hideKey) {
                    CommonUtil.showNavKey(ListVideoUtil.this.context, ListVideoUtil.this.systemUiVisibility);
                }
                CommonUtil.showSupportActionBar(ListVideoUtil.this.context, ListVideoUtil.this.hideActionBar, ListVideoUtil.this.hideStatusBar);
            }
        }, this.orientationUtils.backToProtVideo());
    }

    private void saveLocationStatus(Context context, boolean z, boolean z2) {
        this.listParent.getLocationOnScreen(this.listItemRect);
        int statusBarHeight = CommonUtil.getStatusBarHeight(context);
        int actionBarHeight = CommonUtil.getActionBarHeight((Activity) context);
        if (z) {
            int[] iArr = this.listItemRect;
            iArr[1] = iArr[1] - statusBarHeight;
        }
        if (z2) {
            int[] iArr2 = this.listItemRect;
            iArr2[1] = iArr2[1] - actionBarHeight;
        }
        this.listItemSize[0] = this.listParent.getWidth();
        this.listItemSize[1] = this.listParent.getHeight();
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
            ViewGroup viewGroup2 = (ViewGroup) this.gsyVideoPlayer.getParent();
            if (viewGroup2 != null) {
                viewGroup2.removeAllViews();
            }
            viewGroup.addView(this.gsyVideoPlayer);
            view2.setVisibility(4);
        }
    }

    public boolean backFromFull() {
        if (this.fullViewContainer.getChildCount() <= 0) {
            return false;
        }
        resolveMaterialToNormal(this.gsyVideoPlayer);
        return true;
    }

    public File getCachePath() {
        return this.cachePath;
    }

    public int getCurrentPositionWhenPlaying() {
        return this.gsyVideoPlayer.getCurrentPositionWhenPlaying();
    }

    public int getDuration() {
        return this.gsyVideoPlayer.getDuration();
    }

    public StandardGSYVideoPlayer getGsyVideoPlayer() {
        return this.gsyVideoPlayer;
    }

    public Map<String, String> getMapHeadData() {
        return this.mapHeadData;
    }

    public int getPlayPosition() {
        return this.playPosition;
    }

    public String getPlayTAG() {
        return this.TAG;
    }

    public int getSpeed() {
        return this.speed;
    }

    public String getTitle() {
        return this.mTitle;
    }

    public boolean isAutoRotation() {
        return this.autoRotation;
    }

    public boolean isFull() {
        return this.isFull;
    }

    public boolean isFullLandFrist() {
        return this.fullLandFrist;
    }

    public boolean isHideActionBar() {
        return this.hideActionBar;
    }

    public boolean isHideKey() {
        return this.hideKey;
    }

    public boolean isHideStatusBar() {
        return this.hideStatusBar;
    }

    public boolean isLoop() {
        return this.isLoop;
    }

    public boolean isNeedLockFull() {
        return this.needLockFull;
    }

    public boolean isNeedShowWifiTip() {
        return this.needShowWifiTip;
    }

    public boolean isShowFullAnimation() {
        return this.showFullAnimation;
    }

    public boolean isSmall() {
        return this.isSmall;
    }

    public void releaseVideoPlayer() {
        ViewGroup viewGroup = (ViewGroup) this.gsyVideoPlayer.getParent();
        if (viewGroup != null) {
            viewGroup.removeAllViews();
        }
        this.playPosition = -1;
        this.TAG = "NULL";
        OrientationUtils orientationUtils = this.orientationUtils;
        if (orientationUtils != null) {
            orientationUtils.releaseListener();
        }
    }

    public void resolveFullBtn() {
        if (this.fullViewContainer == null) {
            return;
        }
        if (this.isFull) {
            resolveMaterialToNormal(this.gsyVideoPlayer);
        } else {
            resolveToFull();
        }
    }

    public void setAutoRotation(boolean z) {
        this.autoRotation = z;
    }

    public void setCachePath(File file) {
        this.cachePath = file;
    }

    public void setFullLandFrist(boolean z) {
        this.fullLandFrist = z;
    }

    public void setFullViewContainer(ViewGroup viewGroup) {
        this.fullViewContainer = viewGroup;
    }

    public void setHideActionBar(boolean z) {
        this.hideActionBar = z;
    }

    public void setHideKey(boolean z) {
        this.hideKey = z;
    }

    public void setHideStatusBar(boolean z) {
        this.hideStatusBar = z;
    }

    public void setLoop(boolean z) {
        this.isLoop = z;
    }

    public void setMapHeadData(Map<String, String> map) {
        this.mapHeadData = map;
    }

    public void setNeedLockFull(boolean z) {
        this.needLockFull = z;
    }

    public void setNeedShowWifiTip(boolean z) {
        this.needShowWifiTip = z;
    }

    public void setPlayPositionAndTag(int i2, String str) {
        this.playPosition = i2;
        this.TAG = str;
    }

    public void setShowFullAnimation(boolean z) {
        this.showFullAnimation = z;
    }

    public void setSpeed(int i2) {
        this.speed = i2;
    }

    public void setTitle(String str) {
        this.mTitle = str;
    }

    public void setVideoAllCallBack(InterfaceC2931g interfaceC2931g) {
        this.videoAllCallBack = interfaceC2931g;
        this.gsyVideoPlayer.setVideoAllCallBack(interfaceC2931g);
    }

    public void showSmallVideo(Point point, boolean z, boolean z2) {
        if (this.gsyVideoPlayer.getCurrentState() == 2) {
            this.gsyVideoPlayer.showSmallVideo(point, z, z2);
            this.isSmall = true;
        }
    }

    public void smallVideoToNormal() {
        this.isSmall = false;
        this.gsyVideoPlayer.hideSmallVideo();
    }

    public void startPlay(String str) {
        if (isSmall()) {
            smallVideoToNormal();
        }
        this.url = str;
        this.gsyVideoPlayer.release();
        this.gsyVideoPlayer.setLooping(this.isLoop);
        this.gsyVideoPlayer.setSpeed(this.speed);
        this.gsyVideoPlayer.setNeedShowWifiTip(this.needShowWifiTip);
        this.gsyVideoPlayer.setNeedLockFull(this.needLockFull);
        this.gsyVideoPlayer.setUp(str, true, this.cachePath, this.mapHeadData, this.mTitle);
        if (!TextUtils.isEmpty(this.mTitle)) {
            this.gsyVideoPlayer.getTitleTextView().setText(this.mTitle);
        }
        this.gsyVideoPlayer.getTitleTextView().setVisibility(8);
        this.gsyVideoPlayer.getBackButton().setVisibility(8);
        this.gsyVideoPlayer.getFullscreenButton().setOnClickListener(new View.OnClickListener() { // from class: com.shuyu.gsyvideoplayer.utils.ListVideoUtil.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                ListVideoUtil.this.resolveFullBtn();
            }
        });
        this.gsyVideoPlayer.startPlayLogic();
    }
}
