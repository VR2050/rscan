package com.jbzd.media.movecartoons.view.video;

import android.app.Activity;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Point;
import android.util.AttributeSet;
import android.view.Surface;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.jbzd.media.movecartoons.p396ui.dialog.CommonPopupWindow;
import com.jbzd.media.movecartoons.view.video.FullPlayerView;
import com.qnmd.adnnm.da0yzo.R;
import com.shuyu.gsyvideoplayer.utils.CommonUtil;
import com.shuyu.gsyvideoplayer.utils.GSYVideoType;
import com.shuyu.gsyvideoplayer.utils.OrientationUtils;
import com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer;
import com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer;
import java.util.ArrayList;
import java.util.Objects;
import p005b.p006a.p007a.p008a.C0885h;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p325v.p326a.C2818e;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p336c.C2852c;
import p005b.p362y.p363a.p366f.InterfaceC2927c;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes2.dex */
public class FullPlayerView extends StandardGSYVideoPlayer implements CommonPopupWindow.ViewInterface {
    private static final String TAG = "FullPlayerView";
    public static int mVideoVolume = 0;
    private static final int touchSurfaceMaxMove = 300000;
    public ImageView btn_stop;
    public ImageView btn_voice;
    private VideoCallBack callBack;
    private int curr;
    private boolean hideTopLayoutWhenSmall;
    public boolean isHorizontal;
    private View layout_top;
    public OnCompletionListener mCompletionListener;
    public ImageView mCoverImage;
    private String mCoverOriginUrl;
    public OnStatusChangeListener mStatusListener;
    public ImageView playerImage;
    private SpeedAdapter speedAdapter;
    private TextView speedView;
    private CommonPopupWindow speedWindow;
    private ArrayList<Speed> speeds;
    private boolean visibility;

    public interface OnCompletionListener {
        void onCompletion();
    }

    public interface OnStatusChangeListener {
        void onStatusChange(int i2);
    }

    public interface VideoCallBack {
        void onAutoComplete();
    }

    public FullPlayerView(Context context, Boolean bool) {
        super(context, bool);
        this.isHorizontal = true;
        this.speeds = new ArrayList<Speed>() { // from class: com.jbzd.media.movecartoons.view.video.FullPlayerView.2
            {
                add(new Speed(2.0f, "2倍"));
                add(new Speed(1.5f, "1.5倍"));
                add(new Speed(1.0f, "1倍"));
                add(new Speed(0.75f, "0.75倍"));
                add(new Speed(0.5f, "0.5倍"));
            }
        };
        this.speedAdapter = new SpeedAdapter(this.speeds);
        this.hideTopLayoutWhenSmall = false;
        this.visibility = true;
        this.curr = 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showSpeedDialog() {
        if (this.speedWindow == null) {
            this.speedWindow = new CommonPopupWindow.Builder(getContext()).setView(R.layout.popup_speed).setWidthAndHeight(C4195m.m4785R(100.0f), -2).setViewOnclickListener(this).builder();
        }
        CommonPopupWindow commonPopupWindow = this.speedWindow;
        commonPopupWindow.showAsDropDown(this.speedView, 0, -(this.speedView.getMeasuredHeight() + commonPopupWindow.getHeight()));
    }

    /* renamed from: a */
    public /* synthetic */ void m4514a(View view) {
        int i2;
        if (this.mCurrentState == 7 && (i2 = this.curr) > 0) {
            setSeekOnStart(i2);
            this.curr = 0;
        }
        clickStartIcon();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer
    public void backToNormal() {
        View view = this.layout_top;
        if (view != null && this.hideTopLayoutWhenSmall) {
            view.setAlpha(0.0f);
        }
        super.backToNormal();
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void changeUiToCompleteShow() {
        super.changeUiToCompleteShow();
        CommonPopupWindow commonPopupWindow = this.speedWindow;
        if (commonPopupWindow != null) {
            commonPopupWindow.dismiss();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void changeUiToPlayingShow() {
        super.changeUiToPlayingShow();
        ViewGroup viewGroup = this.mBottomContainer;
        if (viewGroup != null) {
            if (this.visibility) {
                viewGroup.setVisibility(0);
            } else {
                viewGroup.setVisibility(4);
            }
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer
    public void clearFullscreenLayout() {
        int i2;
        if (this.mFullAnimEnd) {
            this.mIfCurrentIsFullscreen = false;
            OrientationUtils orientationUtils = this.mOrientationUtils;
            if (orientationUtils != null) {
                i2 = orientationUtils.backToProtVideo();
                this.mOrientationUtils.setEnable(true);
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
            View findViewById = ((ViewGroup) CommonUtil.scanForActivity(getContext()).findViewById(android.R.id.content)).findViewById(getFullId());
            if (findViewById != null) {
                ((FullPlayerView) findViewById).mIfCurrentIsFullscreen = false;
            }
            if (i2 == 0) {
                backToNormal();
            } else {
                postDelayed(new Runnable() { // from class: com.jbzd.media.movecartoons.view.video.FullPlayerView.4
                    @Override // java.lang.Runnable
                    public void run() {
                        FullPlayerView.this.backToNormal();
                    }
                }, i2);
            }
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer
    public void cloneParams(GSYBaseVideoPlayer gSYBaseVideoPlayer, GSYBaseVideoPlayer gSYBaseVideoPlayer2) {
        super.cloneParams(gSYBaseVideoPlayer, gSYBaseVideoPlayer2);
        ((FullPlayerView) gSYBaseVideoPlayer2).mShowFullAnimation = ((FullPlayerView) gSYBaseVideoPlayer).mShowFullAnimation;
    }

    public String getApplicationName() {
        PackageManager packageManager;
        ApplicationInfo applicationInfo = null;
        try {
            packageManager = C2827a.f7670a.getPackageManager();
            try {
                applicationInfo = packageManager.getApplicationInfo(C2827a.f7670a.getPackageName(), 0);
            } catch (PackageManager.NameNotFoundException unused) {
            }
        } catch (PackageManager.NameNotFoundException unused2) {
            packageManager = null;
        }
        return (String) packageManager.getApplicationLabel(applicationInfo);
    }

    @Override // com.jbzd.media.movecartoons.ui.dialog.CommonPopupWindow.ViewInterface
    public void getChildView(@Nullable View view, int i2) {
        if (i2 == R.layout.popup_speed) {
            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rvSpeed);
            recyclerView.setLayoutManager(new LinearLayoutManager(getContext()));
            this.speedAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: com.jbzd.media.movecartoons.view.video.FullPlayerView.1
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                public void onItemClick(@NonNull BaseQuickAdapter baseQuickAdapter, @NonNull View view2, int i3) {
                    Speed speed = (Speed) baseQuickAdapter.getItem(i3);
                    FullPlayerView.this.setSpeed(speed.getSpeed());
                    FullPlayerView.this.speedAdapter.setSpeed(speed.getSpeed());
                    if (FullPlayerView.this.speedView != null) {
                        FullPlayerView.this.speedView.setText(speed.getName());
                    }
                    FullPlayerView.this.speedWindow.dismiss();
                }
            });
            recyclerView.setAdapter(this.speedAdapter);
        }
    }

    public int getCurrentPositionWhenAnyTime() {
        try {
            int currentPosition = (int) getGSYVideoManager().getCurrentPosition();
            if (currentPosition == 0) {
                long j2 = this.mCurrentPosition;
                if (j2 > 0) {
                    return (int) j2;
                }
            }
            return currentPosition;
        } catch (Exception e2) {
            e2.printStackTrace();
            return 0;
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public int getEnlargeImageRes() {
        return R.drawable.video_enlarge;
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public int getLayoutId() {
        return R.layout.full_video_player;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public int getShrinkImageRes() {
        return R.drawable.video_shrink;
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public void init(Context context) {
        int i2;
        super.init(context);
        this.mCoverImage = (ImageView) findViewById(R.id.thumbImage);
        this.layout_top = findViewById(R.id.layout_top);
        this.playerImage = (ImageView) findViewById(R.id.player);
        this.btn_stop = (ImageView) findViewById(R.id.btn_stop);
        this.btn_voice = (ImageView) findViewById(R.id.btn_voice);
        TextView textView = (TextView) findViewById(R.id.velocityView);
        this.speedView = textView;
        if (textView != null) {
            textView.setOnClickListener(new View.OnClickListener() { // from class: com.jbzd.media.movecartoons.view.video.FullPlayerView.3
                @Override // android.view.View.OnClickListener
                public void onClick(View view) {
                    FullPlayerView.this.showSpeedDialog();
                }
            });
        }
        ImageView imageView = this.btn_stop;
        if (imageView != null) {
            imageView.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.u.q.c
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    FullPlayerView.this.clickStartIcon();
                }
            });
        }
        ImageView imageView2 = this.playerImage;
        if (imageView2 != null) {
            imageView2.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.u.q.a
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    FullPlayerView.this.m4514a(view);
                }
            });
        }
        RelativeLayout relativeLayout = this.mThumbImageViewLayout;
        if (relativeLayout != null && ((i2 = this.mCurrentState) == -1 || i2 == 0 || i2 == 7)) {
            relativeLayout.setVisibility(0);
        }
        if (this.btn_voice == null) {
            try {
                if (this.mAudioManager.getStreamVolume(3) == 0) {
                    this.mAudioManager.setStreamVolume(3, mVideoVolume, 0);
                    return;
                }
                return;
            } catch (Exception unused) {
                return;
            }
        }
        if (C0885h.f330b) {
            C0885h.f330b = false;
            try {
                mVideoVolume = this.mAudioManager.getStreamVolume(3);
                this.mAudioManager.setStreamVolume(3, 0, 0);
            } catch (Exception unused2) {
            }
        }
        updateVoiceStatus();
        this.btn_voice.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.u.q.b
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                FullPlayerView fullPlayerView = FullPlayerView.this;
                Objects.requireNonNull(fullPlayerView);
                try {
                    int streamVolume = fullPlayerView.mAudioManager.getStreamVolume(3);
                    int streamMaxVolume = fullPlayerView.mAudioManager.getStreamMaxVolume(3);
                    if (streamVolume == 0) {
                        if (FullPlayerView.mVideoVolume == 0) {
                            FullPlayerView.mVideoVolume = streamMaxVolume / 2;
                        }
                        fullPlayerView.mAudioManager.setStreamVolume(3, FullPlayerView.mVideoVolume, 0);
                    } else {
                        FullPlayerView.mVideoVolume = streamVolume;
                        fullPlayerView.mAudioManager.setStreamVolume(3, 0, 0);
                    }
                    fullPlayerView.updateVoiceStatus();
                } catch (Exception unused3) {
                }
            }
        });
    }

    public void loadCoverImage(String str) {
        this.mCoverOriginUrl = str;
        if (this.mCoverImage != null) {
            if (this.isHorizontal) {
                if (this.visibility) {
                    ((C2852c) ComponentCallbacks2C1553c.m739i(this)).m3298p(this.mCoverOriginUrl).m3295i0().m3294h0(true).m757R(this.mCoverImage);
                }
            } else if (this.visibility) {
                if (getApplicationName().startsWith("九妖")) {
                    ((C2852c) ComponentCallbacks2C1553c.m739i(this)).m3298p(this.mCoverOriginUrl).m3295i0().m3291e0(R.drawable.ic_place_holder_vertical_51).m3294h0(true).m757R(this.mCoverImage);
                } else {
                    ((C2852c) ComponentCallbacks2C1553c.m739i(this)).m3298p(this.mCoverOriginUrl).m3295i0().m3291e0(R.drawable.ic_place_holder_circle).m3294h0(true).m757R(this.mCoverImage);
                }
            }
        }
    }

    public void loadCoverImageFitCenter(String str) {
        this.mCoverOriginUrl = str;
        if (this.mCoverImage != null) {
            ((C2852c) ComponentCallbacks2C1553c.m739i(this)).m3298p(this.mCoverOriginUrl).m3295i0().m3294h0(true).m757R(this.mCoverImage);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, com.shuyu.gsyvideoplayer.video.base.GSYVideoView, p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onAutoCompletion() {
        backFromFull(getContext());
        super.onAutoCompletion();
        ImageView imageView = this.mCoverImage;
        if (imageView != null) {
            imageView.setVisibility(0);
        }
        ImageView imageView2 = this.playerImage;
        if (imageView2 != null) {
            imageView2.setVisibility(0);
        }
        ViewGroup viewGroup = this.mBottomContainer;
        if (viewGroup != null) {
            viewGroup.setVisibility(8);
        }
        ViewGroup viewGroup2 = this.mTopContainer;
        if (viewGroup2 != null) {
            viewGroup2.setVisibility(8);
        }
        VideoCallBack videoCallBack = this.callBack;
        if (videoCallBack != null) {
            videoCallBack.onAutoComplete();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView, p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onCompletion() {
        super.onCompletion();
        OnCompletionListener onCompletionListener = this.mCompletionListener;
        if (onCompletionListener != null) {
            onCompletionListener.onCompletion();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, com.shuyu.gsyvideoplayer.video.base.GSYVideoView, p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onError(int i2, int i3) {
        C2818e.m3273b(C1499a.m629o("===============what:", i2, "extra:", i3), new Object[0]);
        int currentPositionWhenAnyTime = getCurrentPositionWhenAnyTime() - 3000;
        this.curr = currentPositionWhenAnyTime >= 0 ? currentPositionWhenAnyTime : 0;
        super.onError(i2, i3);
    }

    public void onPlayStatusChange() {
        int i2 = this.mCurrentState;
        if (i2 == 5 || i2 == 7) {
            ImageView imageView = this.playerImage;
            if (imageView != null) {
                imageView.setVisibility(0);
            }
            ImageView imageView2 = this.btn_stop;
            if (imageView2 != null) {
                imageView2.setImageResource(R.drawable.ic_player_icon);
                return;
            }
            return;
        }
        ImageView imageView3 = this.playerImage;
        if (imageView3 != null) {
            imageView3.setVisibility(4);
        }
        ImageView imageView4 = this.btn_stop;
        if (imageView4 != null) {
            imageView4.setImageResource(R.drawable.ic_stop_icon);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYTextureRenderView, p005b.p362y.p363a.p369i.p372d.p373b.InterfaceC2947c
    public void onSurfaceAvailable(Surface surface) {
        RelativeLayout relativeLayout;
        super.onSurfaceAvailable(surface);
        if (GSYVideoType.getRenderType() == 0 || (relativeLayout = this.mThumbImageViewLayout) == null || relativeLayout.getVisibility() != 0) {
            return;
        }
        this.mThumbImageViewLayout.setVisibility(4);
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYTextureRenderView, p005b.p362y.p363a.p369i.p372d.p373b.InterfaceC2947c
    public void onSurfaceUpdated(Surface surface) {
        if (isLooping() && this.mBottomProgressBar.getProgress() == this.mBottomProgressBar.getMax() - 1) {
            loopSetProgressAndTime();
        }
        super.onSurfaceUpdated(surface);
        RelativeLayout relativeLayout = this.mThumbImageViewLayout;
        if (relativeLayout == null || relativeLayout.getVisibility() != 0) {
            return;
        }
        this.mThumbImageViewLayout.setVisibility(4);
    }

    public void setBottomShow(boolean z) {
        this.visibility = z;
    }

    public void setCallBack(VideoCallBack videoCallBack) {
        this.callBack = videoCallBack;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void setGSYVideoProgressListener(InterfaceC2927c interfaceC2927c) {
        super.setGSYVideoProgressListener(interfaceC2927c);
    }

    public void setHideTopLayoutWhenSmall(Boolean bool) {
        boolean booleanValue = bool.booleanValue();
        this.hideTopLayoutWhenSmall = booleanValue;
        View view = this.layout_top;
        if (view == null || !booleanValue) {
            return;
        }
        view.setAlpha(0.0f);
    }

    public void setOnCompletionListener(OnCompletionListener onCompletionListener) {
        this.mCompletionListener = onCompletionListener;
    }

    public void setOnStatusChangeListener(OnStatusChangeListener onStatusChangeListener) {
        this.mStatusListener = onStatusChangeListener;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void setSeekRatio(float f2) {
        super.setSeekRatio(f2);
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public void setStateAndUi(int i2) {
        super.setStateAndUi(i2);
        OnStatusChangeListener onStatusChangeListener = this.mStatusListener;
        if (onStatusChangeListener != null) {
            onStatusChangeListener.onStatusChange(i2);
        }
        onPlayStatusChange();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void setViewShowState(View view, int i2) {
        ImageView imageView;
        if (view != this.mThumbImageViewLayout || i2 == 0) {
            int i3 = this.mCurrentState;
            if (i3 != 5 && i3 != 7 && (imageView = this.playerImage) != null) {
                imageView.setVisibility(4);
            }
            super.setViewShowState(view, i2);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer
    public GSYBaseVideoPlayer showSmallVideo(Point point, boolean z, boolean z2) {
        FullPlayerView fullPlayerView = (FullPlayerView) super.showSmallVideo(point, z, z2);
        fullPlayerView.mStartButton.setVisibility(8);
        fullPlayerView.mStartButton = null;
        fullPlayerView.callBack = this.callBack;
        return fullPlayerView;
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer
    public GSYBaseVideoPlayer startWindowFullscreen(Context context, boolean z, boolean z2) {
        View view = this.layout_top;
        if (view != null && this.hideTopLayoutWhenSmall) {
            view.setAlpha(1.0f);
        }
        GSYBaseVideoPlayer startWindowFullscreen = super.startWindowFullscreen(context, z, z2);
        FullPlayerView fullPlayerView = (FullPlayerView) startWindowFullscreen;
        fullPlayerView.loadCoverImage(this.mCoverOriginUrl);
        fullPlayerView.callBack = this.callBack;
        return startWindowFullscreen;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void touchDoubleUp() {
        if (this.visibility) {
            super.touchDoubleUp();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void touchSurfaceMove(float f2, float f3, float f4) {
        int i2 = CommonUtil.getCurrentScreenLand((Activity) getActivityContext()) ? this.mScreenHeight : this.mScreenWidth;
        int i3 = CommonUtil.getCurrentScreenLand((Activity) getActivityContext()) ? this.mScreenWidth : this.mScreenHeight;
        boolean z = this.mChangePosition;
        if (z) {
            int duration = getDuration();
            int i4 = touchSurfaceMaxMove;
            if (duration <= touchSurfaceMaxMove) {
                i4 = duration;
            }
            int currentPositionWhenAnyTime = (int) ((((i4 * f2) / i2) / this.mSeekRatio) + getCurrentPositionWhenAnyTime());
            this.mSeekTimePosition = currentPositionWhenAnyTime;
            if (currentPositionWhenAnyTime > duration) {
                this.mSeekTimePosition = duration;
            }
            showProgressDialog(f2, CommonUtil.stringForTime(this.mSeekTimePosition), this.mSeekTimePosition, CommonUtil.stringForTime(duration), duration);
            return;
        }
        if (this.mChangeVolume) {
            float f5 = -f3;
            float f6 = i3;
            this.mAudioManager.setStreamVolume(3, this.mGestureDownVolume + ((int) (((this.mAudioManager.getStreamMaxVolume(3) * f5) * 3.0f) / f6)), 0);
            showVolumeDialog(-f5, (int) ((((3.0f * f5) * 100.0f) / f6) + ((this.mGestureDownVolume * 100) / r11)));
            return;
        }
        if (z || !this.mBrightness || Math.abs(f3) <= this.mThreshold) {
            return;
        }
        onBrightnessSlide((-f3) / i3);
        this.mDownY = f4;
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer
    public void updateStartImage() {
        super.updateStartImage();
        ImageView imageView = this.playerImage;
        if (imageView != null) {
            int i2 = this.mCurrentState;
            if (i2 == 2) {
                imageView.setImageResource(R.drawable.ic_media_player);
            } else if (i2 == 7) {
                imageView.setImageResource(R.drawable.good_video_play);
            } else {
                imageView.setImageResource(R.drawable.ic_media_player);
            }
        }
    }

    public void updateVoiceStatus() {
        if (this.btn_voice != null) {
            try {
                this.btn_voice.setSelected(this.mAudioManager.getStreamVolume(3) > 0);
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }

    public FullPlayerView(Context context) {
        super(context);
        this.isHorizontal = true;
        this.speeds = new ArrayList<Speed>() { // from class: com.jbzd.media.movecartoons.view.video.FullPlayerView.2
            {
                add(new Speed(2.0f, "2倍"));
                add(new Speed(1.5f, "1.5倍"));
                add(new Speed(1.0f, "1倍"));
                add(new Speed(0.75f, "0.75倍"));
                add(new Speed(0.5f, "0.5倍"));
            }
        };
        this.speedAdapter = new SpeedAdapter(this.speeds);
        this.hideTopLayoutWhenSmall = false;
        this.visibility = true;
        this.curr = 0;
    }

    public FullPlayerView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.isHorizontal = true;
        this.speeds = new ArrayList<Speed>() { // from class: com.jbzd.media.movecartoons.view.video.FullPlayerView.2
            {
                add(new Speed(2.0f, "2倍"));
                add(new Speed(1.5f, "1.5倍"));
                add(new Speed(1.0f, "1倍"));
                add(new Speed(0.75f, "0.75倍"));
                add(new Speed(0.5f, "0.5倍"));
            }
        };
        this.speedAdapter = new SpeedAdapter(this.speeds);
        this.hideTopLayoutWhenSmall = false;
        this.visibility = true;
        this.curr = 0;
    }
}
