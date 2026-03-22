package com.shuyu.gsyvideoplayer.video;

import android.R;
import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.SeekBar;
import android.widget.TextView;
import com.shuyu.gsyvideoplayer.R$color;
import com.shuyu.gsyvideoplayer.R$drawable;
import com.shuyu.gsyvideoplayer.R$id;
import com.shuyu.gsyvideoplayer.R$layout;
import com.shuyu.gsyvideoplayer.utils.CommonUtil;
import com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer;
import com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p362y.p363a.C2918a;

/* loaded from: classes2.dex */
public class GSYADVideoPlayer extends StandardGSYVideoPlayer {
    public boolean isFirstPrepared;
    public TextView mADTime;
    public View mJumpAd;

    public GSYADVideoPlayer(Context context, Boolean bool) {
        super(context, bool);
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public boolean backFromFull(Context context) {
        return C2918a.m3389b(context);
    }

    public void changeAdUIState() {
        View view = this.mJumpAd;
        if (view != null) {
            view.setVisibility(this.isFirstPrepared ? 0 : 8);
        }
        TextView textView = this.mADTime;
        if (textView != null) {
            textView.setVisibility(this.isFirstPrepared ? 0 : 8);
        }
        if (this.mBottomContainer != null) {
            this.mBottomContainer.setBackgroundColor(this.isFirstPrepared ? 0 : getContext().getResources().getColor(R$color.bottom_container_bg));
        }
        TextView textView2 = this.mCurrentTimeTextView;
        if (textView2 != null) {
            textView2.setVisibility(this.isFirstPrepared ? 4 : 0);
        }
        TextView textView3 = this.mTotalTimeTextView;
        if (textView3 != null) {
            textView3.setVisibility(this.isFirstPrepared ? 4 : 0);
        }
        SeekBar seekBar = this.mProgressBar;
        if (seekBar != null) {
            seekBar.setVisibility(this.isFirstPrepared ? 4 : 0);
            this.mProgressBar.setEnabled(!this.isFirstPrepared);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer
    public void cloneParams(GSYBaseVideoPlayer gSYBaseVideoPlayer, GSYBaseVideoPlayer gSYBaseVideoPlayer2) {
        super.cloneParams(gSYBaseVideoPlayer, gSYBaseVideoPlayer2);
        GSYADVideoPlayer gSYADVideoPlayer = (GSYADVideoPlayer) gSYBaseVideoPlayer2;
        gSYADVideoPlayer.isFirstPrepared = ((GSYADVideoPlayer) gSYBaseVideoPlayer).isFirstPrepared;
        gSYADVideoPlayer.changeAdUIState();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer
    public int getFullId() {
        return C2918a.f7989r;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public GSYVideoViewBridge getGSYVideoManager() {
        C2918a m3390c = C2918a.m3390c();
        Context applicationContext = getContext().getApplicationContext();
        Objects.requireNonNull(m3390c);
        m3390c.f7991a = applicationContext.getApplicationContext();
        return C2918a.m3390c();
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public int getLayoutId() {
        return R$layout.video_layout_ad;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer
    public int getSmallId() {
        return C2918a.f7988q;
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void hideAllWidget() {
        if (this.isFirstPrepared) {
            return;
        }
        super.hideAllWidget();
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public void init(Context context) {
        super.init(context);
        this.mJumpAd = findViewById(R$id.jump_ad);
        this.mADTime = (TextView) findViewById(R$id.ad_time);
        View view = this.mJumpAd;
        if (view != null) {
            view.setOnClickListener(new View.OnClickListener() { // from class: com.shuyu.gsyvideoplayer.video.GSYADVideoPlayer.1
                @Override // android.view.View.OnClickListener
                public void onClick(View view2) {
                    if (GSYADVideoPlayer.this.getGSYVideoManager().listener() != null) {
                        GSYADVideoPlayer.this.getGSYVideoManager().listener().onAutoCompletion();
                    }
                }
            });
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, android.view.View.OnClickListener
    public void onClick(View view) {
        if (view.getId() != R$id.start) {
            super.onClick(view);
        } else if (this.mCurrentState == 7) {
            clickStartIcon();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, com.shuyu.gsyvideoplayer.video.base.GSYVideoView, p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onPrepared() {
        super.onPrepared();
        this.isFirstPrepared = true;
        changeAdUIState();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public void release() {
        super.release();
        TextView textView = this.mADTime;
        if (textView != null) {
            textView.setVisibility(8);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public void releaseVideos() {
        C2918a.m3391d();
    }

    public void removeFullWindowViewOnly() {
        ViewGroup viewGroup = (ViewGroup) CommonUtil.scanForActivity(getContext()).findViewById(R.id.content);
        View findViewById = viewGroup.findViewById(getFullId());
        if (findViewById != null && findViewById.getParent() != null) {
            viewGroup.removeView((ViewGroup) findViewById.getParent());
        }
        this.mIfCurrentIsFullscreen = false;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void setProgressAndTime(int i2, int i3, int i4, int i5, boolean z) {
        super.setProgressAndTime(i2, i3, i4, i5, z);
        TextView textView = this.mADTime;
        if (textView == null || i4 <= 0) {
            return;
        }
        StringBuilder m586H = C1499a.m586H("");
        m586H.append((i5 / 1000) - (i4 / 1000));
        textView.setText(m586H.toString());
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void touchDoubleUp() {
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void touchSurfaceMove(float f2, float f3, float f4) {
        if (this.mChangePosition) {
            return;
        }
        super.touchSurfaceMove(f2, f3, f4);
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void touchSurfaceMoveFullLogic(float f2, float f3) {
        int i2 = this.mThreshold;
        if (f2 > i2 || f3 > i2) {
            int screenWidth = CommonUtil.getScreenWidth(getContext());
            if (f2 < this.mThreshold || Math.abs(screenWidth - this.mDownX) <= this.mSeekEndOffset) {
                super.touchSurfaceMoveFullLogic(f2, f3);
            } else {
                this.mChangePosition = true;
                this.mDownPosition = getCurrentPositionWhenPlaying();
            }
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void touchSurfaceUp() {
        if (this.mChangePosition) {
            return;
        }
        super.touchSurfaceUp();
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer
    public void updateStartImage() {
        View view = this.mStartButton;
        if (view == null || !(view instanceof ImageView)) {
            return;
        }
        ImageView imageView = (ImageView) view;
        int i2 = this.mCurrentState;
        if (i2 == 2) {
            imageView.setImageResource(R$drawable.empty_drawable);
        } else if (i2 == 7) {
            imageView.setImageResource(R$drawable.video_click_error_selector);
        } else {
            imageView.setImageResource(R$drawable.empty_drawable);
        }
    }

    public GSYADVideoPlayer(Context context) {
        super(context);
    }

    public GSYADVideoPlayer(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
    }
}
