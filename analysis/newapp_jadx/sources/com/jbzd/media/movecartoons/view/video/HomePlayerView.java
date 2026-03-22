package com.jbzd.media.movecartoons.view.video;

import android.content.Context;
import android.util.AttributeSet;
import android.widget.ImageView;
import com.qnmd.adnnm.da0yzo.R;
import com.shuyu.gsyvideoplayer.utils.Debuger;

/* loaded from: classes2.dex */
public class HomePlayerView extends FullPlayerView {
    public OnToggleClickListener onToggleClickListener;
    public OnToggleClickListener onTouchSurfaceUpListener;

    public interface OnToggleClickListener {
        void onToggleClick();
    }

    public HomePlayerView(Context context, Boolean bool) {
        super(context, bool);
    }

    @Override // com.jbzd.media.movecartoons.view.video.FullPlayerView, com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public int getLayoutId() {
        return R.layout.home_video_player;
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void hideAllWidget() {
        super.hideAllWidget();
        setViewShowState(this.mBottomContainer, 0);
    }

    @Override // com.jbzd.media.movecartoons.view.video.FullPlayerView, com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public void init(Context context) {
        super.init(context);
    }

    public boolean isPlaying() {
        return this.mCurrentState == 2;
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void onClickUiToggle() {
        OnToggleClickListener onToggleClickListener = this.onToggleClickListener;
        if (onToggleClickListener != null) {
            onToggleClickListener.onToggleClick();
        }
    }

    @Override // com.jbzd.media.movecartoons.view.video.FullPlayerView
    public void onPlayStatusChange() {
        if (this.mCurrentState == 5) {
            ImageView imageView = this.playerImage;
            if (imageView != null) {
                imageView.setVisibility(0);
            }
            ImageView imageView2 = this.btn_stop;
            if (imageView2 != null) {
                imageView2.setVisibility(4);
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
            imageView4.setVisibility(0);
        }
    }

    public void pauseToResume() {
        if (this.mCurrentState == 5) {
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
            } catch (Exception e2) {
                e2.printStackTrace();
            }
            setStateAndUi(2);
        }
    }

    public void playToPause() {
        int i2 = this.mCurrentState;
        if (i2 == 2 || i2 == 3 || i2 == 3) {
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
            } else {
                Debuger.printfLog("onClickStop");
                this.mVideoAllCallBack.onClickStop(this.mOriginUrl, this.mTitle, this);
            }
        }
    }

    public void setOnToggleClickListener(OnToggleClickListener onToggleClickListener) {
        this.onToggleClickListener = onToggleClickListener;
    }

    public void setOnTouchSurfaceUpListener(OnToggleClickListener onToggleClickListener) {
        this.onTouchSurfaceUpListener = onToggleClickListener;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void touchSurfaceUp() {
        super.touchSurfaceUp();
        OnToggleClickListener onToggleClickListener = this.onTouchSurfaceUpListener;
        if (onToggleClickListener != null) {
            onToggleClickListener.onToggleClick();
        }
    }

    public HomePlayerView(Context context) {
        super(context);
    }

    public HomePlayerView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
    }
}
