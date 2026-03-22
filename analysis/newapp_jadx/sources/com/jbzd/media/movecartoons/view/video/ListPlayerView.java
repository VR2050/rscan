package com.jbzd.media.movecartoons.view.video;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.widget.ImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public class ListPlayerView extends HomePlayerView {
    private View layout_bottom;

    public ListPlayerView(Context context, Boolean bool) {
        super(context, bool);
    }

    @Override // com.jbzd.media.movecartoons.view.video.HomePlayerView, com.jbzd.media.movecartoons.view.video.FullPlayerView, com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public int getLayoutId() {
        return R.layout.list_video_player;
    }

    @Override // com.jbzd.media.movecartoons.view.video.HomePlayerView, com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void hideAllWidget() {
        super.hideAllWidget();
        setViewShowState(this.mBottomContainer, 0);
        setViewShowState(this.mBottomProgressBar, 0);
    }

    @Override // com.jbzd.media.movecartoons.view.video.HomePlayerView, com.jbzd.media.movecartoons.view.video.FullPlayerView, com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public void init(Context context) {
        super.init(context);
        this.layout_bottom = findViewById(R.id.layout_bottom);
        if (isVerticalVideo()) {
            this.layout_bottom.setPadding(0, 0, 0, 100);
        } else {
            this.layout_bottom.setPadding(120, 0, 120, 40);
        }
    }

    @Override // com.jbzd.media.movecartoons.view.video.HomePlayerView, com.jbzd.media.movecartoons.view.video.FullPlayerView
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

    public ListPlayerView(Context context) {
        super(context);
    }

    public ListPlayerView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
    }
}
