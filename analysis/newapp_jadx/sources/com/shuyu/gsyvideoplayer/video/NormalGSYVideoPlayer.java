package com.shuyu.gsyvideoplayer.video;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.widget.ImageView;
import com.shuyu.gsyvideoplayer.R$drawable;
import com.shuyu.gsyvideoplayer.R$layout;

/* loaded from: classes2.dex */
public class NormalGSYVideoPlayer extends StandardGSYVideoPlayer {
    public NormalGSYVideoPlayer(Context context, Boolean bool) {
        super(context, bool);
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public int getLayoutId() {
        return R$layout.video_layout_normal;
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer
    public void updateStartImage() {
        View view = this.mStartButton;
        if (view instanceof ImageView) {
            ImageView imageView = (ImageView) view;
            int i2 = this.mCurrentState;
            if (i2 == 2) {
                imageView.setImageResource(R$drawable.video_click_pause_selector);
            } else if (i2 == 7) {
                imageView.setImageResource(R$drawable.video_click_play_selector);
            } else {
                imageView.setImageResource(R$drawable.video_click_play_selector);
            }
        }
    }

    public NormalGSYVideoPlayer(Context context) {
        super(context);
    }

    public NormalGSYVideoPlayer(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
    }
}
