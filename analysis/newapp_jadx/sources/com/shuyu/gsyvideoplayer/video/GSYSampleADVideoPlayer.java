package com.shuyu.gsyvideoplayer.video;

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
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p362y.p363a.p367g.C2933b;

/* loaded from: classes2.dex */
public class GSYSampleADVideoPlayer extends ListGSYVideoPlayer {
    public boolean isAdModel;
    public boolean isFirstPrepared;
    public TextView mADTime;
    public View mJumpAd;
    public ViewGroup mWidgetContainer;

    public static class GSYADVideoModel extends C2933b {
        public static int TYPE_AD = 1;
        public static int TYPE_NORMAL;
        private boolean isSkip;
        private int mType;

        public GSYADVideoModel(String str, String str2, int i2) {
            this(str, str2, i2, false);
        }

        public int getType() {
            return this.mType;
        }

        public boolean isSkip() {
            return this.isSkip;
        }

        public void setSkip(boolean z) {
            this.isSkip = z;
        }

        public void setType(int i2) {
            this.mType = i2;
        }

        public GSYADVideoModel(String str, String str2, int i2, boolean z) {
            super(str, str2);
            this.mType = TYPE_NORMAL;
            this.mType = i2;
            this.isSkip = z;
        }
    }

    public GSYSampleADVideoPlayer(Context context, Boolean bool) {
        super(context, bool);
        this.isAdModel = false;
        this.isFirstPrepared = false;
    }

    public void changeAdUIState() {
        View view = this.mJumpAd;
        if (view != null) {
            view.setVisibility((this.isFirstPrepared && this.isAdModel) ? 0 : 8);
        }
        TextView textView = this.mADTime;
        if (textView != null) {
            textView.setVisibility((this.isFirstPrepared && this.isAdModel) ? 0 : 8);
        }
        ViewGroup viewGroup = this.mWidgetContainer;
        if (viewGroup != null) {
            viewGroup.setVisibility((this.isFirstPrepared && this.isAdModel) ? 8 : 0);
        }
        if (this.mBottomContainer != null) {
            this.mBottomContainer.setBackgroundColor((this.isFirstPrepared && this.isAdModel) ? 0 : getContext().getResources().getColor(R$color.bottom_container_bg));
        }
        TextView textView2 = this.mCurrentTimeTextView;
        if (textView2 != null) {
            textView2.setVisibility((this.isFirstPrepared && this.isAdModel) ? 4 : 0);
        }
        TextView textView3 = this.mTotalTimeTextView;
        if (textView3 != null) {
            textView3.setVisibility((this.isFirstPrepared && this.isAdModel) ? 4 : 0);
        }
        SeekBar seekBar = this.mProgressBar;
        if (seekBar != null) {
            seekBar.setVisibility((this.isFirstPrepared && this.isAdModel) ? 4 : 0);
            this.mProgressBar.setEnabled((this.isFirstPrepared && this.isAdModel) ? false : true);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.ListGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer
    public void cloneParams(GSYBaseVideoPlayer gSYBaseVideoPlayer, GSYBaseVideoPlayer gSYBaseVideoPlayer2) {
        super.cloneParams(gSYBaseVideoPlayer, gSYBaseVideoPlayer2);
        GSYSampleADVideoPlayer gSYSampleADVideoPlayer = (GSYSampleADVideoPlayer) gSYBaseVideoPlayer;
        GSYSampleADVideoPlayer gSYSampleADVideoPlayer2 = (GSYSampleADVideoPlayer) gSYBaseVideoPlayer2;
        gSYSampleADVideoPlayer2.isAdModel = gSYSampleADVideoPlayer.isAdModel;
        gSYSampleADVideoPlayer2.isFirstPrepared = gSYSampleADVideoPlayer.isFirstPrepared;
        gSYSampleADVideoPlayer2.changeAdUIState();
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public int getLayoutId() {
        return R$layout.video_layout_sample_ad;
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void hideAllWidget() {
        if (this.isFirstPrepared && this.isAdModel) {
            return;
        }
        super.hideAllWidget();
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public void init(Context context) {
        super.init(context);
        this.mJumpAd = findViewById(R$id.jump_ad);
        this.mADTime = (TextView) findViewById(R$id.ad_time);
        this.mWidgetContainer = (ViewGroup) findViewById(R$id.widget_container);
        View view = this.mJumpAd;
        if (view != null) {
            view.setOnClickListener(new View.OnClickListener() { // from class: com.shuyu.gsyvideoplayer.video.GSYSampleADVideoPlayer.1
                @Override // android.view.View.OnClickListener
                public void onClick(View view2) {
                    GSYSampleADVideoPlayer.this.playNext();
                }
            });
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.ListGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, com.shuyu.gsyvideoplayer.video.base.GSYVideoView, p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onPrepared() {
        super.onPrepared();
        this.isFirstPrepared = true;
        changeAdUIState();
    }

    public boolean setAdUp(ArrayList<GSYADVideoModel> arrayList, boolean z, int i2) {
        return setUp((ArrayList) arrayList.clone(), z, i2);
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

    @Override // com.shuyu.gsyvideoplayer.video.ListGSYVideoPlayer
    public boolean setUp(List<C2933b> list, boolean z, int i2) {
        return setUp(list, z, i2, (File) null);
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void touchDoubleUp() {
        if (this.isAdModel) {
            return;
        }
        super.touchDoubleUp();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void touchSurfaceMove(float f2, float f3, float f4) {
        if (this.mChangePosition && this.isAdModel) {
            return;
        }
        super.touchSurfaceMove(f2, f3, f4);
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void touchSurfaceMoveFullLogic(float f2, float f3) {
        int i2 = this.mThreshold;
        if (f2 > i2 || f3 > i2) {
            int screenWidth = CommonUtil.getScreenWidth(getContext());
            if (!this.isAdModel || f2 < this.mThreshold || Math.abs(screenWidth - this.mDownX) <= this.mSeekEndOffset) {
                super.touchSurfaceMoveFullLogic(f2, f3);
            } else {
                this.mChangePosition = true;
                this.mDownPosition = getCurrentPositionWhenPlaying();
            }
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void touchSurfaceUp() {
        if (this.mChangePosition && this.isAdModel) {
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
            imageView.setImageResource(R$drawable.video_click_pause_selector);
        } else if (i2 == 7) {
            imageView.setImageResource(R$drawable.video_click_play_selector);
        } else {
            imageView.setImageResource(R$drawable.video_click_play_selector);
        }
    }

    public boolean setAdUp(ArrayList<GSYADVideoModel> arrayList, boolean z, int i2, File file) {
        return setUp((ArrayList) arrayList.clone(), z, i2, file);
    }

    @Override // com.shuyu.gsyvideoplayer.video.ListGSYVideoPlayer
    public boolean setUp(List<C2933b> list, boolean z, int i2, File file) {
        return setUp(list, z, i2, file, new HashMap());
    }

    public boolean setAdUp(ArrayList<GSYADVideoModel> arrayList, boolean z, int i2, File file, Map<String, String> map) {
        return setUp((ArrayList) arrayList.clone(), z, i2, file, map);
    }

    @Override // com.shuyu.gsyvideoplayer.video.ListGSYVideoPlayer
    public boolean setUp(List<C2933b> list, boolean z, int i2, File file, Map<String, String> map) {
        return setUp(list, z, i2, file, map, true);
    }

    public GSYSampleADVideoPlayer(Context context) {
        super(context);
        this.isAdModel = false;
        this.isFirstPrepared = false;
    }

    @Override // com.shuyu.gsyvideoplayer.video.ListGSYVideoPlayer
    public boolean setUp(List<C2933b> list, boolean z, int i2, File file, Map<String, String> map, boolean z2) {
        C2933b c2933b = list.get(i2);
        if (c2933b instanceof GSYADVideoModel) {
            GSYADVideoModel gSYADVideoModel = (GSYADVideoModel) c2933b;
            if (gSYADVideoModel.isSkip() && i2 < list.size() - 1) {
                return setUp(list, z, i2 + 1, file, map, z2);
            }
            this.isAdModel = gSYADVideoModel.getType() == GSYADVideoModel.TYPE_AD;
        }
        changeAdUIState();
        return super.setUp(list, z, i2, file, map, z2);
    }

    public GSYSampleADVideoPlayer(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.isAdModel = false;
        this.isFirstPrepared = false;
    }
}
