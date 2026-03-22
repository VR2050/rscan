package com.jbzd.media.movecartoons.view.video;

import android.content.Context;
import android.util.AttributeSet;
import com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer;
import kotlin.Metadata;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u000e\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\u0018\u00002\u00020\u0001B\u001d\b\u0016\u0012\b\u0010\u0015\u001a\u0004\u0018\u00010\u0014\u0012\b\u0010\u0016\u001a\u0004\u0018\u00010\u0011¢\u0006\u0004\b\u0017\u0010\u0018B\u0013\b\u0016\u0012\b\u0010\u0015\u001a\u0004\u0018\u00010\u0014¢\u0006\u0004\b\u0017\u0010\u0019B\u001d\b\u0016\u0012\b\u0010\u0015\u001a\u0004\u0018\u00010\u0014\u0012\b\u0010\u001b\u001a\u0004\u0018\u00010\u001a¢\u0006\u0004\b\u0017\u0010\u001cJ\u000f\u0010\u0003\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0005\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0006\u0010\u0004J\u000f\u0010\u0007\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0007\u0010\u0004J\u000f\u0010\b\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\b\u0010\u0004J\u000f\u0010\t\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\t\u0010\u0004J\u000f\u0010\n\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\n\u0010\u0004J\u000f\u0010\u000b\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u000b\u0010\u0004J\u000f\u0010\f\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\f\u0010\u0004J\u000f\u0010\r\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\r\u0010\u0004J\u000f\u0010\u000e\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u000e\u0010\u0004J\u000f\u0010\u000f\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u000f\u0010\u0004J\u000f\u0010\u0010\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0010\u0010\u0004J\u000f\u0010\u0012\u001a\u00020\u0011H\u0014¢\u0006\u0004\b\u0012\u0010\u0013¨\u0006\u001d"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/video/BannerPlayerView;", "Lcom/shuyu/gsyvideoplayer/video/StandardGSYVideoPlayer;", "", "changeUiToPreparingShow", "()V", "changeUiToPlayingShow", "changeUiToPauseShow", "changeUiToNormal", "changeUiToError", "changeUiToCompleteShow", "changeUiToPlayingBufferingShow", "changeUiToPrepareingClear", "changeUiToPlayingClear", "changeUiToPauseClear", "changeUiToPlayingBufferingClear", "changeUiToClear", "changeUiToCompleteClear", "", "isShowNetConfirm", "()Z", "Landroid/content/Context;", "context", "fullFlag", "<init>", "(Landroid/content/Context;Ljava/lang/Boolean;)V", "(Landroid/content/Context;)V", "Landroid/util/AttributeSet;", "attrs", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class BannerPlayerView extends StandardGSYVideoPlayer {
    public BannerPlayerView(@Nullable Context context, @Nullable Boolean bool) {
        super(context, bool);
    }

    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer
    public void changeUiToClear() {
        super.changeUiToClear();
        setViewShowState(this.mBottomContainer, 4);
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer
    public void changeUiToCompleteClear() {
        super.changeUiToCompleteClear();
        setViewShowState(this.mBottomContainer, 4);
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void changeUiToCompleteShow() {
        super.changeUiToCompleteShow();
        setViewShowState(this.mBottomContainer, 4);
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void changeUiToError() {
        super.changeUiToError();
        setViewShowState(this.mBottomContainer, 4);
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void changeUiToNormal() {
        super.changeUiToNormal();
        setViewShowState(this.mBottomContainer, 4);
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer
    public void changeUiToPauseClear() {
        super.changeUiToPauseClear();
        setViewShowState(this.mBottomContainer, 4);
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void changeUiToPauseShow() {
        super.changeUiToPauseShow();
        setViewShowState(this.mBottomContainer, 4);
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer
    public void changeUiToPlayingBufferingClear() {
        super.changeUiToPlayingBufferingClear();
        setViewShowState(this.mBottomContainer, 4);
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void changeUiToPlayingBufferingShow() {
        super.changeUiToPlayingBufferingShow();
        setViewShowState(this.mBottomContainer, 4);
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer
    public void changeUiToPlayingClear() {
        super.changeUiToPlayingClear();
        setViewShowState(this.mBottomContainer, 4);
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void changeUiToPlayingShow() {
        super.changeUiToPlayingShow();
        setViewShowState(this.mBottomContainer, 4);
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer
    public void changeUiToPrepareingClear() {
        super.changeUiToPrepareingClear();
        setViewShowState(this.mBottomContainer, 4);
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void changeUiToPreparingShow() {
        super.changeUiToPreparingShow();
        setViewShowState(this.mBottomContainer, 4);
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public boolean isShowNetConfirm() {
        return false;
    }

    public BannerPlayerView(@Nullable Context context) {
        super(context);
    }

    public BannerPlayerView(@Nullable Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
    }
}
