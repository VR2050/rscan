package com.shuyu.gsyvideoplayer.video.base;

import android.content.Context;
import android.util.AttributeSet;
import java.util.Objects;
import p005b.p362y.p363a.C2920c;

/* loaded from: classes2.dex */
public abstract class GSYVideoPlayer extends GSYBaseVideoPlayer {
    public GSYVideoPlayer(Context context, Boolean bool) {
        super(context, bool);
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public boolean backFromFull(Context context) {
        return C2920c.m3393b(context);
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer
    public int getFullId() {
        return C2920c.f8022r;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public GSYVideoViewBridge getGSYVideoManager() {
        C2920c m3394c = C2920c.m3394c();
        Context applicationContext = getContext().getApplicationContext();
        Objects.requireNonNull(m3394c);
        m3394c.f7991a = applicationContext.getApplicationContext();
        return C2920c.m3394c();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer
    public int getSmallId() {
        return C2920c.f8021q;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public void releaseVideos() {
        C2920c.m3397f();
    }

    public GSYVideoPlayer(Context context) {
        super(context);
    }

    public GSYVideoPlayer(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
    }

    public GSYVideoPlayer(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
    }
}
