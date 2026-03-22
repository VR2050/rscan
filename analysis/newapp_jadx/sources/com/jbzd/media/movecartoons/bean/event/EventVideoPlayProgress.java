package com.jbzd.media.movecartoons.bean.event;

import com.jbzd.media.movecartoons.bean.response.VideoItemBean;

/* loaded from: classes2.dex */
public class EventVideoPlayProgress {
    public int currentPosition;
    public int duration;
    public int progress;
    public int secProgress;
    public VideoItemBean video;

    public EventVideoPlayProgress() {
    }

    public EventVideoPlayProgress(int i2, int i3, int i4, int i5, VideoItemBean videoItemBean) {
        this.progress = i2;
        this.secProgress = i3;
        this.currentPosition = i4;
        this.duration = i5;
        this.video = videoItemBean;
    }
}
