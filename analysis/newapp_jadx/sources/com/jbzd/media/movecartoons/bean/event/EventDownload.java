package com.jbzd.media.movecartoons.bean.event;

import com.jbzd.media.movecartoons.bean.response.DownloadVideoInfo;

/* loaded from: classes2.dex */
public class EventDownload {
    private DownloadVideoInfo downloadVideoInfo;

    public EventDownload(DownloadVideoInfo downloadVideoInfo) {
        this.downloadVideoInfo = downloadVideoInfo;
    }

    public DownloadVideoInfo getDownloadVideoInfo() {
        return this.downloadVideoInfo;
    }

    public void setDownloadVideoInfo(DownloadVideoInfo downloadVideoInfo) {
        this.downloadVideoInfo = downloadVideoInfo;
    }
}
