package com.jbzd.media.movecartoons.bean.event;

import com.jbzd.media.movecartoons.bean.response.UploadBean;

/* loaded from: classes2.dex */
public class EventUpload {
    private UploadBean uploadBean;

    public EventUpload(UploadBean uploadBean) {
        this.uploadBean = uploadBean;
    }

    public UploadBean getUploadVideoInfo() {
        return this.uploadBean;
    }

    public void setUploadVideoInfo(UploadBean uploadBean) {
        this.uploadBean = uploadBean;
    }
}
