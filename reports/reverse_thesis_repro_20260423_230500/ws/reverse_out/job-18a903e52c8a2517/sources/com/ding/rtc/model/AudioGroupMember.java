package com.ding.rtc.model;

import com.ding.rtc.DingRtcEngine;

/* JADX INFO: loaded from: classes.dex */
public class AudioGroupMember {
    public String uid;
    public String usrData;

    private AudioGroupMember() {
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public void setUsrData(String usrData) {
        this.usrData = usrData;
    }

    public DingRtcEngine.DingRtcAudioGroupMember convert() {
        DingRtcEngine.DingRtcAudioGroupMember member = new DingRtcEngine.DingRtcAudioGroupMember();
        member.uid = this.uid;
        member.usrData = this.usrData;
        return member;
    }
}
