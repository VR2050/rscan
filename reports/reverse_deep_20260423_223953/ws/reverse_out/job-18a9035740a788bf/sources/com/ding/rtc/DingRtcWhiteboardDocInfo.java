package com.ding.rtc;

import com.ding.rtc.api.DingRtcWhiteBoardTypes;

/* JADX INFO: loaded from: classes.dex */
public class DingRtcWhiteboardDocInfo {
    public String creater;
    public String docId;
    public String name;
    public DingRtcWhiteBoardTypes.DingRtcWBDocType type;

    private DingRtcWhiteboardDocInfo() {
    }

    public DingRtcWhiteBoardTypes.DingRtcWBDocType getType() {
        return this.type;
    }

    public void setType(int type) {
        this.type = DingRtcWhiteBoardTypes.DingRtcWBDocType.fromValue(type);
    }

    public String getDocId() {
        return this.docId;
    }

    public void setDocId(String docId) {
        this.docId = docId;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCreater() {
        return this.creater;
    }

    public void setCreater(String creater) {
        this.creater = creater;
    }
}
