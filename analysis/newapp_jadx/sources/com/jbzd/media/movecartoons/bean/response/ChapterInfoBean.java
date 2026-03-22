package com.jbzd.media.movecartoons.bean.response;

import java.util.List;

/* loaded from: classes2.dex */
public class ChapterInfoBean {
    private InfoBean info;
    private List<ChapterListBean> list;

    public InfoBean getInfo() {
        return this.info;
    }

    public List<ChapterListBean> getList() {
        return this.list;
    }

    public void setInfo(InfoBean infoBean) {
        this.info = infoBean;
    }

    public void setList(List<ChapterListBean> list) {
        this.list = list;
    }
}
