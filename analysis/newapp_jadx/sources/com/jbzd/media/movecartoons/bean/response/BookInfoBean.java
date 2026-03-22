package com.jbzd.media.movecartoons.bean.response;

import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import java.util.List;

/* loaded from: classes2.dex */
public class BookInfoBean {
    private List<AdBean> ads;
    private InfoBean info;

    public List<AdBean> getAds() {
        return this.ads;
    }

    public InfoBean getInfo() {
        return this.info;
    }

    public void setAds(List<AdBean> list) {
        this.ads = list;
    }

    public void setInfo(InfoBean infoBean) {
        this.info = infoBean;
    }
}
