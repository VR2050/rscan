package com.lljjcoder.style.citylist;

import com.lljjcoder.style.citylist.bean.CityInfoBean;

/* loaded from: classes2.dex */
public class CConfig {
    private static CityInfoBean sCityInfoBean;

    public static CityInfoBean getCitySelected() {
        return sCityInfoBean;
    }

    public static void setCity(CityInfoBean cityInfoBean) {
        sCityInfoBean = cityInfoBean;
    }
}
