package com.lljjcoder.style.citylist.utils;

import android.content.Context;
import com.lljjcoder.Constant;
import com.lljjcoder.style.citylist.bean.CityInfoBean;
import com.lljjcoder.utils.utils;
import java.util.ArrayList;
import java.util.List;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.p264d0.C2470a;

/* loaded from: classes2.dex */
public class CityListLoader {
    public static final String BUNDATA = "bundata";
    private static volatile CityListLoader instance;
    private static List<CityInfoBean> mCityListData = new ArrayList();
    private static List<CityInfoBean> mProListData = new ArrayList();

    private CityListLoader() {
    }

    public static CityListLoader getInstance() {
        if (instance == null) {
            synchronized (CityListLoader.class) {
                if (instance == null) {
                    instance = new CityListLoader();
                }
            }
        }
        return instance;
    }

    public List<CityInfoBean> getCityListData() {
        return mCityListData;
    }

    public List<CityInfoBean> getProListData() {
        return mProListData;
    }

    public void loadCityData(Context context) {
        ArrayList arrayList = (ArrayList) new C2480j().m2849c(utils.getJson(context, Constant.CITY_DATA), new C2470a<ArrayList<CityInfoBean>>() { // from class: com.lljjcoder.style.citylist.utils.CityListLoader.1
        }.getType());
        if (arrayList == null || arrayList.isEmpty()) {
            return;
        }
        for (int i2 = 0; i2 < arrayList.size(); i2++) {
            ArrayList<CityInfoBean> cityList = ((CityInfoBean) arrayList.get(i2)).getCityList();
            for (int i3 = 0; i3 < cityList.size(); i3++) {
                mCityListData.add(cityList.get(i3));
            }
        }
    }

    public void loadProData(Context context) {
        mProListData = (List) new C2480j().m2849c(utils.getJson(context, Constant.CITY_DATA), new C2470a<ArrayList<CityInfoBean>>() { // from class: com.lljjcoder.style.citylist.utils.CityListLoader.2
        }.getType());
    }
}
