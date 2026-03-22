package com.lljjcoder.citywheel;

import android.content.Context;
import com.lljjcoder.Constant;
import com.lljjcoder.bean.CityBean;
import com.lljjcoder.bean.DistrictBean;
import com.lljjcoder.bean.ProvinceBean;
import com.lljjcoder.utils.utils;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.p264d0.C2470a;

/* loaded from: classes2.dex */
public class CityParseHelper {
    private CityBean mCityBean;
    private ArrayList<ArrayList<CityBean>> mCityBeanArrayList;
    private DistrictBean mDistrictBean;
    private ArrayList<ArrayList<ArrayList<DistrictBean>>> mDistrictBeanArrayList;
    private ProvinceBean mProvinceBean;
    private List<ProvinceBean> mProvinceBeenArray;
    private ArrayList<ProvinceBean> mProvinceBeanArrayList = new ArrayList<>();
    private Map<String, List<CityBean>> mPro_CityMap = new HashMap();
    private Map<String, List<DistrictBean>> mCity_DisMap = new HashMap();
    private Map<String, DistrictBean> mDisMap = new HashMap();

    public CityBean getCityBean() {
        return this.mCityBean;
    }

    public ArrayList<ArrayList<CityBean>> getCityBeanArrayList() {
        return this.mCityBeanArrayList;
    }

    public Map<String, List<DistrictBean>> getCity_DisMap() {
        return this.mCity_DisMap;
    }

    public Map<String, DistrictBean> getDisMap() {
        return this.mDisMap;
    }

    public DistrictBean getDistrictBean() {
        return this.mDistrictBean;
    }

    public ArrayList<ArrayList<ArrayList<DistrictBean>>> getDistrictBeanArrayList() {
        return this.mDistrictBeanArrayList;
    }

    public Map<String, List<CityBean>> getPro_CityMap() {
        return this.mPro_CityMap;
    }

    public ProvinceBean getProvinceBean() {
        return this.mProvinceBean;
    }

    public ArrayList<ProvinceBean> getProvinceBeanArrayList() {
        return this.mProvinceBeanArrayList;
    }

    public List<ProvinceBean> getProvinceBeenArray() {
        return this.mProvinceBeenArray;
    }

    public void initData(Context context) {
        ArrayList<DistrictBean> cityList;
        ArrayList<ProvinceBean> arrayList = (ArrayList) new C2480j().m2849c(utils.getJson(context, Constant.CITY_DATA), new C2470a<ArrayList<ProvinceBean>>() { // from class: com.lljjcoder.citywheel.CityParseHelper.1
        }.getType());
        this.mProvinceBeanArrayList = arrayList;
        if (arrayList == null || arrayList.isEmpty()) {
            return;
        }
        this.mCityBeanArrayList = new ArrayList<>(this.mProvinceBeanArrayList.size());
        this.mDistrictBeanArrayList = new ArrayList<>(this.mProvinceBeanArrayList.size());
        ArrayList<ProvinceBean> arrayList2 = this.mProvinceBeanArrayList;
        if (arrayList2 != null && !arrayList2.isEmpty()) {
            ProvinceBean provinceBean = this.mProvinceBeanArrayList.get(0);
            this.mProvinceBean = provinceBean;
            ArrayList<CityBean> cityList2 = provinceBean.getCityList();
            if (cityList2 != null && !cityList2.isEmpty() && cityList2.size() > 0) {
                CityBean cityBean = cityList2.get(0);
                this.mCityBean = cityBean;
                ArrayList<DistrictBean> cityList3 = cityBean.getCityList();
                if (cityList3 != null && !cityList3.isEmpty() && cityList3.size() > 0) {
                    this.mDistrictBean = cityList3.get(0);
                }
            }
        }
        this.mProvinceBeenArray = new ArrayList();
        for (int i2 = 0; i2 < this.mProvinceBeanArrayList.size(); i2++) {
            ProvinceBean provinceBean2 = this.mProvinceBeanArrayList.get(i2);
            ArrayList<CityBean> cityList4 = provinceBean2.getCityList();
            for (int i3 = 0; i3 < cityList4.size() && (cityList = cityList4.get(i3).getCityList()) != null; i3++) {
                for (int i4 = 0; i4 < cityList.size(); i4++) {
                    DistrictBean districtBean = cityList.get(i4);
                    this.mDisMap.put(provinceBean2.getName() + cityList4.get(i3).getName() + cityList.get(i4).getName(), districtBean);
                }
                this.mCity_DisMap.put(provinceBean2.getName() + cityList4.get(i3).getName(), cityList);
            }
            this.mPro_CityMap.put(provinceBean2.getName(), cityList4);
            this.mCityBeanArrayList.add(cityList4);
            ArrayList<ArrayList<DistrictBean>> arrayList3 = new ArrayList<>(cityList4.size());
            for (int i5 = 0; i5 < cityList4.size(); i5++) {
                arrayList3.add(cityList4.get(i5).getCityList());
            }
            this.mDistrictBeanArrayList.add(arrayList3);
            this.mProvinceBeenArray.add(i2, provinceBean2);
        }
    }

    public void setCityBean(CityBean cityBean) {
        this.mCityBean = cityBean;
    }

    public void setCityBeanArrayList(ArrayList<ArrayList<CityBean>> arrayList) {
        this.mCityBeanArrayList = arrayList;
    }

    public void setCity_DisMap(Map<String, List<DistrictBean>> map) {
        this.mCity_DisMap = map;
    }

    public void setDisMap(Map<String, DistrictBean> map) {
        this.mDisMap = map;
    }

    public void setDistrictBean(DistrictBean districtBean) {
        this.mDistrictBean = districtBean;
    }

    public void setDistrictBeanArrayList(ArrayList<ArrayList<ArrayList<DistrictBean>>> arrayList) {
        this.mDistrictBeanArrayList = arrayList;
    }

    public void setPro_CityMap(Map<String, List<CityBean>> map) {
        this.mPro_CityMap = map;
    }

    public void setProvinceBean(ProvinceBean provinceBean) {
        this.mProvinceBean = provinceBean;
    }

    public void setProvinceBeanArrayList(ArrayList<ProvinceBean> arrayList) {
        this.mProvinceBeanArrayList = arrayList;
    }

    public void setProvinceBeenArray(List<ProvinceBean> list) {
        this.mProvinceBeenArray = list;
    }
}
