package com.lljjcoder.style.citypickerview;

import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.PopupWindow;
import android.widget.RelativeLayout;
import android.widget.TextView;
import com.lljjcoder.Interface.OnCityItemClickListener;
import com.lljjcoder.bean.CityBean;
import com.lljjcoder.bean.DistrictBean;
import com.lljjcoder.bean.ProvinceBean;
import com.lljjcoder.citywheel.CityConfig;
import com.lljjcoder.citywheel.CityParseHelper;
import com.lljjcoder.style.citylist.Toast.ToastUtils;
import com.lljjcoder.style.citypickerview.widget.CanShow;
import com.lljjcoder.style.citypickerview.widget.wheel.OnWheelChangedListener;
import com.lljjcoder.style.citypickerview.widget.wheel.WheelView;
import com.lljjcoder.style.citypickerview.widget.wheel.adapters.ArrayWheelAdapter;
import com.lljjcoder.utils.utils;
import java.util.ArrayList;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class CityPickerView implements CanShow, OnWheelChangedListener {
    private String TAG = "citypicker_log";
    private CityConfig config;
    private Context context;
    private OnCityItemClickListener mBaseListener;
    private RelativeLayout mRelativeTitleBg;
    private TextView mTvCancel;
    private TextView mTvOK;
    private TextView mTvTitle;
    private WheelView mViewCity;
    private WheelView mViewDistrict;
    private WheelView mViewProvince;
    private CityParseHelper parseHelper;
    private View popview;
    private PopupWindow popwindow;
    private List<ProvinceBean> proArra;

    /* JADX WARN: Multi-variable type inference failed */
    private List<ProvinceBean> getProArrData(List<ProvinceBean> list) {
        ArrayList arrayList = new ArrayList();
        for (int i2 = 0; i2 < list.size(); i2++) {
            arrayList.add(list.get(i2));
        }
        if (!this.config.isShowGAT()) {
            arrayList.remove(arrayList.size() - 1);
            arrayList.remove(arrayList.size() - 1);
            arrayList.remove(arrayList.size() - 1);
        }
        this.proArra = new ArrayList();
        for (int i3 = 0; i3 < arrayList.size(); i3++) {
            this.proArra.add(arrayList.get(i3));
        }
        return this.proArra;
    }

    private void initCityPickerPopwindow() {
        if (this.config == null) {
            throw new IllegalArgumentException("please set config first...");
        }
        if (this.parseHelper == null) {
            this.parseHelper = new CityParseHelper();
        }
        if (this.parseHelper.getProvinceBeanArrayList().isEmpty()) {
            ToastUtils.showLongToast(this.context, "请在Activity中增加init操作");
            return;
        }
        View inflate = LayoutInflater.from(this.context).inflate(C3949R.layout.pop_citypicker, (ViewGroup) null);
        this.popview = inflate;
        this.mViewProvince = (WheelView) inflate.findViewById(C3949R.id.id_province);
        this.mViewCity = (WheelView) this.popview.findViewById(C3949R.id.id_city);
        this.mViewDistrict = (WheelView) this.popview.findViewById(C3949R.id.id_district);
        this.mRelativeTitleBg = (RelativeLayout) this.popview.findViewById(C3949R.id.rl_title);
        this.mTvOK = (TextView) this.popview.findViewById(C3949R.id.tv_confirm);
        this.mTvTitle = (TextView) this.popview.findViewById(C3949R.id.tv_title);
        this.mTvCancel = (TextView) this.popview.findViewById(C3949R.id.tv_cancel);
        PopupWindow popupWindow = new PopupWindow(this.popview, -1, -2);
        this.popwindow = popupWindow;
        popupWindow.setAnimationStyle(C3949R.style.AnimBottom);
        this.popwindow.setBackgroundDrawable(new ColorDrawable());
        this.popwindow.setTouchable(true);
        this.popwindow.setOutsideTouchable(false);
        this.popwindow.setFocusable(true);
        this.popwindow.setOnDismissListener(new PopupWindow.OnDismissListener() { // from class: com.lljjcoder.style.citypickerview.CityPickerView.1
            @Override // android.widget.PopupWindow.OnDismissListener
            public void onDismiss() {
                if (CityPickerView.this.config.isShowBackground()) {
                    utils.setBackgroundAlpha(CityPickerView.this.context, 1.0f);
                }
            }
        });
        if (!TextUtils.isEmpty(this.config.getTitleBackgroundColorStr())) {
            if (this.config.getTitleBackgroundColorStr().startsWith("#")) {
                this.mRelativeTitleBg.setBackgroundColor(Color.parseColor(this.config.getTitleBackgroundColorStr()));
            } else {
                RelativeLayout relativeLayout = this.mRelativeTitleBg;
                StringBuilder m586H = C1499a.m586H("#");
                m586H.append(this.config.getTitleBackgroundColorStr());
                relativeLayout.setBackgroundColor(Color.parseColor(m586H.toString()));
            }
        }
        if (!TextUtils.isEmpty(this.config.getTitle())) {
            this.mTvTitle.setText(this.config.getTitle());
        }
        if (this.config.getTitleTextSize() > 0) {
            this.mTvTitle.setTextSize(this.config.getTitleTextSize());
        }
        if (!TextUtils.isEmpty(this.config.getTitleTextColorStr())) {
            if (this.config.getTitleTextColorStr().startsWith("#")) {
                this.mTvTitle.setTextColor(Color.parseColor(this.config.getTitleTextColorStr()));
            } else {
                TextView textView = this.mTvTitle;
                StringBuilder m586H2 = C1499a.m586H("#");
                m586H2.append(this.config.getTitleTextColorStr());
                textView.setTextColor(Color.parseColor(m586H2.toString()));
            }
        }
        if (!TextUtils.isEmpty(this.config.getConfirmTextColorStr())) {
            if (this.config.getConfirmTextColorStr().startsWith("#")) {
                this.mTvOK.setTextColor(Color.parseColor(this.config.getConfirmTextColorStr()));
            } else {
                TextView textView2 = this.mTvOK;
                StringBuilder m586H3 = C1499a.m586H("#");
                m586H3.append(this.config.getConfirmTextColorStr());
                textView2.setTextColor(Color.parseColor(m586H3.toString()));
            }
        }
        if (!TextUtils.isEmpty(this.config.getConfirmText())) {
            this.mTvOK.setText(this.config.getConfirmText());
        }
        if (this.config.getConfirmTextSize() > 0) {
            this.mTvOK.setTextSize(this.config.getConfirmTextSize());
        }
        if (!TextUtils.isEmpty(this.config.getCancelTextColorStr())) {
            if (this.config.getCancelTextColorStr().startsWith("#")) {
                this.mTvCancel.setTextColor(Color.parseColor(this.config.getCancelTextColorStr()));
            } else {
                TextView textView3 = this.mTvCancel;
                StringBuilder m586H4 = C1499a.m586H("#");
                m586H4.append(this.config.getCancelTextColorStr());
                textView3.setTextColor(Color.parseColor(m586H4.toString()));
            }
        }
        if (!TextUtils.isEmpty(this.config.getCancelText())) {
            this.mTvCancel.setText(this.config.getCancelText());
        }
        if (this.config.getCancelTextSize() > 0) {
            this.mTvCancel.setTextSize(this.config.getCancelTextSize());
        }
        if (this.config.getWheelType() == CityConfig.WheelType.PRO) {
            this.mViewCity.setVisibility(8);
            this.mViewDistrict.setVisibility(8);
        } else if (this.config.getWheelType() == CityConfig.WheelType.PRO_CITY) {
            this.mViewDistrict.setVisibility(8);
        } else {
            this.mViewProvince.setVisibility(0);
            this.mViewCity.setVisibility(0);
            this.mViewDistrict.setVisibility(0);
        }
        this.mViewProvince.addChangingListener(this);
        this.mViewCity.addChangingListener(this);
        this.mViewDistrict.addChangingListener(this);
        this.mTvCancel.setOnClickListener(new View.OnClickListener() { // from class: com.lljjcoder.style.citypickerview.CityPickerView.2
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                CityPickerView.this.mBaseListener.onCancel();
                CityPickerView.this.hide();
            }
        });
        this.mTvOK.setOnClickListener(new View.OnClickListener() { // from class: com.lljjcoder.style.citypickerview.CityPickerView.3
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (CityPickerView.this.parseHelper == null) {
                    CityPickerView.this.mBaseListener.onSelected(new ProvinceBean(), new CityBean(), new DistrictBean());
                } else if (CityPickerView.this.config.getWheelType() == CityConfig.WheelType.PRO) {
                    CityPickerView.this.mBaseListener.onSelected(CityPickerView.this.parseHelper.getProvinceBean(), new CityBean(), new DistrictBean());
                } else if (CityPickerView.this.config.getWheelType() == CityConfig.WheelType.PRO_CITY) {
                    CityPickerView.this.mBaseListener.onSelected(CityPickerView.this.parseHelper.getProvinceBean(), CityPickerView.this.parseHelper.getCityBean(), new DistrictBean());
                } else {
                    CityPickerView.this.mBaseListener.onSelected(CityPickerView.this.parseHelper.getProvinceBean(), CityPickerView.this.parseHelper.getCityBean(), CityPickerView.this.parseHelper.getDistrictBean());
                }
                CityPickerView.this.hide();
            }
        });
        setUpData();
        CityConfig cityConfig = this.config;
        if (cityConfig == null || !cityConfig.isShowBackground()) {
            return;
        }
        utils.setBackgroundAlpha(this.context, 0.5f);
    }

    private void setUpData() {
        int i2;
        CityParseHelper cityParseHelper = this.parseHelper;
        if (cityParseHelper == null || this.config == null) {
            return;
        }
        getProArrData(cityParseHelper.getProvinceBeenArray());
        if (!TextUtils.isEmpty(this.config.getDefaultProvinceName()) && this.proArra.size() > 0) {
            i2 = 0;
            while (i2 < this.proArra.size()) {
                if (this.proArra.get(i2).getName().equals(this.config.getDefaultProvinceName())) {
                    break;
                } else {
                    i2++;
                }
            }
        }
        i2 = -1;
        ArrayWheelAdapter arrayWheelAdapter = new ArrayWheelAdapter(this.context, this.proArra);
        this.mViewProvince.setViewAdapter(arrayWheelAdapter);
        Integer customItemLayout = this.config.getCustomItemLayout();
        Integer num = CityConfig.NONE;
        if (customItemLayout == num || this.config.getCustomItemTextViewId() == num) {
            arrayWheelAdapter.setItemResource(C3949R.layout.default_item_city);
            arrayWheelAdapter.setItemTextResource(C3949R.id.default_item_city_name_tv);
        } else {
            arrayWheelAdapter.setItemResource(this.config.getCustomItemLayout().intValue());
            arrayWheelAdapter.setItemTextResource(this.config.getCustomItemTextViewId().intValue());
        }
        if (-1 != i2) {
            this.mViewProvince.setCurrentItem(i2);
        }
        this.mViewProvince.setVisibleItems(this.config.getVisibleItems());
        this.mViewCity.setVisibleItems(this.config.getVisibleItems());
        this.mViewDistrict.setVisibleItems(this.config.getVisibleItems());
        this.mViewProvince.setCyclic(this.config.isProvinceCyclic());
        this.mViewCity.setCyclic(this.config.isCityCyclic());
        this.mViewDistrict.setCyclic(this.config.isDistrictCyclic());
        this.mViewProvince.setDrawShadows(this.config.isDrawShadows());
        this.mViewCity.setDrawShadows(this.config.isDrawShadows());
        this.mViewDistrict.setDrawShadows(this.config.isDrawShadows());
        this.mViewProvince.setLineColorStr(this.config.getLineColor());
        this.mViewProvince.setLineWidth(this.config.getLineHeigh());
        this.mViewCity.setLineColorStr(this.config.getLineColor());
        this.mViewCity.setLineWidth(this.config.getLineHeigh());
        this.mViewDistrict.setLineColorStr(this.config.getLineColor());
        this.mViewDistrict.setLineWidth(this.config.getLineHeigh());
        updateCities();
        updateAreas();
    }

    private void updateAreas() {
        int i2;
        int currentItem = this.mViewCity.getCurrentItem();
        if (this.parseHelper.getPro_CityMap() == null || this.parseHelper.getCity_DisMap() == null) {
            return;
        }
        if (this.config.getWheelType() == CityConfig.WheelType.PRO_CITY || this.config.getWheelType() == CityConfig.WheelType.PRO_CITY_DIS) {
            CityBean cityBean = this.parseHelper.getPro_CityMap().get(this.parseHelper.getProvinceBean().getName()).get(currentItem);
            this.parseHelper.setCityBean(cityBean);
            if (this.config.getWheelType() == CityConfig.WheelType.PRO_CITY_DIS) {
                List<DistrictBean> list = this.parseHelper.getCity_DisMap().get(this.parseHelper.getProvinceBean().getName() + cityBean.getName());
                if (list == null) {
                    return;
                }
                if (!TextUtils.isEmpty(this.config.getDefaultDistrict()) && list.size() > 0) {
                    i2 = 0;
                    while (i2 < list.size()) {
                        if (this.config.getDefaultDistrict().equals(list.get(i2).getName())) {
                            break;
                        } else {
                            i2++;
                        }
                    }
                }
                i2 = -1;
                ArrayWheelAdapter arrayWheelAdapter = new ArrayWheelAdapter(this.context, list);
                Integer customItemLayout = this.config.getCustomItemLayout();
                Integer num = CityConfig.NONE;
                if (customItemLayout == num || this.config.getCustomItemTextViewId() == num) {
                    arrayWheelAdapter.setItemResource(C3949R.layout.default_item_city);
                    arrayWheelAdapter.setItemTextResource(C3949R.id.default_item_city_name_tv);
                } else {
                    arrayWheelAdapter.setItemResource(this.config.getCustomItemLayout().intValue());
                    arrayWheelAdapter.setItemTextResource(this.config.getCustomItemTextViewId().intValue());
                }
                this.mViewDistrict.setViewAdapter(arrayWheelAdapter);
                DistrictBean districtBean = null;
                if (this.parseHelper.getDisMap() == null) {
                    return;
                }
                if (-1 != i2) {
                    this.mViewDistrict.setCurrentItem(i2);
                    districtBean = this.parseHelper.getDisMap().get(this.parseHelper.getProvinceBean().getName() + cityBean.getName() + this.config.getDefaultDistrict());
                } else {
                    this.mViewDistrict.setCurrentItem(0);
                    if (list.size() > 0) {
                        districtBean = list.get(0);
                    }
                }
                this.parseHelper.setDistrictBean(districtBean);
            }
        }
    }

    private void updateCities() {
        List<CityBean> list;
        int i2;
        if (this.parseHelper == null || this.config == null) {
            return;
        }
        ProvinceBean provinceBean = this.proArra.get(this.mViewProvince.getCurrentItem());
        this.parseHelper.setProvinceBean(provinceBean);
        if (this.parseHelper.getPro_CityMap() == null || (list = this.parseHelper.getPro_CityMap().get(provinceBean.getName())) == null) {
            return;
        }
        if (!TextUtils.isEmpty(this.config.getDefaultCityName()) && list.size() > 0) {
            i2 = 0;
            while (i2 < list.size()) {
                if (this.config.getDefaultCityName().equals(list.get(i2).getName())) {
                    break;
                } else {
                    i2++;
                }
            }
        }
        i2 = -1;
        ArrayWheelAdapter arrayWheelAdapter = new ArrayWheelAdapter(this.context, list);
        Integer customItemLayout = this.config.getCustomItemLayout();
        Integer num = CityConfig.NONE;
        if (customItemLayout == num || this.config.getCustomItemTextViewId() == num) {
            arrayWheelAdapter.setItemResource(C3949R.layout.default_item_city);
            arrayWheelAdapter.setItemTextResource(C3949R.id.default_item_city_name_tv);
        } else {
            arrayWheelAdapter.setItemResource(this.config.getCustomItemLayout().intValue());
            arrayWheelAdapter.setItemTextResource(this.config.getCustomItemTextViewId().intValue());
        }
        this.mViewCity.setViewAdapter(arrayWheelAdapter);
        if (-1 != i2) {
            this.mViewCity.setCurrentItem(i2);
        } else {
            this.mViewCity.setCurrentItem(0);
        }
        updateAreas();
    }

    @Override // com.lljjcoder.style.citypickerview.widget.CanShow
    public void hide() {
        if (isShow()) {
            this.popwindow.dismiss();
        }
    }

    public void init(Context context) {
        this.context = context;
        CityParseHelper cityParseHelper = new CityParseHelper();
        this.parseHelper = cityParseHelper;
        if (cityParseHelper.getProvinceBeanArrayList().isEmpty()) {
            this.parseHelper.initData(context);
        }
    }

    @Override // com.lljjcoder.style.citypickerview.widget.CanShow
    public boolean isShow() {
        return this.popwindow.isShowing();
    }

    @Override // com.lljjcoder.style.citypickerview.widget.wheel.OnWheelChangedListener
    public void onChanged(WheelView wheelView, int i2, int i3) {
        CityParseHelper cityParseHelper;
        if (wheelView == this.mViewProvince) {
            updateCities();
            return;
        }
        if (wheelView == this.mViewCity) {
            updateAreas();
            return;
        }
        if (wheelView != this.mViewDistrict || (cityParseHelper = this.parseHelper) == null || cityParseHelper.getCity_DisMap() == null) {
            return;
        }
        this.parseHelper.setDistrictBean(this.parseHelper.getCity_DisMap().get(this.parseHelper.getProvinceBean().getName() + this.parseHelper.getCityBean().getName()).get(i3));
    }

    public void setConfig(CityConfig cityConfig) {
        this.config = cityConfig;
    }

    public void setOnCityItemClickListener(OnCityItemClickListener onCityItemClickListener) {
        this.mBaseListener = onCityItemClickListener;
    }

    public void showCityPicker() {
        initCityPickerPopwindow();
        if (isShow()) {
            return;
        }
        this.popwindow.showAtLocation(this.popview, 80, 0, 0);
    }
}
