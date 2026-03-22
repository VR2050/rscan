package com.lljjcoder.style.citycustome;

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
import com.lljjcoder.Interface.OnCustomCityPickerItemClickListener;
import com.lljjcoder.bean.CustomCityData;
import com.lljjcoder.citywheel.CityConfig;
import com.lljjcoder.citywheel.CustomConfig;
import com.lljjcoder.style.citylist.Toast.ToastUtils;
import com.lljjcoder.style.citypickerview.C3949R;
import com.lljjcoder.style.citypickerview.widget.CanShow;
import com.lljjcoder.style.citypickerview.widget.wheel.OnWheelChangedListener;
import com.lljjcoder.style.citypickerview.widget.wheel.WheelView;
import com.lljjcoder.style.citypickerview.widget.wheel.adapters.ArrayWheelAdapter;
import com.lljjcoder.utils.utils;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class CustomCityPicker implements CanShow, OnWheelChangedListener {
    private CustomConfig config;
    private Context mContext;
    private RelativeLayout mRelativeTitleBg;
    private TextView mTvCancel;
    private TextView mTvOK;
    private TextView mTvTitle;
    private WheelView mViewCity;
    private WheelView mViewDistrict;
    private WheelView mViewProvince;
    private View popview;
    private PopupWindow popwindow;
    private OnCustomCityPickerItemClickListener listener = null;
    private CustomConfig.WheelType type = CustomConfig.WheelType.PRO_CITY_DIS;

    public CustomCityPicker(Context context) {
        this.mContext = context;
    }

    private void initView() {
        if (this.config == null) {
            ToastUtils.showLongToast(this.mContext, "请设置相关的config");
            return;
        }
        View inflate = LayoutInflater.from(this.mContext).inflate(C3949R.layout.pop_citypicker, (ViewGroup) null);
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
        this.popwindow.setOnDismissListener(new PopupWindow.OnDismissListener() { // from class: com.lljjcoder.style.citycustome.CustomCityPicker.1
            @Override // android.widget.PopupWindow.OnDismissListener
            public void onDismiss() {
                if (CustomCityPicker.this.config.isShowBackground()) {
                    utils.setBackgroundAlpha(CustomCityPicker.this.mContext, 1.0f);
                }
            }
        });
        CustomConfig.WheelType wheelType = this.config.getWheelType();
        this.type = wheelType;
        setWheelShowLevel(wheelType);
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
        this.mViewProvince.addChangingListener(this);
        this.mViewCity.addChangingListener(this);
        this.mViewDistrict.addChangingListener(this);
        this.mTvCancel.setOnClickListener(new View.OnClickListener() { // from class: com.lljjcoder.style.citycustome.CustomCityPicker.2
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                CustomCityPicker.this.listener.onCancel();
                CustomCityPicker.this.hide();
            }
        });
        this.mTvOK.setOnClickListener(new View.OnClickListener() { // from class: com.lljjcoder.style.citycustome.CustomCityPicker.3
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (CustomCityPicker.this.type == CustomConfig.WheelType.PRO) {
                    CustomCityPicker.this.listener.onSelected(CustomCityPicker.this.config.getCityDataList().get(CustomCityPicker.this.mViewProvince.getCurrentItem()), new CustomCityData(), new CustomCityData());
                } else if (CustomCityPicker.this.type == CustomConfig.WheelType.PRO_CITY) {
                    CustomCityData customCityData = CustomCityPicker.this.config.getCityDataList().get(CustomCityPicker.this.mViewProvince.getCurrentItem());
                    int currentItem = CustomCityPicker.this.mViewCity.getCurrentItem();
                    List<CustomCityData> list = customCityData.getList();
                    if (list == null) {
                        return;
                    }
                    CustomCityPicker.this.listener.onSelected(customCityData, list.get(currentItem), new CustomCityData());
                } else if (CustomCityPicker.this.type == CustomConfig.WheelType.PRO_CITY_DIS) {
                    CustomCityData customCityData2 = CustomCityPicker.this.config.getCityDataList().get(CustomCityPicker.this.mViewProvince.getCurrentItem());
                    int currentItem2 = CustomCityPicker.this.mViewCity.getCurrentItem();
                    List<CustomCityData> list2 = customCityData2.getList();
                    if (list2 == null) {
                        return;
                    }
                    CustomCityData customCityData3 = list2.get(currentItem2);
                    int currentItem3 = CustomCityPicker.this.mViewDistrict.getCurrentItem();
                    List<CustomCityData> list3 = customCityData3.getList();
                    if (list3 == null) {
                        return;
                    }
                    CustomCityPicker.this.listener.onSelected(customCityData2, customCityData3, list3.get(currentItem3));
                }
                CustomCityPicker.this.hide();
            }
        });
        CustomConfig customConfig = this.config;
        if (customConfig != null && customConfig.isShowBackground()) {
            utils.setBackgroundAlpha(this.mContext, 0.5f);
        }
        setUpData();
    }

    private void setUpData() {
        int i2;
        List<CustomCityData> cityDataList = this.config.getCityDataList();
        if (cityDataList == null) {
            return;
        }
        if (!TextUtils.isEmpty(this.config.getDefaultProvinceName()) && cityDataList.size() > 0) {
            i2 = 0;
            while (i2 < cityDataList.size()) {
                if (cityDataList.get(i2).getName().startsWith(this.config.getDefaultProvinceName())) {
                    break;
                } else {
                    i2++;
                }
            }
        }
        i2 = -1;
        ArrayWheelAdapter arrayWheelAdapter = new ArrayWheelAdapter(this.mContext, cityDataList);
        Integer customItemLayout = this.config.getCustomItemLayout();
        Integer num = CityConfig.NONE;
        if (customItemLayout == num || this.config.getCustomItemTextViewId() == num) {
            arrayWheelAdapter.setItemResource(C3949R.layout.default_item_city);
            arrayWheelAdapter.setItemTextResource(C3949R.id.default_item_city_name_tv);
        } else {
            arrayWheelAdapter.setItemResource(this.config.getCustomItemLayout().intValue());
            arrayWheelAdapter.setItemTextResource(this.config.getCustomItemTextViewId().intValue());
        }
        this.mViewProvince.setViewAdapter(arrayWheelAdapter);
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
        CustomConfig.WheelType wheelType = this.type;
        if (wheelType == CustomConfig.WheelType.PRO_CITY || wheelType == CustomConfig.WheelType.PRO_CITY_DIS) {
            updateCities();
        }
    }

    private void setWheelShowLevel(CustomConfig.WheelType wheelType) {
        if (wheelType == CustomConfig.WheelType.PRO) {
            this.mViewProvince.setVisibility(0);
            this.mViewCity.setVisibility(8);
            this.mViewDistrict.setVisibility(8);
        } else if (wheelType == CustomConfig.WheelType.PRO_CITY) {
            this.mViewProvince.setVisibility(0);
            this.mViewCity.setVisibility(0);
            this.mViewDistrict.setVisibility(8);
        } else {
            this.mViewProvince.setVisibility(0);
            this.mViewCity.setVisibility(0);
            this.mViewDistrict.setVisibility(0);
        }
    }

    private void updateAreas() {
        List<CustomCityData> list;
        int i2;
        int currentItem = this.mViewProvince.getCurrentItem();
        int currentItem2 = this.mViewCity.getCurrentItem();
        List<CustomCityData> list2 = this.config.getCityDataList().get(currentItem).getList();
        if (list2 == null || list2.size() <= currentItem2 || (list = list2.get(currentItem2).getList()) == null) {
            return;
        }
        if (!TextUtils.isEmpty(this.config.getDefaultDistrict()) && list.size() > 0) {
            i2 = 0;
            while (i2 < list.size()) {
                if (list.get(i2).getName().startsWith(this.config.getDefaultDistrict())) {
                    break;
                } else {
                    i2++;
                }
            }
        }
        i2 = -1;
        ArrayWheelAdapter arrayWheelAdapter = new ArrayWheelAdapter(this.mContext, list);
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
            this.mViewDistrict.setCurrentItem(i2);
        } else {
            this.mViewDistrict.setCurrentItem(0);
        }
        this.mViewDistrict.setViewAdapter(arrayWheelAdapter);
    }

    private void updateCities() {
        int i2;
        List<CustomCityData> list = this.config.getCityDataList().get(this.mViewProvince.getCurrentItem()).getList();
        if (list == null) {
            return;
        }
        if (!TextUtils.isEmpty(this.config.getDefaultCityName()) && list.size() > 0) {
            i2 = 0;
            while (i2 < list.size()) {
                if (list.get(i2).getName().startsWith(this.config.getDefaultCityName())) {
                    break;
                } else {
                    i2++;
                }
            }
        }
        i2 = -1;
        ArrayWheelAdapter arrayWheelAdapter = new ArrayWheelAdapter(this.mContext, list);
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
        this.mViewCity.setViewAdapter(arrayWheelAdapter);
        if (this.type == CustomConfig.WheelType.PRO_CITY_DIS) {
            updateAreas();
        }
    }

    @Override // com.lljjcoder.style.citypickerview.widget.CanShow
    public void hide() {
        if (isShow()) {
            this.popwindow.dismiss();
        }
    }

    @Override // com.lljjcoder.style.citypickerview.widget.CanShow
    public boolean isShow() {
        return this.popwindow.isShowing();
    }

    @Override // com.lljjcoder.style.citypickerview.widget.wheel.OnWheelChangedListener
    public void onChanged(WheelView wheelView, int i2, int i3) {
        if (wheelView == this.mViewProvince) {
            updateCities();
        } else if (wheelView == this.mViewCity) {
            updateAreas();
        }
    }

    public void setCustomConfig(CustomConfig customConfig) {
        this.config = customConfig;
    }

    public void setOnCustomCityPickerItemClickListener(OnCustomCityPickerItemClickListener onCustomCityPickerItemClickListener) {
        this.listener = onCustomCityPickerItemClickListener;
    }

    public void showCityPicker() {
        initView();
        if (isShow()) {
            return;
        }
        this.popwindow.showAtLocation(this.popview, 80, 0, 0);
    }
}
