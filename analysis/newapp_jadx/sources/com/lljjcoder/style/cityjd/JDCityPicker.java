package com.lljjcoder.style.cityjd;

import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.os.Handler;
import android.os.Message;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ImageView;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.PopupWindow;
import android.widget.TextView;
import androidx.interpolator.view.animation.FastOutSlowInInterpolator;
import com.lljjcoder.Interface.OnCityItemClickListener;
import com.lljjcoder.bean.CityBean;
import com.lljjcoder.bean.DistrictBean;
import com.lljjcoder.bean.ProvinceBean;
import com.lljjcoder.citywheel.CityParseHelper;
import com.lljjcoder.style.cityjd.JDCityConfig;
import com.lljjcoder.style.citylist.Toast.ToastUtils;
import com.lljjcoder.style.citypickerview.C3949R;
import com.lljjcoder.utils.utils;
import java.util.ArrayList;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class JDCityPicker {
    private Context context;
    private AreaAdapter mAreaAdapter;
    private TextView mAreaTv;
    private OnCityItemClickListener mBaseListener;
    private CityAdapter mCityAdapter;
    private ListView mCityListView;
    private TextView mCityTv;
    private ImageView mCloseImg;
    private TextView mProTv;
    private ProvinceAdapter mProvinceAdapter;
    private View mSelectedLine;
    private CityParseHelper parseHelper;
    private View popview;
    private PopupWindow popwindow;
    private List<ProvinceBean> provinceList = null;
    private List<CityBean> cityList = null;
    private List<DistrictBean> areaList = null;
    private int tabIndex = 0;
    private String colorSelected = "#ff181c20";
    private String colorAlert = "#ffff4444";
    private JDCityConfig cityConfig = null;
    private Handler mHandler = new Handler(new Handler.Callback() { // from class: com.lljjcoder.style.cityjd.JDCityPicker.9
        @Override // android.os.Handler.Callback
        public boolean handleMessage(Message message) {
            int i2 = message.what;
            if (i2 == -1) {
                JDCityPicker.this.provinceList = (List) message.obj;
                JDCityPicker.this.mProvinceAdapter.notifyDataSetChanged();
                JDCityPicker.this.mCityListView.setAdapter((ListAdapter) JDCityPicker.this.mProvinceAdapter);
            } else if (i2 == 0) {
                JDCityPicker.this.provinceList = (List) message.obj;
                JDCityPicker.this.mProvinceAdapter.notifyDataSetChanged();
                JDCityPicker.this.mCityListView.setAdapter((ListAdapter) JDCityPicker.this.mProvinceAdapter);
            } else if (i2 == 1) {
                JDCityPicker.this.cityList = (List) message.obj;
                JDCityPicker.this.mCityAdapter.notifyDataSetChanged();
                if (JDCityPicker.this.cityList != null && !JDCityPicker.this.cityList.isEmpty()) {
                    JDCityPicker.this.mCityListView.setAdapter((ListAdapter) JDCityPicker.this.mCityAdapter);
                    JDCityPicker.this.tabIndex = 1;
                }
            } else if (i2 == 2) {
                JDCityPicker.this.areaList = (List) message.obj;
                JDCityPicker.this.mAreaAdapter.notifyDataSetChanged();
                if (JDCityPicker.this.areaList != null && !JDCityPicker.this.areaList.isEmpty()) {
                    JDCityPicker.this.mCityListView.setAdapter((ListAdapter) JDCityPicker.this.mAreaAdapter);
                    JDCityPicker.this.tabIndex = 2;
                }
            }
            JDCityPicker jDCityPicker = JDCityPicker.this;
            jDCityPicker.updateTabsStyle(jDCityPicker.tabIndex);
            JDCityPicker.this.updateIndicator();
            return true;
        }
    });

    private void callback(DistrictBean districtBean) {
        CityAdapter cityAdapter;
        ProvinceAdapter provinceAdapter;
        List<ProvinceBean> list = this.provinceList;
        CityBean cityBean = null;
        ProvinceBean provinceBean = (list == null || list.isEmpty() || (provinceAdapter = this.mProvinceAdapter) == null || provinceAdapter.getSelectedPosition() == -1) ? null : this.provinceList.get(this.mProvinceAdapter.getSelectedPosition());
        List<CityBean> list2 = this.cityList;
        if (list2 != null && !list2.isEmpty() && (cityAdapter = this.mCityAdapter) != null && cityAdapter.getSelectedPosition() != -1) {
            cityBean = this.cityList.get(this.mCityAdapter.getSelectedPosition());
        }
        this.mBaseListener.onSelected(provinceBean, cityBean, districtBean);
        hidePop();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void hidePop() {
        if (isShow()) {
            this.popwindow.dismiss();
        }
    }

    private void initJDCityPickerPop() {
        if (this.cityConfig == null) {
            this.cityConfig = new JDCityConfig.Builder().setJDCityShowType(JDCityConfig.ShowType.PRO_CITY_DIS).build();
        }
        this.tabIndex = 0;
        if (this.parseHelper == null) {
            this.parseHelper = new CityParseHelper();
        }
        if (this.parseHelper.getProvinceBeanArrayList().isEmpty()) {
            ToastUtils.showLongToast(this.context, "请调用init方法进行初始化相关操作");
            return;
        }
        View inflate = LayoutInflater.from(this.context).inflate(C3949R.layout.pop_jdcitypicker, (ViewGroup) null);
        this.popview = inflate;
        this.mCityListView = (ListView) inflate.findViewById(C3949R.id.city_listview);
        this.mProTv = (TextView) this.popview.findViewById(C3949R.id.province_tv);
        this.mCityTv = (TextView) this.popview.findViewById(C3949R.id.city_tv);
        this.mAreaTv = (TextView) this.popview.findViewById(C3949R.id.area_tv);
        this.mCloseImg = (ImageView) this.popview.findViewById(C3949R.id.close_img);
        this.mSelectedLine = this.popview.findViewById(C3949R.id.selected_line);
        PopupWindow popupWindow = new PopupWindow(this.popview, -1, -2);
        this.popwindow = popupWindow;
        popupWindow.setAnimationStyle(C3949R.style.AnimBottom);
        this.popwindow.setBackgroundDrawable(new ColorDrawable());
        this.popwindow.setTouchable(true);
        this.popwindow.setOutsideTouchable(false);
        this.popwindow.setFocusable(true);
        this.popwindow.setOnDismissListener(new PopupWindow.OnDismissListener() { // from class: com.lljjcoder.style.cityjd.JDCityPicker.1
            @Override // android.widget.PopupWindow.OnDismissListener
            public void onDismiss() {
                utils.setBackgroundAlpha(JDCityPicker.this.context, 1.0f);
            }
        });
        this.mCloseImg.setOnClickListener(new View.OnClickListener() { // from class: com.lljjcoder.style.cityjd.JDCityPicker.2
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                JDCityPicker.this.hidePop();
                utils.setBackgroundAlpha(JDCityPicker.this.context, 1.0f);
                if (JDCityPicker.this.mBaseListener != null) {
                    JDCityPicker.this.mBaseListener.onCancel();
                }
            }
        });
        this.mProTv.setOnClickListener(new View.OnClickListener() { // from class: com.lljjcoder.style.cityjd.JDCityPicker.3
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                JDCityPicker.this.tabIndex = 0;
                if (JDCityPicker.this.mProvinceAdapter != null) {
                    JDCityPicker.this.mCityListView.setAdapter((ListAdapter) JDCityPicker.this.mProvinceAdapter);
                    if (JDCityPicker.this.mProvinceAdapter.getSelectedPosition() != -1) {
                        JDCityPicker.this.mCityListView.setSelection(JDCityPicker.this.mProvinceAdapter.getSelectedPosition());
                    }
                }
                JDCityPicker.this.updateTabVisible();
                JDCityPicker.this.updateIndicator();
            }
        });
        this.mCityTv.setOnClickListener(new View.OnClickListener() { // from class: com.lljjcoder.style.cityjd.JDCityPicker.4
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                JDCityPicker.this.tabIndex = 1;
                if (JDCityPicker.this.mCityAdapter != null) {
                    JDCityPicker.this.mCityListView.setAdapter((ListAdapter) JDCityPicker.this.mCityAdapter);
                    if (JDCityPicker.this.mCityAdapter.getSelectedPosition() != -1) {
                        JDCityPicker.this.mCityListView.setSelection(JDCityPicker.this.mCityAdapter.getSelectedPosition());
                    }
                }
                JDCityPicker.this.updateTabVisible();
                JDCityPicker.this.updateIndicator();
            }
        });
        this.mAreaTv.setOnClickListener(new View.OnClickListener() { // from class: com.lljjcoder.style.cityjd.JDCityPicker.5
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                JDCityPicker.this.tabIndex = 2;
                if (JDCityPicker.this.mAreaAdapter != null) {
                    JDCityPicker.this.mCityListView.setAdapter((ListAdapter) JDCityPicker.this.mAreaAdapter);
                    if (JDCityPicker.this.mAreaAdapter.getSelectedPosition() != -1) {
                        JDCityPicker.this.mCityListView.setSelection(JDCityPicker.this.mAreaAdapter.getSelectedPosition());
                    }
                }
                JDCityPicker.this.updateTabVisible();
                JDCityPicker.this.updateIndicator();
            }
        });
        this.mCityListView.setOnItemClickListener(new AdapterView.OnItemClickListener() { // from class: com.lljjcoder.style.cityjd.JDCityPicker.6
            @Override // android.widget.AdapterView.OnItemClickListener
            public void onItemClick(AdapterView<?> adapterView, View view, int i2, long j2) {
                JDCityPicker.this.selectedList(i2);
            }
        });
        utils.setBackgroundAlpha(this.context, 0.5f);
        updateIndicator();
        updateTabsStyle(-1);
        setProvinceListData();
    }

    private boolean isShow() {
        return this.popwindow.isShowing();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void selectedList(int i2) {
        DistrictBean item;
        int i3 = this.tabIndex;
        if (i3 == 0) {
            ProvinceBean item2 = this.mProvinceAdapter.getItem(i2);
            if (item2 != null) {
                TextView textView = this.mProTv;
                StringBuilder m586H = C1499a.m586H("");
                m586H.append(item2.getName());
                textView.setText(m586H.toString());
                this.mCityTv.setText("请选择");
                this.mProvinceAdapter.updateSelectedPosition(i2);
                this.mProvinceAdapter.notifyDataSetChanged();
                this.mCityAdapter = new CityAdapter(this.context, item2.getCityList());
                Handler handler = this.mHandler;
                handler.sendMessage(Message.obtain(handler, 1, item2.getCityList()));
                return;
            }
            return;
        }
        if (i3 != 1) {
            if (i3 == 2 && (item = this.mAreaAdapter.getItem(i2)) != null) {
                callback(item);
                return;
            }
            return;
        }
        CityBean item3 = this.mCityAdapter.getItem(i2);
        if (item3 != null) {
            TextView textView2 = this.mCityTv;
            StringBuilder m586H2 = C1499a.m586H("");
            m586H2.append(item3.getName());
            textView2.setText(m586H2.toString());
            this.mAreaTv.setText("请选择");
            this.mCityAdapter.updateSelectedPosition(i2);
            this.mCityAdapter.notifyDataSetChanged();
            JDCityConfig jDCityConfig = this.cityConfig;
            if (jDCityConfig != null && jDCityConfig.getShowType() == JDCityConfig.ShowType.PRO_CITY) {
                callback(new DistrictBean());
                return;
            }
            this.mAreaAdapter = new AreaAdapter(this.context, item3.getCityList());
            Handler handler2 = this.mHandler;
            handler2.sendMessage(Message.obtain(handler2, 2, item3.getCityList()));
        }
    }

    private void setProvinceListData() {
        ArrayList<ProvinceBean> provinceBeanArrayList = this.parseHelper.getProvinceBeanArrayList();
        this.provinceList = provinceBeanArrayList;
        if (provinceBeanArrayList == null || provinceBeanArrayList.isEmpty()) {
            ToastUtils.showLongToast(this.context, "解析本地城市数据失败！");
            return;
        }
        ProvinceAdapter provinceAdapter = new ProvinceAdapter(this.context, this.provinceList);
        this.mProvinceAdapter = provinceAdapter;
        this.mCityListView.setAdapter((ListAdapter) provinceAdapter);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public AnimatorSet tabSelectedIndicatorAnimation(TextView textView) {
        View view = this.mSelectedLine;
        ObjectAnimator ofFloat = ObjectAnimator.ofFloat(view, "X", view.getX(), textView.getX());
        final ViewGroup.LayoutParams layoutParams = this.mSelectedLine.getLayoutParams();
        ValueAnimator ofInt = ValueAnimator.ofInt(layoutParams.width, textView.getMeasuredWidth());
        ofInt.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: com.lljjcoder.style.cityjd.JDCityPicker.8
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public void onAnimationUpdate(ValueAnimator valueAnimator) {
                layoutParams.width = ((Integer) valueAnimator.getAnimatedValue()).intValue();
                JDCityPicker.this.mSelectedLine.setLayoutParams(layoutParams);
            }
        });
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.setInterpolator(new FastOutSlowInInterpolator());
        animatorSet.playTogether(ofFloat, ofInt);
        return animatorSet;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateIndicator() {
        this.popview.post(new Runnable() { // from class: com.lljjcoder.style.cityjd.JDCityPicker.7
            @Override // java.lang.Runnable
            public void run() {
                int i2 = JDCityPicker.this.tabIndex;
                if (i2 == 0) {
                    JDCityPicker jDCityPicker = JDCityPicker.this;
                    jDCityPicker.tabSelectedIndicatorAnimation(jDCityPicker.mProTv).start();
                } else if (i2 == 1) {
                    JDCityPicker jDCityPicker2 = JDCityPicker.this;
                    jDCityPicker2.tabSelectedIndicatorAnimation(jDCityPicker2.mCityTv).start();
                } else {
                    if (i2 != 2) {
                        return;
                    }
                    JDCityPicker jDCityPicker3 = JDCityPicker.this;
                    jDCityPicker3.tabSelectedIndicatorAnimation(jDCityPicker3.mAreaTv).start();
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateTabVisible() {
        TextView textView = this.mProTv;
        List<ProvinceBean> list = this.provinceList;
        textView.setVisibility((list == null || list.isEmpty()) ? 8 : 0);
        TextView textView2 = this.mCityTv;
        List<CityBean> list2 = this.cityList;
        textView2.setVisibility((list2 == null || list2.isEmpty()) ? 8 : 0);
        TextView textView3 = this.mAreaTv;
        List<DistrictBean> list3 = this.areaList;
        textView3.setVisibility((list3 == null || list3.isEmpty()) ? 8 : 0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateTabsStyle(int i2) {
        if (i2 == -1) {
            this.mProTv.setTextColor(Color.parseColor(this.colorAlert));
            this.mProTv.setVisibility(0);
            this.mCityTv.setVisibility(8);
            this.mAreaTv.setVisibility(8);
            return;
        }
        if (i2 == 0) {
            this.mProTv.setTextColor(Color.parseColor(this.colorAlert));
            this.mProTv.setVisibility(0);
            this.mCityTv.setVisibility(8);
            this.mAreaTv.setVisibility(8);
            return;
        }
        if (i2 == 1) {
            this.mProTv.setTextColor(Color.parseColor(this.colorSelected));
            this.mCityTv.setTextColor(Color.parseColor(this.colorAlert));
            this.mProTv.setVisibility(0);
            this.mCityTv.setVisibility(0);
            this.mAreaTv.setVisibility(8);
            return;
        }
        if (i2 != 2) {
            return;
        }
        this.mProTv.setTextColor(Color.parseColor(this.colorSelected));
        this.mCityTv.setTextColor(Color.parseColor(this.colorSelected));
        this.mAreaTv.setTextColor(Color.parseColor(this.colorAlert));
        this.mProTv.setVisibility(0);
        this.mCityTv.setVisibility(0);
        this.mAreaTv.setVisibility(0);
    }

    public void init(Context context) {
        this.context = context;
        CityParseHelper cityParseHelper = new CityParseHelper();
        this.parseHelper = cityParseHelper;
        if (cityParseHelper.getProvinceBeanArrayList().isEmpty()) {
            this.parseHelper.initData(context);
        }
    }

    public void setConfig(JDCityConfig jDCityConfig) {
        this.cityConfig = jDCityConfig;
    }

    public void setOnCityItemClickListener(OnCityItemClickListener onCityItemClickListener) {
        this.mBaseListener = onCityItemClickListener;
    }

    public void showCityPicker() {
        initJDCityPickerPop();
        if (isShow()) {
            return;
        }
        this.popwindow.showAtLocation(this.popview, 80, 0, 0);
    }
}
