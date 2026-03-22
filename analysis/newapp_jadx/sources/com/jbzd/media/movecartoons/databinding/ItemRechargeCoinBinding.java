package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.databinding.Bindable;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.jbzd.media.movecartoons.bean.response.RechargeBean;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class ItemRechargeCoinBinding extends ViewDataBinding {

    @Bindable
    public RechargeBean.ProductsBean mItem;

    @NonNull
    public final TextView promotionTips;

    @NonNull
    public final ConstraintLayout root;

    @NonNull
    public final TextView tvCoin;

    @NonNull
    public final TextView tvPrice;

    @NonNull
    public final TextView tvTagTui;

    public ItemRechargeCoinBinding(Object obj, View view, int i2, TextView textView, ConstraintLayout constraintLayout, TextView textView2, TextView textView3, TextView textView4) {
        super(obj, view, i2);
        this.promotionTips = textView;
        this.root = constraintLayout;
        this.tvCoin = textView2;
        this.tvPrice = textView3;
        this.tvTagTui = textView4;
    }

    public static ItemRechargeCoinBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemRechargeCoinBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public RechargeBean.ProductsBean getItem() {
        return this.mItem;
    }

    public abstract void setItem(@Nullable RechargeBean.ProductsBean productsBean);

    @Deprecated
    public static ItemRechargeCoinBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemRechargeCoinBinding) ViewDataBinding.bind(obj, view, R.layout.item_recharge_coin);
    }

    @NonNull
    @Deprecated
    public static ItemRechargeCoinBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemRechargeCoinBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_recharge_coin, viewGroup, z, obj);
    }

    @NonNull
    public static ItemRechargeCoinBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemRechargeCoinBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemRechargeCoinBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_recharge_coin, null, false, obj);
    }
}
