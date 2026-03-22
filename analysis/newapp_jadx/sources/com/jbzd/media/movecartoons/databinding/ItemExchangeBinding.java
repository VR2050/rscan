package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.databinding.Bindable;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.jbzd.media.movecartoons.bean.response.ExchangeLogBean;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class ItemExchangeBinding extends ViewDataBinding {

    @Bindable
    public ExchangeLogBean mItem;

    @NonNull
    public final TextView tvCode;

    @NonNull
    public final TextView tvDay;

    @NonNull
    public final TextView tvTime;

    public ItemExchangeBinding(Object obj, View view, int i2, TextView textView, TextView textView2, TextView textView3) {
        super(obj, view, i2);
        this.tvCode = textView;
        this.tvDay = textView2;
        this.tvTime = textView3;
    }

    public static ItemExchangeBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemExchangeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public ExchangeLogBean getItem() {
        return this.mItem;
    }

    public abstract void setItem(@Nullable ExchangeLogBean exchangeLogBean);

    @Deprecated
    public static ItemExchangeBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemExchangeBinding) ViewDataBinding.bind(obj, view, R.layout.item_exchange);
    }

    @NonNull
    @Deprecated
    public static ItemExchangeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemExchangeBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_exchange, viewGroup, z, obj);
    }

    @NonNull
    public static ItemExchangeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemExchangeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemExchangeBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_exchange, null, false, obj);
    }
}
