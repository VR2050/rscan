package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatButton;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.databinding.Bindable;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.PageRefreshLayout;
import com.jbzd.media.movecartoons.p396ui.vip.ExchangeViewModel;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class ActExchangeBinding extends ViewDataBinding {

    @NonNull
    public final AppCompatEditText etContent;

    @Bindable
    public ExchangeViewModel mViewModel;

    @NonNull
    public final PageRefreshLayout pager;

    @NonNull
    public final RecyclerView rvExchange;

    @NonNull
    public final AppCompatButton tvSubmit;

    public ActExchangeBinding(Object obj, View view, int i2, AppCompatEditText appCompatEditText, PageRefreshLayout pageRefreshLayout, RecyclerView recyclerView, AppCompatButton appCompatButton) {
        super(obj, view, i2);
        this.etContent = appCompatEditText;
        this.pager = pageRefreshLayout;
        this.rvExchange = recyclerView;
        this.tvSubmit = appCompatButton;
    }

    public static ActExchangeBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ActExchangeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public ExchangeViewModel getViewModel() {
        return this.mViewModel;
    }

    public abstract void setViewModel(@Nullable ExchangeViewModel exchangeViewModel);

    @Deprecated
    public static ActExchangeBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ActExchangeBinding) ViewDataBinding.bind(obj, view, R.layout.act_exchange);
    }

    @NonNull
    @Deprecated
    public static ActExchangeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ActExchangeBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.act_exchange, viewGroup, z, obj);
    }

    @NonNull
    public static ActExchangeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ActExchangeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ActExchangeBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.act_exchange, null, false, obj);
    }
}
