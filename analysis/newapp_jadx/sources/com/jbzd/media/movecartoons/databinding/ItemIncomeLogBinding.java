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
import com.jbzd.media.movecartoons.bean.response.IncomeLogBean;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class ItemIncomeLogBinding extends ViewDataBinding {

    @Bindable
    public IncomeLogBean mItem;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final TextView tvNum;

    @NonNull
    public final TextView tvTime;

    public ItemIncomeLogBinding(Object obj, View view, int i2, TextView textView, TextView textView2, TextView textView3) {
        super(obj, view, i2);
        this.tvName = textView;
        this.tvNum = textView2;
        this.tvTime = textView3;
    }

    public static ItemIncomeLogBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemIncomeLogBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public IncomeLogBean getItem() {
        return this.mItem;
    }

    public abstract void setItem(@Nullable IncomeLogBean incomeLogBean);

    @Deprecated
    public static ItemIncomeLogBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemIncomeLogBinding) ViewDataBinding.bind(obj, view, R.layout.item_income_log);
    }

    @NonNull
    @Deprecated
    public static ItemIncomeLogBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemIncomeLogBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_income_log, viewGroup, z, obj);
    }

    @NonNull
    public static ItemIncomeLogBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemIncomeLogBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemIncomeLogBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_income_log, null, false, obj);
    }
}
