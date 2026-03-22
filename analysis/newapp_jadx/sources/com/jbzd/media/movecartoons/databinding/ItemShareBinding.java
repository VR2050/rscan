package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.Guideline;
import androidx.databinding.Bindable;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.jbzd.media.movecartoons.bean.response.ShareBean;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class ItemShareBinding extends ViewDataBinding {

    @NonNull
    public final Guideline guideLeft;

    @NonNull
    public final Guideline guideRight;

    @Bindable
    public ShareBean mItem;

    @NonNull
    public final TextView tvItemshareCode;

    @NonNull
    public final TextView tvItemshareNickname;

    @NonNull
    public final TextView tvItemshareTime;

    public ItemShareBinding(Object obj, View view, int i2, Guideline guideline, Guideline guideline2, TextView textView, TextView textView2, TextView textView3) {
        super(obj, view, i2);
        this.guideLeft = guideline;
        this.guideRight = guideline2;
        this.tvItemshareCode = textView;
        this.tvItemshareNickname = textView2;
        this.tvItemshareTime = textView3;
    }

    public static ItemShareBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemShareBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public ShareBean getItem() {
        return this.mItem;
    }

    public abstract void setItem(@Nullable ShareBean shareBean);

    @Deprecated
    public static ItemShareBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemShareBinding) ViewDataBinding.bind(obj, view, R.layout.item_share);
    }

    @NonNull
    @Deprecated
    public static ItemShareBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemShareBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_share, viewGroup, z, obj);
    }

    @NonNull
    public static ItemShareBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemShareBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemShareBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_share, null, false, obj);
    }
}
