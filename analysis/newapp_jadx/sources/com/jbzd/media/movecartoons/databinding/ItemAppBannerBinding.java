package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.databinding.Bindable;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;
import p005b.p006a.p007a.p008a.p013o.C0907a;

/* loaded from: classes2.dex */
public abstract class ItemAppBannerBinding extends ViewDataBinding {

    @NonNull
    public final Banner banner;

    @Bindable
    public C0907a mItem;

    public ItemAppBannerBinding(Object obj, View view, int i2, Banner banner) {
        super(obj, view, i2);
        this.banner = banner;
    }

    public static ItemAppBannerBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemAppBannerBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public C0907a getItem() {
        return this.mItem;
    }

    public abstract void setItem(@Nullable C0907a c0907a);

    @Deprecated
    public static ItemAppBannerBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemAppBannerBinding) ViewDataBinding.bind(obj, view, R.layout.item_app_banner);
    }

    @NonNull
    @Deprecated
    public static ItemAppBannerBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemAppBannerBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_app_banner, viewGroup, z, obj);
    }

    @NonNull
    public static ItemAppBannerBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemAppBannerBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemAppBannerBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_app_banner, null, false, obj);
    }
}
