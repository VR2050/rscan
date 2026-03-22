package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.databinding.Bindable;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.qnmd.adnnm.da0yzo.R;
import p005b.p006a.p007a.p008a.p013o.C0908b;

/* loaded from: classes2.dex */
public abstract class ItemBottomMineBinding extends ViewDataBinding {

    @NonNull
    public final ImageView ivIcon;

    @Bindable
    public C0908b mItem;

    @NonNull
    public final LinearLayout root;

    @NonNull
    public final TextView tvBottomitemName;

    public ItemBottomMineBinding(Object obj, View view, int i2, ImageView imageView, LinearLayout linearLayout, TextView textView) {
        super(obj, view, i2);
        this.ivIcon = imageView;
        this.root = linearLayout;
        this.tvBottomitemName = textView;
    }

    public static ItemBottomMineBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemBottomMineBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public C0908b getItem() {
        return this.mItem;
    }

    public abstract void setItem(@Nullable C0908b c0908b);

    @Deprecated
    public static ItemBottomMineBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemBottomMineBinding) ViewDataBinding.bind(obj, view, R.layout.item_bottom_mine);
    }

    @NonNull
    @Deprecated
    public static ItemBottomMineBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemBottomMineBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_bottom_mine, viewGroup, z, obj);
    }

    @NonNull
    public static ItemBottomMineBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemBottomMineBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemBottomMineBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_bottom_mine, null, false, obj);
    }
}
