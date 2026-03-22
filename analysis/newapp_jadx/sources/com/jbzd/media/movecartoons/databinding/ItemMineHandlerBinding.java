package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.databinding.Bindable;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.qnmd.adnnm.da0yzo.R;
import p005b.p006a.p007a.p008a.p013o.C0908b;

/* loaded from: classes2.dex */
public abstract class ItemMineHandlerBinding extends ViewDataBinding {

    @NonNull
    public final ImageView ivIcon;

    @NonNull
    public final ImageView ivRightArrow;

    @Bindable
    public C0908b mItem;

    @NonNull
    public final ConstraintLayout root;

    @NonNull
    public final TextView tvRightTips;

    public ItemMineHandlerBinding(Object obj, View view, int i2, ImageView imageView, ImageView imageView2, ConstraintLayout constraintLayout, TextView textView) {
        super(obj, view, i2);
        this.ivIcon = imageView;
        this.ivRightArrow = imageView2;
        this.root = constraintLayout;
        this.tvRightTips = textView;
    }

    public static ItemMineHandlerBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemMineHandlerBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public C0908b getItem() {
        return this.mItem;
    }

    public abstract void setItem(@Nullable C0908b c0908b);

    @Deprecated
    public static ItemMineHandlerBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemMineHandlerBinding) ViewDataBinding.bind(obj, view, R.layout.item_mine_handler);
    }

    @NonNull
    @Deprecated
    public static ItemMineHandlerBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemMineHandlerBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_mine_handler, viewGroup, z, obj);
    }

    @NonNull
    public static ItemMineHandlerBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemMineHandlerBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemMineHandlerBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_mine_handler, null, false, obj);
    }
}
