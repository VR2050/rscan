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
import com.google.android.material.imageview.ShapeableImageView;
import com.qnmd.adnnm.da0yzo.R;
import p005b.p006a.p007a.p008a.p013o.C0908b;

/* loaded from: classes2.dex */
public abstract class ItemMineGridBinding extends ViewDataBinding {

    @NonNull
    public final ShapeableImageView imgBg;

    @NonNull
    public final ImageView imgItemCoin;

    @Bindable
    public C0908b mItem;

    @NonNull
    public final ConstraintLayout root;

    @NonNull
    public final TextView tvItemName;

    public ItemMineGridBinding(Object obj, View view, int i2, ShapeableImageView shapeableImageView, ImageView imageView, ConstraintLayout constraintLayout, TextView textView) {
        super(obj, view, i2);
        this.imgBg = shapeableImageView;
        this.imgItemCoin = imageView;
        this.root = constraintLayout;
        this.tvItemName = textView;
    }

    public static ItemMineGridBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemMineGridBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public C0908b getItem() {
        return this.mItem;
    }

    public abstract void setItem(@Nullable C0908b c0908b);

    @Deprecated
    public static ItemMineGridBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemMineGridBinding) ViewDataBinding.bind(obj, view, R.layout.item_mine_grid);
    }

    @NonNull
    @Deprecated
    public static ItemMineGridBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemMineGridBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_mine_grid, viewGroup, z, obj);
    }

    @NonNull
    public static ItemMineGridBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemMineGridBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemMineGridBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_mine_grid, null, false, obj);
    }
}
