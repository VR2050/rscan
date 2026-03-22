package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class ItemAppVerticalBinding extends ViewDataBinding {

    @NonNull
    public final ShapeableImageView imgIcon;

    @NonNull
    public final ConstraintLayout root;

    @NonNull
    public final TextView txtName;

    public ItemAppVerticalBinding(Object obj, View view, int i2, ShapeableImageView shapeableImageView, ConstraintLayout constraintLayout, TextView textView) {
        super(obj, view, i2);
        this.imgIcon = shapeableImageView;
        this.root = constraintLayout;
        this.txtName = textView;
    }

    public static ItemAppVerticalBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemAppVerticalBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Deprecated
    public static ItemAppVerticalBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemAppVerticalBinding) ViewDataBinding.bind(obj, view, R.layout.item_app_vertical);
    }

    @NonNull
    @Deprecated
    public static ItemAppVerticalBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemAppVerticalBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_app_vertical, viewGroup, z, obj);
    }

    @NonNull
    public static ItemAppVerticalBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemAppVerticalBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemAppVerticalBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_app_vertical, null, false, obj);
    }
}
