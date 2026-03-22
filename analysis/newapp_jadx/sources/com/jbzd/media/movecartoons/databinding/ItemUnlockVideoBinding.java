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
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class ItemUnlockVideoBinding extends ViewDataBinding {

    @NonNull
    public final ShapeableImageView ivVideo;

    @Bindable
    public VideoItemBean mItem;

    @NonNull
    public final TextView tvDuration;

    @NonNull
    public final TextView tvTitle;

    public ItemUnlockVideoBinding(Object obj, View view, int i2, ShapeableImageView shapeableImageView, TextView textView, TextView textView2) {
        super(obj, view, i2);
        this.ivVideo = shapeableImageView;
        this.tvDuration = textView;
        this.tvTitle = textView2;
    }

    public static ItemUnlockVideoBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemUnlockVideoBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public VideoItemBean getItem() {
        return this.mItem;
    }

    public abstract void setItem(@Nullable VideoItemBean videoItemBean);

    @Deprecated
    public static ItemUnlockVideoBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemUnlockVideoBinding) ViewDataBinding.bind(obj, view, R.layout.item_unlock_video);
    }

    @NonNull
    @Deprecated
    public static ItemUnlockVideoBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemUnlockVideoBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_unlock_video, viewGroup, z, obj);
    }

    @NonNull
    public static ItemUnlockVideoBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemUnlockVideoBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemUnlockVideoBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_unlock_video, null, false, obj);
    }
}
