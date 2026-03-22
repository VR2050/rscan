package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.databinding.Bindable;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class ItemUnlockAccountBinding extends ViewDataBinding {

    @NonNull
    public final ShapeableImageView ivMineAvatar;

    @NonNull
    public final ImageView ivMore;

    @Bindable
    public UserInfoBean mItem;

    @NonNull
    public final TextView tvCount;

    @NonNull
    public final TextView tvName;

    public ItemUnlockAccountBinding(Object obj, View view, int i2, ShapeableImageView shapeableImageView, ImageView imageView, TextView textView, TextView textView2) {
        super(obj, view, i2);
        this.ivMineAvatar = shapeableImageView;
        this.ivMore = imageView;
        this.tvCount = textView;
        this.tvName = textView2;
    }

    public static ItemUnlockAccountBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemUnlockAccountBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public UserInfoBean getItem() {
        return this.mItem;
    }

    public abstract void setItem(@Nullable UserInfoBean userInfoBean);

    @Deprecated
    public static ItemUnlockAccountBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemUnlockAccountBinding) ViewDataBinding.bind(obj, view, R.layout.item_unlock_account);
    }

    @NonNull
    @Deprecated
    public static ItemUnlockAccountBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemUnlockAccountBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_unlock_account, viewGroup, z, obj);
    }

    @NonNull
    public static ItemUnlockAccountBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemUnlockAccountBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemUnlockAccountBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_unlock_account, null, false, obj);
    }
}
