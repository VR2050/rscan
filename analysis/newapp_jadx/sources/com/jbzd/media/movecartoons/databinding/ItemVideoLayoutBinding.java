package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.databinding.Bindable;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class ItemVideoLayoutBinding extends ViewDataBinding {

    @NonNull
    public final ImageView imgIconMoney;

    @NonNull
    public final ShapeableImageView imgStroke;

    @NonNull
    public final ImageView ivIcoType;

    @NonNull
    public final ShapeableImageView ivVideo;

    @NonNull
    public final LinearLayout layoutIsHideVip;

    @Bindable
    public VideoItemBean mItem;

    @NonNull
    public final ConstraintLayout root;

    @NonNull
    public final ImageTextView tvCount;

    @NonNull
    public final TextView tvDuration;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final TextView tvVideoClick;

    @NonNull
    public final TextView tvVideoType;

    public ItemVideoLayoutBinding(Object obj, View view, int i2, ImageView imageView, ShapeableImageView shapeableImageView, ImageView imageView2, ShapeableImageView shapeableImageView2, LinearLayout linearLayout, ConstraintLayout constraintLayout, ImageTextView imageTextView, TextView textView, TextView textView2, TextView textView3, TextView textView4) {
        super(obj, view, i2);
        this.imgIconMoney = imageView;
        this.imgStroke = shapeableImageView;
        this.ivIcoType = imageView2;
        this.ivVideo = shapeableImageView2;
        this.layoutIsHideVip = linearLayout;
        this.root = constraintLayout;
        this.tvCount = imageTextView;
        this.tvDuration = textView;
        this.tvName = textView2;
        this.tvVideoClick = textView3;
        this.tvVideoType = textView4;
    }

    public static ItemVideoLayoutBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemVideoLayoutBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public VideoItemBean getItem() {
        return this.mItem;
    }

    public abstract void setItem(@Nullable VideoItemBean videoItemBean);

    @Deprecated
    public static ItemVideoLayoutBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemVideoLayoutBinding) ViewDataBinding.bind(obj, view, R.layout.item_video_layout);
    }

    @NonNull
    @Deprecated
    public static ItemVideoLayoutBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemVideoLayoutBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_video_layout, viewGroup, z, obj);
    }

    @NonNull
    public static ItemVideoLayoutBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemVideoLayoutBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemVideoLayoutBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_video_layout, null, false, obj);
    }
}
