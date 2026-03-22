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
import com.jbzd.media.movecartoons.bean.response.comicsinfo.ComicsItemBean;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class ItemComicLayoutBinding extends ViewDataBinding {

    @NonNull
    public final ShapeableImageView imgCover;

    @NonNull
    public final ShapeableImageView imgStroke;

    @NonNull
    public final ImageView ivIcoType;

    @Bindable
    public ComicsItemBean mItem;

    @NonNull
    public final ConstraintLayout root;

    @NonNull
    public final TextView tvAdNewComics;

    @NonNull
    public final TextView tvComicsCategorySubtitle;

    @NonNull
    public final TextView tvComicsName;

    @NonNull
    public final ImageTextView txtNumClick;

    public ItemComicLayoutBinding(Object obj, View view, int i2, ShapeableImageView shapeableImageView, ShapeableImageView shapeableImageView2, ImageView imageView, ConstraintLayout constraintLayout, TextView textView, TextView textView2, TextView textView3, ImageTextView imageTextView) {
        super(obj, view, i2);
        this.imgCover = shapeableImageView;
        this.imgStroke = shapeableImageView2;
        this.ivIcoType = imageView;
        this.root = constraintLayout;
        this.tvAdNewComics = textView;
        this.tvComicsCategorySubtitle = textView2;
        this.tvComicsName = textView3;
        this.txtNumClick = imageTextView;
    }

    public static ItemComicLayoutBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemComicLayoutBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public ComicsItemBean getItem() {
        return this.mItem;
    }

    public abstract void setItem(@Nullable ComicsItemBean comicsItemBean);

    @Deprecated
    public static ItemComicLayoutBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemComicLayoutBinding) ViewDataBinding.bind(obj, view, R.layout.item_comic_layout);
    }

    @NonNull
    @Deprecated
    public static ItemComicLayoutBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemComicLayoutBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_comic_layout, viewGroup, z, obj);
    }

    @NonNull
    public static ItemComicLayoutBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemComicLayoutBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemComicLayoutBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_comic_layout, null, false, obj);
    }
}
