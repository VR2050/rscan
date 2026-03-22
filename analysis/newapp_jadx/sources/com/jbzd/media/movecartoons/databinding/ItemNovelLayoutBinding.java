package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.databinding.Bindable;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.bean.response.novel.NovelItemsBean;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class ItemNovelLayoutBinding extends ViewDataBinding {

    @NonNull
    public final ShapeableImageView imgCover;

    @NonNull
    public final ScaleRelativeLayout itemParent;

    @NonNull
    public final ImageView ivNovelAudio;

    @NonNull
    public final LinearLayout llName;

    @Bindable
    public NovelItemsBean mItem;

    @NonNull
    public final RelativeLayout rlCoverOption;

    @NonNull
    public final ConstraintLayout root;

    @NonNull
    public final TextView tvNovelCategorySubtitle;

    @NonNull
    public final TextView tvNovelName;

    public ItemNovelLayoutBinding(Object obj, View view, int i2, ShapeableImageView shapeableImageView, ScaleRelativeLayout scaleRelativeLayout, ImageView imageView, LinearLayout linearLayout, RelativeLayout relativeLayout, ConstraintLayout constraintLayout, TextView textView, TextView textView2) {
        super(obj, view, i2);
        this.imgCover = shapeableImageView;
        this.itemParent = scaleRelativeLayout;
        this.ivNovelAudio = imageView;
        this.llName = linearLayout;
        this.rlCoverOption = relativeLayout;
        this.root = constraintLayout;
        this.tvNovelCategorySubtitle = textView;
        this.tvNovelName = textView2;
    }

    public static ItemNovelLayoutBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemNovelLayoutBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public NovelItemsBean getItem() {
        return this.mItem;
    }

    public abstract void setItem(@Nullable NovelItemsBean novelItemsBean);

    @Deprecated
    public static ItemNovelLayoutBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemNovelLayoutBinding) ViewDataBinding.bind(obj, view, R.layout.item_novel_layout);
    }

    @NonNull
    @Deprecated
    public static ItemNovelLayoutBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemNovelLayoutBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_novel_layout, viewGroup, z, obj);
    }

    @NonNull
    public static ItemNovelLayoutBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemNovelLayoutBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemNovelLayoutBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_novel_layout, null, false, obj);
    }
}
