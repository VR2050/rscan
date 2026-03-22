package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.databinding.Bindable;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import androidx.recyclerview.widget.RecyclerView;
import com.jbzd.media.movecartoons.bean.response.PostListBean;
import com.jbzd.media.movecartoons.view.PostFileView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class ItemPostLayoutBinding extends ViewDataBinding {

    @NonNull
    public final LinearLayout layoutClick;

    @NonNull
    public final LinearLayout layoutComment;

    @NonNull
    public final PostFileView layoutPostFile;

    @NonNull
    public final LinearLayout layoutPraise;

    @NonNull
    public final LinearLayout layoutShare;

    @Bindable
    public PostListBean mItem;

    @NonNull
    public final ConstraintLayout root;

    @NonNull
    public final RecyclerView rvTagPost;

    @NonNull
    public final ImageTextView txtClick;

    @NonNull
    public final ImageTextView txtComment;

    @NonNull
    public final TextView txtContent;

    @NonNull
    public final TextView txtNumClick;

    @NonNull
    public final ImageTextView txtPraise;

    public ItemPostLayoutBinding(Object obj, View view, int i2, LinearLayout linearLayout, LinearLayout linearLayout2, PostFileView postFileView, LinearLayout linearLayout3, LinearLayout linearLayout4, ConstraintLayout constraintLayout, RecyclerView recyclerView, ImageTextView imageTextView, ImageTextView imageTextView2, TextView textView, TextView textView2, ImageTextView imageTextView3) {
        super(obj, view, i2);
        this.layoutClick = linearLayout;
        this.layoutComment = linearLayout2;
        this.layoutPostFile = postFileView;
        this.layoutPraise = linearLayout3;
        this.layoutShare = linearLayout4;
        this.root = constraintLayout;
        this.rvTagPost = recyclerView;
        this.txtClick = imageTextView;
        this.txtComment = imageTextView2;
        this.txtContent = textView;
        this.txtNumClick = textView2;
        this.txtPraise = imageTextView3;
    }

    public static ItemPostLayoutBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemPostLayoutBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public PostListBean getItem() {
        return this.mItem;
    }

    public abstract void setItem(@Nullable PostListBean postListBean);

    @Deprecated
    public static ItemPostLayoutBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemPostLayoutBinding) ViewDataBinding.bind(obj, view, R.layout.item_post_layout);
    }

    @NonNull
    @Deprecated
    public static ItemPostLayoutBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemPostLayoutBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_post_layout, viewGroup, z, obj);
    }

    @NonNull
    public static ItemPostLayoutBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemPostLayoutBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemPostLayoutBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_post_layout, null, false, obj);
    }
}
