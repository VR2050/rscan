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
import com.jbzd.media.movecartoons.bean.response.PostListBean;
import com.jbzd.media.movecartoons.view.FollowTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class LayoutItemPostUserBinding extends ViewDataBinding {

    @NonNull
    public final ImageView imgUp;

    @NonNull
    public final ImageView imgVip;

    @NonNull
    public final FollowTextView itvPostuserFollow;

    @NonNull
    public final ShapeableImageView ivMineAvatar;

    @NonNull
    public final ConstraintLayout layoutUserInfo;

    @Bindable
    public String mTime;

    @Bindable
    public PostListBean.UserBean mUserBean;

    @NonNull
    public final TextView txtName;

    @NonNull
    public final TextView txtReleaseTime;

    public LayoutItemPostUserBinding(Object obj, View view, int i2, ImageView imageView, ImageView imageView2, FollowTextView followTextView, ShapeableImageView shapeableImageView, ConstraintLayout constraintLayout, TextView textView, TextView textView2) {
        super(obj, view, i2);
        this.imgUp = imageView;
        this.imgVip = imageView2;
        this.itvPostuserFollow = followTextView;
        this.ivMineAvatar = shapeableImageView;
        this.layoutUserInfo = constraintLayout;
        this.txtName = textView;
        this.txtReleaseTime = textView2;
    }

    public static LayoutItemPostUserBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static LayoutItemPostUserBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public String getTime() {
        return this.mTime;
    }

    @Nullable
    public PostListBean.UserBean getUserBean() {
        return this.mUserBean;
    }

    public abstract void setTime(@Nullable String str);

    public abstract void setUserBean(@Nullable PostListBean.UserBean userBean);

    @Deprecated
    public static LayoutItemPostUserBinding bind(@NonNull View view, @Nullable Object obj) {
        return (LayoutItemPostUserBinding) ViewDataBinding.bind(obj, view, R.layout.layout_item_post_user);
    }

    @NonNull
    @Deprecated
    public static LayoutItemPostUserBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (LayoutItemPostUserBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.layout_item_post_user, viewGroup, z, obj);
    }

    @NonNull
    public static LayoutItemPostUserBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static LayoutItemPostUserBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (LayoutItemPostUserBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.layout_item_post_user, null, false, obj);
    }
}
