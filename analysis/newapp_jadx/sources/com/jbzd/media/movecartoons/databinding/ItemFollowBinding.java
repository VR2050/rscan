package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.ToggleButton;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.databinding.Bindable;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.bean.response.FollowItem;
import com.jbzd.media.movecartoons.view.FollowTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class ItemFollowBinding extends ViewDataBinding {

    @NonNull
    public final ToggleButton btnFollow;

    @NonNull
    public final ShapeableImageView civAvatar;

    @NonNull
    public final FollowTextView itvItemFollowState;

    @NonNull
    public final LinearLayout llItemFollow;

    @Bindable
    public FollowItem mItem;

    @NonNull
    public final TextView tvPostdetailNickname;

    public ItemFollowBinding(Object obj, View view, int i2, ToggleButton toggleButton, ShapeableImageView shapeableImageView, FollowTextView followTextView, LinearLayout linearLayout, TextView textView) {
        super(obj, view, i2);
        this.btnFollow = toggleButton;
        this.civAvatar = shapeableImageView;
        this.itvItemFollowState = followTextView;
        this.llItemFollow = linearLayout;
        this.tvPostdetailNickname = textView;
    }

    public static ItemFollowBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemFollowBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public FollowItem getItem() {
        return this.mItem;
    }

    public abstract void setItem(@Nullable FollowItem followItem);

    @Deprecated
    public static ItemFollowBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemFollowBinding) ViewDataBinding.bind(obj, view, R.layout.item_follow);
    }

    @NonNull
    @Deprecated
    public static ItemFollowBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemFollowBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_follow, viewGroup, z, obj);
    }

    @NonNull
    public static ItemFollowBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemFollowBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemFollowBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_follow, null, false, obj);
    }
}
