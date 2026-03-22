package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.databinding.Bindable;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.jbzd.media.movecartoons.bean.response.GroupBean;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class ItemPayTypeVerticalBinding extends ViewDataBinding {

    @NonNull
    public final CheckBox checkbox;

    @NonNull
    public final ImageView imgPayIcon;

    @Bindable
    public GroupBean.PaymentsBean mItem;

    @NonNull
    public final ConstraintLayout root;

    @NonNull
    public final TextView txtPayName;

    public ItemPayTypeVerticalBinding(Object obj, View view, int i2, CheckBox checkBox, ImageView imageView, ConstraintLayout constraintLayout, TextView textView) {
        super(obj, view, i2);
        this.checkbox = checkBox;
        this.imgPayIcon = imageView;
        this.root = constraintLayout;
        this.txtPayName = textView;
    }

    public static ItemPayTypeVerticalBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemPayTypeVerticalBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public GroupBean.PaymentsBean getItem() {
        return this.mItem;
    }

    public abstract void setItem(@Nullable GroupBean.PaymentsBean paymentsBean);

    @Deprecated
    public static ItemPayTypeVerticalBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemPayTypeVerticalBinding) ViewDataBinding.bind(obj, view, R.layout.item_pay_type_vertical);
    }

    @NonNull
    @Deprecated
    public static ItemPayTypeVerticalBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemPayTypeVerticalBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_pay_type_vertical, viewGroup, z, obj);
    }

    @NonNull
    public static ItemPayTypeVerticalBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemPayTypeVerticalBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemPayTypeVerticalBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_pay_type_vertical, null, false, obj);
    }
}
