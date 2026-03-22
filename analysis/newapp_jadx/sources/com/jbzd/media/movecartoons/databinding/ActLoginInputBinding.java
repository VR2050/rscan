package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.databinding.Bindable;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.jbzd.media.movecartoons.p396ui.settings.SignViewModel;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.widget.CommonShapeButton;

/* loaded from: classes2.dex */
public abstract class ActLoginInputBinding extends ViewDataBinding {

    @NonNull
    public final CommonShapeButton btnLoginNow;

    @NonNull
    public final AppCompatEditText editLoginPhone;

    @NonNull
    public final AppCompatEditText editLoginPwd;

    @NonNull
    public final ImageView ivHeader;

    @NonNull
    public final ImageView ivTipsLogin;

    @Bindable
    public SignViewModel mViewModel;

    @NonNull
    public final TextView tvAccountLoginTips;

    @NonNull
    public final TextView tvScancodeLogin;

    @NonNull
    public final TextView txtSignNow;

    public ActLoginInputBinding(Object obj, View view, int i2, CommonShapeButton commonShapeButton, AppCompatEditText appCompatEditText, AppCompatEditText appCompatEditText2, ImageView imageView, ImageView imageView2, TextView textView, TextView textView2, TextView textView3) {
        super(obj, view, i2);
        this.btnLoginNow = commonShapeButton;
        this.editLoginPhone = appCompatEditText;
        this.editLoginPwd = appCompatEditText2;
        this.ivHeader = imageView;
        this.ivTipsLogin = imageView2;
        this.tvAccountLoginTips = textView;
        this.tvScancodeLogin = textView2;
        this.txtSignNow = textView3;
    }

    public static ActLoginInputBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ActLoginInputBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public SignViewModel getViewModel() {
        return this.mViewModel;
    }

    public abstract void setViewModel(@Nullable SignViewModel signViewModel);

    @Deprecated
    public static ActLoginInputBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ActLoginInputBinding) ViewDataBinding.bind(obj, view, R.layout.act_login_input);
    }

    @NonNull
    @Deprecated
    public static ActLoginInputBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ActLoginInputBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.act_login_input, viewGroup, z, obj);
    }

    @NonNull
    public static ActLoginInputBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ActLoginInputBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ActLoginInputBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.act_login_input, null, false, obj);
    }
}
