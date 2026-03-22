package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
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
public abstract class ActRegisterInputBinding extends ViewDataBinding {

    @NonNull
    public final CommonShapeButton btnRegisterNow;

    @NonNull
    public final AppCompatEditText edLoginInviteCode;

    @NonNull
    public final AppCompatEditText editRegisterPhone;

    @NonNull
    public final AppCompatEditText editRegisterPwd;

    @NonNull
    public final ImageView ivHeader;

    @Bindable
    public SignViewModel mViewModel;

    public ActRegisterInputBinding(Object obj, View view, int i2, CommonShapeButton commonShapeButton, AppCompatEditText appCompatEditText, AppCompatEditText appCompatEditText2, AppCompatEditText appCompatEditText3, ImageView imageView) {
        super(obj, view, i2);
        this.btnRegisterNow = commonShapeButton;
        this.edLoginInviteCode = appCompatEditText;
        this.editRegisterPhone = appCompatEditText2;
        this.editRegisterPwd = appCompatEditText3;
        this.ivHeader = imageView;
    }

    public static ActRegisterInputBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ActRegisterInputBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public SignViewModel getViewModel() {
        return this.mViewModel;
    }

    public abstract void setViewModel(@Nullable SignViewModel signViewModel);

    @Deprecated
    public static ActRegisterInputBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ActRegisterInputBinding) ViewDataBinding.bind(obj, view, R.layout.act_register_input);
    }

    @NonNull
    @Deprecated
    public static ActRegisterInputBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ActRegisterInputBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.act_register_input, viewGroup, z, obj);
    }

    @NonNull
    public static ActRegisterInputBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ActRegisterInputBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ActRegisterInputBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.act_register_input, null, false, obj);
    }
}
