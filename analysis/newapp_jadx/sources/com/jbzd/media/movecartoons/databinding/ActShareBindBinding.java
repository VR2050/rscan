package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatButton;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.databinding.Bindable;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.jbzd.media.movecartoons.p396ui.share.BindCodeViewModel;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class ActShareBindBinding extends ViewDataBinding {

    @NonNull
    public final AppCompatEditText etBind;

    @Bindable
    public BindCodeViewModel mViewModel;

    @NonNull
    public final AppCompatButton submit;

    public ActShareBindBinding(Object obj, View view, int i2, AppCompatEditText appCompatEditText, AppCompatButton appCompatButton) {
        super(obj, view, i2);
        this.etBind = appCompatEditText;
        this.submit = appCompatButton;
    }

    public static ActShareBindBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ActShareBindBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public BindCodeViewModel getViewModel() {
        return this.mViewModel;
    }

    public abstract void setViewModel(@Nullable BindCodeViewModel bindCodeViewModel);

    @Deprecated
    public static ActShareBindBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ActShareBindBinding) ViewDataBinding.bind(obj, view, R.layout.act_share_bind);
    }

    @NonNull
    @Deprecated
    public static ActShareBindBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ActShareBindBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.act_share_bind, viewGroup, z, obj);
    }

    @NonNull
    public static ActShareBindBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ActShareBindBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ActShareBindBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.act_share_bind, null, false, obj);
    }
}
