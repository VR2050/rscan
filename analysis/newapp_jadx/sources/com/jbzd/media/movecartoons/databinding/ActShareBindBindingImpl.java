package com.jbzd.media.movecartoons.databinding;

import android.util.SparseIntArray;
import android.view.View;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatButton;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.databinding.DataBindingComponent;
import androidx.databinding.InverseBindingListener;
import androidx.databinding.ViewDataBinding;
import androidx.databinding.adapters.TextViewBindingAdapter;
import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.p396ui.share.BindCodeViewModel;
import p005b.p006a.p007a.p008a.p014p.p015a.ViewOnClickListenerC0910a;

/* loaded from: classes2.dex */
public class ActShareBindBindingImpl extends ActShareBindBinding implements ViewOnClickListenerC0910a.a {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds = null;
    private InverseBindingListener etBindandroidTextAttrChanged;

    @Nullable
    private final View.OnClickListener mCallback4;
    private long mDirtyFlags;

    @NonNull
    private final LinearLayout mboundView0;

    /* renamed from: com.jbzd.media.movecartoons.databinding.ActShareBindBindingImpl$a */
    public class C3634a implements InverseBindingListener {
        public C3634a() {
        }

        @Override // androidx.databinding.InverseBindingListener
        public void onChange() {
            String textString = TextViewBindingAdapter.getTextString(ActShareBindBindingImpl.this.etBind);
            BindCodeViewModel bindCodeViewModel = ActShareBindBindingImpl.this.mViewModel;
            if (bindCodeViewModel != null) {
                MutableLiveData<String> bindCode = bindCodeViewModel.getBindCode();
                if (bindCode != null) {
                    bindCode.setValue(textString);
                }
            }
        }
    }

    public ActShareBindBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 3, sIncludes, sViewsWithIds));
    }

    private boolean onChangeViewModelBindCode(MutableLiveData<String> mutableLiveData, int i2) {
        if (i2 != 0) {
            return false;
        }
        synchronized (this) {
            this.mDirtyFlags |= 1;
        }
        return true;
    }

    @Override // p005b.p006a.p007a.p008a.p014p.p015a.ViewOnClickListenerC0910a.a
    public final void _internalCallbackOnClick(int i2, View view) {
        BindCodeViewModel bindCodeViewModel = this.mViewModel;
        if (bindCodeViewModel != null) {
            bindCodeViewModel.bindParent();
        }
    }

    @Override // androidx.databinding.ViewDataBinding
    public void executeBindings() {
        long j2;
        String str;
        synchronized (this) {
            j2 = this.mDirtyFlags;
            this.mDirtyFlags = 0L;
        }
        BindCodeViewModel bindCodeViewModel = this.mViewModel;
        long j3 = 7 & j2;
        boolean z = false;
        if (j3 != 0) {
            MutableLiveData<String> bindCode = bindCodeViewModel != null ? bindCodeViewModel.getBindCode() : null;
            updateLiveDataRegistration(0, bindCode);
            str = bindCode != null ? bindCode.getValue() : null;
            if ((str != null ? str.length() : 0) != 0) {
                z = true;
            }
        } else {
            str = null;
        }
        if (j3 != 0) {
            TextViewBindingAdapter.setText(this.etBind, str);
            this.submit.setEnabled(z);
        }
        if ((j2 & 4) != 0) {
            TextViewBindingAdapter.setTextWatcher(this.etBind, null, null, null, this.etBindandroidTextAttrChanged);
            this.submit.setOnClickListener(this.mCallback4);
        }
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean hasPendingBindings() {
        synchronized (this) {
            return this.mDirtyFlags != 0;
        }
    }

    @Override // androidx.databinding.ViewDataBinding
    public void invalidateAll() {
        synchronized (this) {
            this.mDirtyFlags = 4L;
        }
        requestRebind();
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean onFieldChange(int i2, Object obj, int i3) {
        if (i2 != 0) {
            return false;
        }
        return onChangeViewModelBindCode((MutableLiveData) obj, i3);
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean setVariable(int i2, @Nullable Object obj) {
        if (5 != i2) {
            return false;
        }
        setViewModel((BindCodeViewModel) obj);
        return true;
    }

    @Override // com.jbzd.media.movecartoons.databinding.ActShareBindBinding
    public void setViewModel(@Nullable BindCodeViewModel bindCodeViewModel) {
        this.mViewModel = bindCodeViewModel;
        synchronized (this) {
            this.mDirtyFlags |= 2;
        }
        notifyPropertyChanged(5);
        super.requestRebind();
    }

    private ActShareBindBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 1, (AppCompatEditText) objArr[1], (AppCompatButton) objArr[2]);
        this.etBindandroidTextAttrChanged = new C3634a();
        this.mDirtyFlags = -1L;
        this.etBind.setTag(null);
        LinearLayout linearLayout = (LinearLayout) objArr[0];
        this.mboundView0 = linearLayout;
        linearLayout.setTag(null);
        this.submit.setTag(null);
        setRootTag(view);
        this.mCallback4 = new ViewOnClickListenerC0910a(this, 1);
        invalidateAll();
    }
}
