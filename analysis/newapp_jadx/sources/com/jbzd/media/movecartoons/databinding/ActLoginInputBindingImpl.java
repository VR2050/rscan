package com.jbzd.media.movecartoons.databinding;

import android.util.SparseIntArray;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.databinding.DataBindingComponent;
import androidx.databinding.InverseBindingListener;
import androidx.databinding.ViewDataBinding;
import androidx.databinding.adapters.TextViewBindingAdapter;
import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.p396ui.settings.SignViewModel;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.widget.CommonShapeButton;
import p005b.p006a.p007a.p008a.p014p.p015a.ViewOnClickListenerC0910a;

/* loaded from: classes2.dex */
public class ActLoginInputBindingImpl extends ActLoginInputBinding implements ViewOnClickListenerC0910a.a {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds;
    private InverseBindingListener editLoginPhoneandroidTextAttrChanged;
    private InverseBindingListener editLoginPwdandroidTextAttrChanged;

    @Nullable
    private final View.OnClickListener mCallback6;

    @Nullable
    private final View.OnClickListener mCallback7;
    private long mDirtyFlags;

    @NonNull
    private final ConstraintLayout mboundView0;

    /* renamed from: com.jbzd.media.movecartoons.databinding.ActLoginInputBindingImpl$a */
    public class C3629a implements InverseBindingListener {
        public C3629a() {
        }

        @Override // androidx.databinding.InverseBindingListener
        public void onChange() {
            String textString = TextViewBindingAdapter.getTextString(ActLoginInputBindingImpl.this.editLoginPhone);
            SignViewModel signViewModel = ActLoginInputBindingImpl.this.mViewModel;
            if (signViewModel != null) {
                MutableLiveData<String> phoneData = signViewModel.getPhoneData();
                if (phoneData != null) {
                    phoneData.setValue(textString);
                }
            }
        }
    }

    /* renamed from: com.jbzd.media.movecartoons.databinding.ActLoginInputBindingImpl$b */
    public class C3630b implements InverseBindingListener {
        public C3630b() {
        }

        @Override // androidx.databinding.InverseBindingListener
        public void onChange() {
            String textString = TextViewBindingAdapter.getTextString(ActLoginInputBindingImpl.this.editLoginPwd);
            SignViewModel signViewModel = ActLoginInputBindingImpl.this.mViewModel;
            if (signViewModel != null) {
                MutableLiveData<String> pwdData = signViewModel.getPwdData();
                if (pwdData != null) {
                    pwdData.setValue(textString);
                }
            }
        }
    }

    static {
        SparseIntArray sparseIntArray = new SparseIntArray();
        sViewsWithIds = sparseIntArray;
        sparseIntArray.put(R.id.iv_header, 5);
        sparseIntArray.put(R.id.tv_scancode_login, 6);
        sparseIntArray.put(R.id.iv_tips_login_, 7);
        sparseIntArray.put(R.id.tv_account_login_tips, 8);
    }

    public ActLoginInputBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 9, sIncludes, sViewsWithIds));
    }

    private boolean onChangeViewModelPhoneData(MutableLiveData<String> mutableLiveData, int i2) {
        if (i2 != 0) {
            return false;
        }
        synchronized (this) {
            this.mDirtyFlags |= 1;
        }
        return true;
    }

    private boolean onChangeViewModelPwdData(MutableLiveData<String> mutableLiveData, int i2) {
        if (i2 != 0) {
            return false;
        }
        synchronized (this) {
            this.mDirtyFlags |= 2;
        }
        return true;
    }

    @Override // p005b.p006a.p007a.p008a.p014p.p015a.ViewOnClickListenerC0910a.a
    public final void _internalCallbackOnClick(int i2, View view) {
        if (i2 == 1) {
            SignViewModel signViewModel = this.mViewModel;
            if (signViewModel != null) {
                signViewModel.refreshAccount(getRoot().getContext());
                return;
            }
            return;
        }
        if (i2 != 2) {
            return;
        }
        SignViewModel signViewModel2 = this.mViewModel;
        if (signViewModel2 != null) {
            signViewModel2.register(getRoot().getContext());
        }
    }

    @Override // androidx.databinding.ViewDataBinding
    public void executeBindings() {
        long j2;
        MutableLiveData<String> mutableLiveData;
        String str;
        String str2;
        boolean z;
        String str3;
        long j3;
        boolean z2;
        synchronized (this) {
            j2 = this.mDirtyFlags;
            this.mDirtyFlags = 0L;
        }
        SignViewModel signViewModel = this.mViewModel;
        long j4 = j2 & 15;
        boolean z3 = false;
        if (j4 != 0) {
            MutableLiveData<String> phoneData = signViewModel != null ? signViewModel.getPhoneData() : null;
            updateLiveDataRegistration(0, phoneData);
            str = phoneData != null ? phoneData.getValue() : null;
            z = (str != null ? str.length() : 0) > 0;
            if (j4 != 0) {
                j2 = z ? j2 | 32 : j2 | 16;
            }
            if ((j2 & 14) != 0) {
                mutableLiveData = signViewModel != null ? signViewModel.getPwdData() : null;
                updateLiveDataRegistration(1, mutableLiveData);
                str2 = mutableLiveData != null ? mutableLiveData.getValue() : null;
            } else {
                mutableLiveData = null;
                str2 = null;
            }
        } else {
            mutableLiveData = null;
            str = null;
            str2 = null;
            z = false;
        }
        if ((32 & j2) != 0) {
            if (signViewModel != null) {
                mutableLiveData = signViewModel.getPwdData();
            }
            updateLiveDataRegistration(1, mutableLiveData);
            if (mutableLiveData != null) {
                str2 = mutableLiveData.getValue();
            }
            z2 = (str2 != null ? str2.length() : 0) > 0;
            str3 = str2;
            j3 = 15;
        } else {
            str3 = str2;
            j3 = 15;
            z2 = false;
        }
        long j5 = j3 & j2;
        if (j5 != 0 && z) {
            z3 = z2;
        }
        if (j5 != 0) {
            this.btnLoginNow.setEnabled(z3);
        }
        if ((8 & j2) != 0) {
            this.btnLoginNow.setOnClickListener(this.mCallback6);
            TextViewBindingAdapter.setTextWatcher(this.editLoginPhone, null, null, null, this.editLoginPhoneandroidTextAttrChanged);
            TextViewBindingAdapter.setTextWatcher(this.editLoginPwd, null, null, null, this.editLoginPwdandroidTextAttrChanged);
            this.txtSignNow.setOnClickListener(this.mCallback7);
        }
        if ((13 & j2) != 0) {
            TextViewBindingAdapter.setText(this.editLoginPhone, str);
        }
        if ((j2 & 14) != 0) {
            TextViewBindingAdapter.setText(this.editLoginPwd, str3);
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
            this.mDirtyFlags = 8L;
        }
        requestRebind();
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean onFieldChange(int i2, Object obj, int i3) {
        if (i2 == 0) {
            return onChangeViewModelPhoneData((MutableLiveData) obj, i3);
        }
        if (i2 != 1) {
            return false;
        }
        return onChangeViewModelPwdData((MutableLiveData) obj, i3);
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean setVariable(int i2, @Nullable Object obj) {
        if (5 != i2) {
            return false;
        }
        setViewModel((SignViewModel) obj);
        return true;
    }

    @Override // com.jbzd.media.movecartoons.databinding.ActLoginInputBinding
    public void setViewModel(@Nullable SignViewModel signViewModel) {
        this.mViewModel = signViewModel;
        synchronized (this) {
            this.mDirtyFlags |= 4;
        }
        notifyPropertyChanged(5);
        super.requestRebind();
    }

    private ActLoginInputBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 2, (CommonShapeButton) objArr[3], (AppCompatEditText) objArr[1], (AppCompatEditText) objArr[2], (ImageView) objArr[5], (ImageView) objArr[7], (TextView) objArr[8], (TextView) objArr[6], (TextView) objArr[4]);
        this.editLoginPhoneandroidTextAttrChanged = new C3629a();
        this.editLoginPwdandroidTextAttrChanged = new C3630b();
        this.mDirtyFlags = -1L;
        this.btnLoginNow.setTag(null);
        this.editLoginPhone.setTag(null);
        this.editLoginPwd.setTag(null);
        ConstraintLayout constraintLayout = (ConstraintLayout) objArr[0];
        this.mboundView0 = constraintLayout;
        constraintLayout.setTag(null);
        this.txtSignNow.setTag(null);
        setRootTag(view);
        this.mCallback6 = new ViewOnClickListenerC0910a(this, 1);
        this.mCallback7 = new ViewOnClickListenerC0910a(this, 2);
        invalidateAll();
    }
}
