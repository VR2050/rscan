package com.jbzd.media.movecartoons.databinding;

import android.util.SparseIntArray;
import android.view.View;
import android.widget.ImageView;
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
public class ActRegisterInputBindingImpl extends ActRegisterInputBinding implements ViewOnClickListenerC0910a.a {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds;
    private InverseBindingListener edLoginInviteCodeandroidTextAttrChanged;
    private InverseBindingListener editRegisterPhoneandroidTextAttrChanged;
    private InverseBindingListener editRegisterPwdandroidTextAttrChanged;

    @Nullable
    private final View.OnClickListener mCallback5;
    private long mDirtyFlags;

    @NonNull
    private final ConstraintLayout mboundView0;

    /* renamed from: com.jbzd.media.movecartoons.databinding.ActRegisterInputBindingImpl$a */
    public class C3631a implements InverseBindingListener {
        public C3631a() {
        }

        @Override // androidx.databinding.InverseBindingListener
        public void onChange() {
            String textString = TextViewBindingAdapter.getTextString(ActRegisterInputBindingImpl.this.edLoginInviteCode);
            SignViewModel signViewModel = ActRegisterInputBindingImpl.this.mViewModel;
            if (signViewModel != null) {
                MutableLiveData<String> inviteCode = signViewModel.getInviteCode();
                if (inviteCode != null) {
                    inviteCode.setValue(textString);
                }
            }
        }
    }

    /* renamed from: com.jbzd.media.movecartoons.databinding.ActRegisterInputBindingImpl$b */
    public class C3632b implements InverseBindingListener {
        public C3632b() {
        }

        @Override // androidx.databinding.InverseBindingListener
        public void onChange() {
            String textString = TextViewBindingAdapter.getTextString(ActRegisterInputBindingImpl.this.editRegisterPhone);
            SignViewModel signViewModel = ActRegisterInputBindingImpl.this.mViewModel;
            if (signViewModel != null) {
                MutableLiveData<String> phoneData = signViewModel.getPhoneData();
                if (phoneData != null) {
                    phoneData.setValue(textString);
                }
            }
        }
    }

    /* renamed from: com.jbzd.media.movecartoons.databinding.ActRegisterInputBindingImpl$c */
    public class C3633c implements InverseBindingListener {
        public C3633c() {
        }

        @Override // androidx.databinding.InverseBindingListener
        public void onChange() {
            String textString = TextViewBindingAdapter.getTextString(ActRegisterInputBindingImpl.this.editRegisterPwd);
            SignViewModel signViewModel = ActRegisterInputBindingImpl.this.mViewModel;
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
    }

    public ActRegisterInputBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 6, sIncludes, sViewsWithIds));
    }

    private boolean onChangeViewModelInviteCode(MutableLiveData<String> mutableLiveData, int i2) {
        if (i2 != 0) {
            return false;
        }
        synchronized (this) {
            this.mDirtyFlags |= 4;
        }
        return true;
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
        SignViewModel signViewModel = this.mViewModel;
        if (signViewModel != null) {
            signViewModel.refreshAccount(getRoot().getContext());
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:46:0x00b2, code lost:
    
        if ((r10 != null ? r10.length() : 0) > 0) goto L61;
     */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0076  */
    @Override // androidx.databinding.ViewDataBinding
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void executeBindings() {
        /*
            Method dump skipped, instructions count: 275
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.databinding.ActRegisterInputBindingImpl.executeBindings():void");
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
            this.mDirtyFlags = 16L;
        }
        requestRebind();
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean onFieldChange(int i2, Object obj, int i3) {
        if (i2 == 0) {
            return onChangeViewModelPhoneData((MutableLiveData) obj, i3);
        }
        if (i2 == 1) {
            return onChangeViewModelPwdData((MutableLiveData) obj, i3);
        }
        if (i2 != 2) {
            return false;
        }
        return onChangeViewModelInviteCode((MutableLiveData) obj, i3);
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean setVariable(int i2, @Nullable Object obj) {
        if (5 != i2) {
            return false;
        }
        setViewModel((SignViewModel) obj);
        return true;
    }

    @Override // com.jbzd.media.movecartoons.databinding.ActRegisterInputBinding
    public void setViewModel(@Nullable SignViewModel signViewModel) {
        this.mViewModel = signViewModel;
        synchronized (this) {
            this.mDirtyFlags |= 8;
        }
        notifyPropertyChanged(5);
        super.requestRebind();
    }

    private ActRegisterInputBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 3, (CommonShapeButton) objArr[4], (AppCompatEditText) objArr[3], (AppCompatEditText) objArr[1], (AppCompatEditText) objArr[2], (ImageView) objArr[5]);
        this.edLoginInviteCodeandroidTextAttrChanged = new C3631a();
        this.editRegisterPhoneandroidTextAttrChanged = new C3632b();
        this.editRegisterPwdandroidTextAttrChanged = new C3633c();
        this.mDirtyFlags = -1L;
        this.btnRegisterNow.setTag(null);
        this.edLoginInviteCode.setTag(null);
        this.editRegisterPhone.setTag(null);
        this.editRegisterPwd.setTag(null);
        ConstraintLayout constraintLayout = (ConstraintLayout) objArr[0];
        this.mboundView0 = constraintLayout;
        constraintLayout.setTag(null);
        setRootTag(view);
        this.mCallback5 = new ViewOnClickListenerC0910a(this, 1);
        invalidateAll();
    }
}
