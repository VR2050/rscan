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
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.PageRefreshLayout;
import com.jbzd.media.movecartoons.p396ui.vip.ExchangeViewModel;
import com.qnmd.adnnm.da0yzo.R;
import p005b.p006a.p007a.p008a.p014p.p015a.ViewOnClickListenerC0910a;

/* loaded from: classes2.dex */
public class ActExchangeBindingImpl extends ActExchangeBinding implements ViewOnClickListenerC0910a.a {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds;
    private InverseBindingListener etContentandroidTextAttrChanged;

    @Nullable
    private final View.OnClickListener mCallback8;
    private long mDirtyFlags;

    @NonNull
    private final LinearLayout mboundView0;

    /* renamed from: com.jbzd.media.movecartoons.databinding.ActExchangeBindingImpl$a */
    public class C3628a implements InverseBindingListener {
        public C3628a() {
        }

        @Override // androidx.databinding.InverseBindingListener
        public void onChange() {
            String textString = TextViewBindingAdapter.getTextString(ActExchangeBindingImpl.this.etContent);
            ExchangeViewModel exchangeViewModel = ActExchangeBindingImpl.this.mViewModel;
            if (exchangeViewModel != null) {
                MutableLiveData<String> exchangeCode = exchangeViewModel.getExchangeCode();
                if (exchangeCode != null) {
                    exchangeCode.setValue(textString);
                }
            }
        }
    }

    static {
        SparseIntArray sparseIntArray = new SparseIntArray();
        sViewsWithIds = sparseIntArray;
        sparseIntArray.put(R.id.pager, 3);
        sparseIntArray.put(R.id.rv_exchange, 4);
    }

    public ActExchangeBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 5, sIncludes, sViewsWithIds));
    }

    private boolean onChangeViewModelExchangeCode(MutableLiveData<String> mutableLiveData, int i2) {
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
        ExchangeViewModel exchangeViewModel = this.mViewModel;
        if (exchangeViewModel != null) {
            exchangeViewModel.exchangeVip();
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
        ExchangeViewModel exchangeViewModel = this.mViewModel;
        long j3 = 7 & j2;
        boolean z = false;
        if (j3 != 0) {
            MutableLiveData<String> exchangeCode = exchangeViewModel != null ? exchangeViewModel.getExchangeCode() : null;
            updateLiveDataRegistration(0, exchangeCode);
            str = exchangeCode != null ? exchangeCode.getValue() : null;
            if ((str != null ? str.length() : 0) > 0) {
                z = true;
            }
        } else {
            str = null;
        }
        if (j3 != 0) {
            TextViewBindingAdapter.setText(this.etContent, str);
            this.tvSubmit.setEnabled(z);
        }
        if ((j2 & 4) != 0) {
            TextViewBindingAdapter.setTextWatcher(this.etContent, null, null, null, this.etContentandroidTextAttrChanged);
            this.tvSubmit.setOnClickListener(this.mCallback8);
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
        return onChangeViewModelExchangeCode((MutableLiveData) obj, i3);
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean setVariable(int i2, @Nullable Object obj) {
        if (5 != i2) {
            return false;
        }
        setViewModel((ExchangeViewModel) obj);
        return true;
    }

    @Override // com.jbzd.media.movecartoons.databinding.ActExchangeBinding
    public void setViewModel(@Nullable ExchangeViewModel exchangeViewModel) {
        this.mViewModel = exchangeViewModel;
        synchronized (this) {
            this.mDirtyFlags |= 2;
        }
        notifyPropertyChanged(5);
        super.requestRebind();
    }

    private ActExchangeBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 1, (AppCompatEditText) objArr[1], (PageRefreshLayout) objArr[3], (RecyclerView) objArr[4], (AppCompatButton) objArr[2]);
        this.etContentandroidTextAttrChanged = new C3628a();
        this.mDirtyFlags = -1L;
        this.etContent.setTag(null);
        LinearLayout linearLayout = (LinearLayout) objArr[0];
        this.mboundView0 = linearLayout;
        linearLayout.setTag(null);
        this.tvSubmit.setTag(null);
        setRootTag(view);
        this.mCallback8 = new ViewOnClickListenerC0910a(this, 1);
        invalidateAll();
    }
}
