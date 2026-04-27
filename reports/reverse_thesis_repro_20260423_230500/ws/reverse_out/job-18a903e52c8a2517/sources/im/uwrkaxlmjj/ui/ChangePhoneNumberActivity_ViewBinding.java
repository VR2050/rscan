package im.uwrkaxlmjj.ui;

import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import butterknife.Unbinder;
import butterknife.internal.DebouncingOnClickListener;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.hviews.MryEditText;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ChangePhoneNumberActivity_ViewBinding implements Unbinder {
    private ChangePhoneNumberActivity target;
    private View view7f0900b4;
    private View view7f090217;
    private View view7f0905cb;
    private View view7f090629;

    public ChangePhoneNumberActivity_ViewBinding(final ChangePhoneNumberActivity target, View source) {
        this.target = target;
        View view = Utils.findRequiredView(source, R.attr.tv_country_code, "field 'mTvCountryCode' and method 'onViewClicked'");
        target.mTvCountryCode = (MryTextView) Utils.castView(view, R.attr.tv_country_code, "field 'mTvCountryCode'", MryTextView.class);
        this.view7f0905cb = view;
        view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.ChangePhoneNumberActivity_ViewBinding.1
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.mEtPhoneNumber = (MryEditText) Utils.findRequiredViewAsType(source, R.attr.et_phone_number, "field 'mEtPhoneNumber'", MryEditText.class);
        View view2 = Utils.findRequiredView(source, R.attr.iv_clear, "field 'mIvClear' and method 'onViewClicked'");
        target.mIvClear = (ImageView) Utils.castView(view2, R.attr.iv_clear, "field 'mIvClear'", ImageView.class);
        this.view7f090217 = view2;
        view2.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.ChangePhoneNumberActivity_ViewBinding.2
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.mLlPhoneContainer = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.ll_phone_container, "field 'mLlPhoneContainer'", LinearLayout.class);
        target.mEtCode = (MryEditText) Utils.findRequiredViewAsType(source, R.attr.et_code, "field 'mEtCode'", MryEditText.class);
        View view3 = Utils.findRequiredView(source, R.attr.tv_send_code, "field 'mTvSendCode' and method 'onViewClicked'");
        target.mTvSendCode = (MryTextView) Utils.castView(view3, R.attr.tv_send_code, "field 'mTvSendCode'", MryTextView.class);
        this.view7f090629 = view3;
        view3.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.ChangePhoneNumberActivity_ViewBinding.3
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.mLlCodeContainer = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.ll_code_container, "field 'mLlCodeContainer'", LinearLayout.class);
        View view4 = Utils.findRequiredView(source, R.attr.btn_submit, "field 'mBtnSubmit' and method 'onViewClicked'");
        target.mBtnSubmit = (MryRoundButton) Utils.castView(view4, R.attr.btn_submit, "field 'mBtnSubmit'", MryRoundButton.class);
        this.view7f0900b4 = view4;
        view4.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.ChangePhoneNumberActivity_ViewBinding.4
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        ChangePhoneNumberActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.mTvCountryCode = null;
        target.mEtPhoneNumber = null;
        target.mIvClear = null;
        target.mLlPhoneContainer = null;
        target.mEtCode = null;
        target.mTvSendCode = null;
        target.mLlCodeContainer = null;
        target.mBtnSubmit = null;
        this.view7f0905cb.setOnClickListener(null);
        this.view7f0905cb = null;
        this.view7f090217.setOnClickListener(null);
        this.view7f090217 = null;
        this.view7f090629.setOnClickListener(null);
        this.view7f090629 = null;
        this.view7f0900b4.setOnClickListener(null);
        this.view7f0900b4 = null;
    }
}
