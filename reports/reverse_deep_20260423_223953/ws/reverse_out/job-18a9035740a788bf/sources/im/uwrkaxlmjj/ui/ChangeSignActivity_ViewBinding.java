package im.uwrkaxlmjj.ui;

import android.view.View;
import android.widget.RelativeLayout;
import butterknife.Unbinder;
import butterknife.internal.DebouncingOnClickListener;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.hviews.MryEditText;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ChangeSignActivity_ViewBinding implements Unbinder {
    private ChangeSignActivity target;
    private View view7f0900b4;

    public ChangeSignActivity_ViewBinding(final ChangeSignActivity target, View source) {
        this.target = target;
        target.mEtSignature = (MryEditText) Utils.findRequiredViewAsType(source, R.attr.et_signature, "field 'mEtSignature'", MryEditText.class);
        target.mTvCount = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tv_count, "field 'mTvCount'", MryTextView.class);
        target.mRlSignatureContainer = (RelativeLayout) Utils.findRequiredViewAsType(source, R.attr.rl_signature_container, "field 'mRlSignatureContainer'", RelativeLayout.class);
        View view = Utils.findRequiredView(source, R.attr.btn_submit, "field 'mBtnSubmit' and method 'onViewClicked'");
        target.mBtnSubmit = (MryRoundButton) Utils.castView(view, R.attr.btn_submit, "field 'mBtnSubmit'", MryRoundButton.class);
        this.view7f0900b4 = view;
        view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.ChangeSignActivity_ViewBinding.1
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked();
            }
        });
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        ChangeSignActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.mEtSignature = null;
        target.mTvCount = null;
        target.mRlSignatureContainer = null;
        target.mBtnSubmit = null;
        this.view7f0900b4.setOnClickListener(null);
        this.view7f0900b4 = null;
    }
}
