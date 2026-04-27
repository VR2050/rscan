package im.uwrkaxlmjj.ui.hui.transfer;

import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import butterknife.Unbinder;
import butterknife.internal.DebouncingOnClickListener;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class TransferStatusActivity_ViewBinding implements Unbinder {
    private TransferStatusActivity target;
    private View view7f0900aa;
    private View view7f0905a7;

    public TransferStatusActivity_ViewBinding(final TransferStatusActivity target, View source) {
        this.target = target;
        target.ivTransferStateImg = (ImageView) Utils.findRequiredViewAsType(source, R.attr.ivTransferStateImg, "field 'ivTransferStateImg'", ImageView.class);
        target.tvTransferStateText = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvTransferStateText, "field 'tvTransferStateText'", TextView.class);
        target.tvTransferAmount = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvTransferAmount, "field 'tvTransferAmount'", MryTextView.class);
        target.tvHongbaoType = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvHongbaoType, "field 'tvHongbaoType'", TextView.class);
        View view = Utils.findRequiredView(source, R.attr.btnTransferStateButton, "field 'btnTransferStateButton' and method 'onClick'");
        target.btnTransferStateButton = (MryRoundButton) Utils.castView(view, R.attr.btnTransferStateButton, "field 'btnTransferStateButton'", MryRoundButton.class);
        this.view7f0900aa = view;
        view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.TransferStatusActivity_ViewBinding.1
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onClick(p0);
            }
        });
        View view2 = Utils.findRequiredView(source, R.attr.tvWallet, "field 'tvWallet' and method 'onClick'");
        target.tvWallet = (TextView) Utils.castView(view2, R.attr.tvWallet, "field 'tvWallet'", TextView.class);
        this.view7f0905a7 = view2;
        view2.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.transfer.TransferStatusActivity_ViewBinding.2
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onClick(p0);
            }
        });
        target.tvRefuseTransfer = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvRefuseTransfer, "field 'tvRefuseTransfer'", TextView.class);
        target.llTransferAboutLayout = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.llTransferAboutLayout, "field 'llTransferAboutLayout'", LinearLayout.class);
        target.tvTransferTime = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvTransferTime, "field 'tvTransferTime'", TextView.class);
        target.tvActionTime = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvActionTime, "field 'tvActionTime'", TextView.class);
        target.tvRemarks = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvRemarks, "field 'tvRemarks'", TextView.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        TransferStatusActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.ivTransferStateImg = null;
        target.tvTransferStateText = null;
        target.tvTransferAmount = null;
        target.tvHongbaoType = null;
        target.btnTransferStateButton = null;
        target.tvWallet = null;
        target.tvRefuseTransfer = null;
        target.llTransferAboutLayout = null;
        target.tvTransferTime = null;
        target.tvActionTime = null;
        target.tvRemarks = null;
        this.view7f0900aa.setOnClickListener(null);
        this.view7f0900aa = null;
        this.view7f0905a7.setOnClickListener(null);
        this.view7f0905a7 = null;
    }
}
