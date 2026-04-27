package im.uwrkaxlmjj.ui.hui.transfer;

import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import butterknife.Unbinder;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class TransferSendActivity_ViewBinding implements Unbinder {
    private TransferSendActivity target;

    public TransferSendActivity_ViewBinding(TransferSendActivity target, View source) {
        this.target = target;
        target.bivTransferAvatar = (BackupImageView) Utils.findRequiredViewAsType(source, R.attr.bivTransferAvatar, "field 'bivTransferAvatar'", BackupImageView.class);
        target.tvTransferName = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvTransferName, "field 'tvTransferName'", TextView.class);
        target.tvPromtText = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvPromtText, "field 'tvPromtText'", TextView.class);
        target.etTransferAmountView = (EditText) Utils.findRequiredViewAsType(source, R.attr.etTransferAmountView, "field 'etTransferAmountView'", EditText.class);
        target.tvTransferHintView = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvTransferHintView, "field 'tvTransferHintView'", TextView.class);
        target.tvHongbaoUnit = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvHongbaoUnit, "field 'tvHongbaoUnit'", TextView.class);
        target.etTransferText = (EditText) Utils.findRequiredViewAsType(source, R.attr.etTransferText, "field 'etTransferText'", EditText.class);
        target.btnSendTransferView = (Button) Utils.findRequiredViewAsType(source, R.attr.btnSendTransferView, "field 'btnSendTransferView'", Button.class);
        target.tvTransferHintText = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvTransferHintText, "field 'tvTransferHintText'", TextView.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        TransferSendActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.bivTransferAvatar = null;
        target.tvTransferName = null;
        target.tvPromtText = null;
        target.etTransferAmountView = null;
        target.tvTransferHintView = null;
        target.tvHongbaoUnit = null;
        target.etTransferText = null;
        target.btnSendTransferView = null;
        target.tvTransferHintText = null;
    }
}
