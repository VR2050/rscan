package im.uwrkaxlmjj.ui.hui.packet;

import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import butterknife.Unbinder;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class RedpktDetailReceiverActivity_ViewBinding implements Unbinder {
    private RedpktDetailReceiverActivity target;

    public RedpktDetailReceiverActivity_ViewBinding(RedpktDetailReceiverActivity target, View source) {
        this.target = target;
        target.bivRpkAvatar = (BackupImageView) Utils.findRequiredViewAsType(source, R.attr.biv_rpk_avatar, "field 'bivRpkAvatar'", BackupImageView.class);
        target.tvRpkName = (TextView) Utils.findRequiredViewAsType(source, R.attr.tv_rpk_name, "field 'tvRpkName'", TextView.class);
        target.tvRpkGreet = (TextView) Utils.findRequiredViewAsType(source, R.attr.tv_rpk_greet, "field 'tvRpkGreet'", TextView.class);
        target.tvRpkAmount = (TextView) Utils.findRequiredViewAsType(source, R.attr.tv_rpk_amount, "field 'tvRpkAmount'", TextView.class);
        target.tvRpkDesc = (TextView) Utils.findRequiredViewAsType(source, R.attr.tv_rpk_desc, "field 'tvRpkDesc'", TextView.class);
        target.llUserLayout = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.llUserLayout, "field 'llUserLayout'", LinearLayout.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        RedpktDetailReceiverActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.bivRpkAvatar = null;
        target.tvRpkName = null;
        target.tvRpkGreet = null;
        target.tvRpkAmount = null;
        target.tvRpkDesc = null;
        target.llUserLayout = null;
    }
}
