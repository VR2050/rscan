package im.uwrkaxlmjj.ui.hui.packet;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import butterknife.Unbinder;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class RedpktDetailActivity_ViewBinding implements Unbinder {
    private RedpktDetailActivity target;

    public RedpktDetailActivity_ViewBinding(RedpktDetailActivity target, View source) {
        this.target = target;
        target.ivRptAvatar = (BackupImageView) Utils.findRequiredViewAsType(source, R.attr.ivRptAvatar, "field 'ivRptAvatar'", BackupImageView.class);
        target.tvRptName = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvRptName, "field 'tvRptName'", TextView.class);
        target.tvRptGreet = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvRptGreet, "field 'tvRptGreet'", TextView.class);
        target.tvRptState = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvRptState, "field 'tvRptState'", TextView.class);
        target.llUserLayout = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.llUserLayout, "field 'llUserLayout'", LinearLayout.class);
        target.bivReceiverAvatar = (BackupImageView) Utils.findRequiredViewAsType(source, R.attr.biv_receiver_avatar, "field 'bivReceiverAvatar'", BackupImageView.class);
        target.tvRpkName = (TextView) Utils.findRequiredViewAsType(source, R.attr.tv_rpk_name, "field 'tvRpkName'", TextView.class);
        target.tvRpkAmount = (TextView) Utils.findRequiredViewAsType(source, R.attr.tv_rpk_amount, "field 'tvRpkAmount'", TextView.class);
        target.tvRpkReceiveTime = (TextView) Utils.findRequiredViewAsType(source, R.attr.tv_rpk_receive_time, "field 'tvRpkReceiveTime'", TextView.class);
        target.flRpkRecordLayout = (FrameLayout) Utils.findRequiredViewAsType(source, R.attr.fl_rpk_record_layout, "field 'flRpkRecordLayout'", FrameLayout.class);
        target.tvRpkBackDesc = (TextView) Utils.findRequiredViewAsType(source, R.attr.tv_rpk_back_desc, "field 'tvRpkBackDesc'", TextView.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        RedpktDetailActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.ivRptAvatar = null;
        target.tvRptName = null;
        target.tvRptGreet = null;
        target.tvRptState = null;
        target.llUserLayout = null;
        target.bivReceiverAvatar = null;
        target.tvRpkName = null;
        target.tvRpkAmount = null;
        target.tvRpkReceiveTime = null;
        target.flRpkRecordLayout = null;
        target.tvRpkBackDesc = null;
    }
}
