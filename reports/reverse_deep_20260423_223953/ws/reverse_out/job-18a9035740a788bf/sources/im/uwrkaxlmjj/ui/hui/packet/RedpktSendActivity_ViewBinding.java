package im.uwrkaxlmjj.ui.hui.packet;

import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import butterknife.Unbinder;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class RedpktSendActivity_ViewBinding implements Unbinder {
    private RedpktSendActivity target;

    public RedpktSendActivity_ViewBinding(RedpktSendActivity target, View source) {
        this.target = target;
        target.tvRpkPromet = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tv_rpk_promet, "field 'tvRpkPromet'", MryTextView.class);
        target.etRedPacketAmount = (EditText) Utils.findRequiredViewAsType(source, R.attr.et_red_packet_amount, "field 'etRedPacketAmount'", EditText.class);
        target.tvRedPacketAmountHint = (TextView) Utils.findRequiredViewAsType(source, R.attr.tv_red_packet_amount_hint, "field 'tvRedPacketAmountHint'", TextView.class);
        target.tvRedPacketUnit = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tv_red_packet_unit, "field 'tvRedPacketUnit'", MryTextView.class);
        target.llAmountLayout = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.ll_amount_layout, "field 'llAmountLayout'", LinearLayout.class);
        target.etRedPacketGreet = (EditText) Utils.findRequiredViewAsType(source, R.attr.et_red_packet_greet, "field 'etRedPacketGreet'", EditText.class);
        target.tvRedPacketGreetHint = (TextView) Utils.findRequiredViewAsType(source, R.attr.tv_red_packet_greet_hint, "field 'tvRedPacketGreetHint'", TextView.class);
        target.llRemarkLayout = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.ll_remark_layout, "field 'llRemarkLayout'", LinearLayout.class);
        target.tvAmountShowView = (TextView) Utils.findRequiredViewAsType(source, R.attr.tv_amount_show_view, "field 'tvAmountShowView'", TextView.class);
        target.tvAmountShowUnit = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tv_amount_show_unit, "field 'tvAmountShowUnit'", MryTextView.class);
        target.flAmountShowLayout = (FrameLayout) Utils.findRequiredViewAsType(source, R.attr.fl_amount_show_layout, "field 'flAmountShowLayout'", FrameLayout.class);
        target.btnRedPacketSend = (Button) Utils.findRequiredViewAsType(source, R.attr.btn_red_packet_send, "field 'btnRedPacketSend'", Button.class);
        target.tvTimeOutDesc = (TextView) Utils.findRequiredViewAsType(source, R.attr.tv_time_out_desc, "field 'tvTimeOutDesc'", TextView.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        RedpktSendActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.tvRpkPromet = null;
        target.etRedPacketAmount = null;
        target.tvRedPacketAmountHint = null;
        target.tvRedPacketUnit = null;
        target.llAmountLayout = null;
        target.etRedPacketGreet = null;
        target.tvRedPacketGreetHint = null;
        target.llRemarkLayout = null;
        target.tvAmountShowView = null;
        target.tvAmountShowUnit = null;
        target.flAmountShowLayout = null;
        target.btnRedPacketSend = null;
        target.tvTimeOutDesc = null;
    }
}
