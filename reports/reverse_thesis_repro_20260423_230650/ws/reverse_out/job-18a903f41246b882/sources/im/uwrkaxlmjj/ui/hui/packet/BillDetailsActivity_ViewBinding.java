package im.uwrkaxlmjj.ui.hui.packet;

import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import butterknife.Unbinder;
import butterknife.internal.DebouncingOnClickListener;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.hviews.MryImageView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class BillDetailsActivity_ViewBinding implements Unbinder {
    private BillDetailsActivity target;
    private View view7f0901e3;
    private View view7f0901fb;
    private View view7f0901fc;
    private View view7f0901fd;
    private View view7f0901fe;

    public BillDetailsActivity_ViewBinding(final BillDetailsActivity target, View source) {
        this.target = target;
        target.ivIcon = (ImageView) Utils.findRequiredViewAsType(source, R.attr.ivIcon, "field 'ivIcon'", ImageView.class);
        target.tvAmount = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvAmount, "field 'tvAmount'", TextView.class);
        target.llIconView = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.llIconView, "field 'llIconView'", LinearLayout.class);
        target.ivIcon2 = (ImageView) Utils.findRequiredViewAsType(source, R.attr.ivIcon2, "field 'ivIcon2'", ImageView.class);
        target.tvAmount2 = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvAmount2, "field 'tvAmount2'", TextView.class);
        target.llContainer = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.llContainer, "field 'llContainer'", LinearLayout.class);
        target.tvRowName1 = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRowName1, "field 'tvRowName1'", MryTextView.class);
        target.tvRowAddress1 = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRowAddress1, "field 'tvRowAddress1'", MryTextView.class);
        View view = Utils.findRequiredView(source, R.attr.ivRowCopy1, "field 'ivRowCopy1' and method 'onViewClicked'");
        target.ivRowCopy1 = (MryImageView) Utils.castView(view, R.attr.ivRowCopy1, "field 'ivRowCopy1'", MryImageView.class);
        this.view7f0901fc = view;
        view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.BillDetailsActivity_ViewBinding.1
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.tvRowName2 = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRowName2, "field 'tvRowName2'", MryTextView.class);
        target.tvRowAddress2 = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRowAddress2, "field 'tvRowAddress2'", MryTextView.class);
        View view2 = Utils.findRequiredView(source, R.attr.ivRowCopy2, "field 'ivRowCopy2' and method 'onViewClicked'");
        target.ivRowCopy2 = (MryImageView) Utils.castView(view2, R.attr.ivRowCopy2, "field 'ivRowCopy2'", MryImageView.class);
        this.view7f0901fd = view2;
        view2.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.BillDetailsActivity_ViewBinding.2
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.tvRowName3 = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRowName3, "field 'tvRowName3'", MryTextView.class);
        target.tvRowAddress3 = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRowAddress3, "field 'tvRowAddress3'", MryTextView.class);
        View view3 = Utils.findRequiredView(source, R.attr.ivRowCopy3, "field 'ivRowCopy3' and method 'onViewClicked'");
        target.ivRowCopy3 = (MryImageView) Utils.castView(view3, R.attr.ivRowCopy3, "field 'ivRowCopy3'", MryImageView.class);
        this.view7f0901fe = view3;
        view3.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.BillDetailsActivity_ViewBinding.3
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.tvRowName4 = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRowName4, "field 'tvRowName4'", MryTextView.class);
        target.tvRowAddress4 = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRowAddress4, "field 'tvRowAddress4'", MryTextView.class);
        target.tvRowName5 = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRowName5, "field 'tvRowName5'", MryTextView.class);
        target.tvRowAddress5 = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRowAddress5, "field 'tvRowAddress5'", MryTextView.class);
        target.rlRow6 = (RelativeLayout) Utils.findRequiredViewAsType(source, R.attr.rlRow6, "field 'rlRow6'", RelativeLayout.class);
        target.tvRowName6 = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRowName6, "field 'tvRowName6'", MryTextView.class);
        target.tvRowAddress6 = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRowAddress6, "field 'tvRowAddress6'", MryTextView.class);
        target.tvRowName7 = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRowName7, "field 'tvRowName7'", MryTextView.class);
        target.tvRowAddress7 = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRowAddress7, "field 'tvRowAddress7'", MryTextView.class);
        target.rlRow8 = (RelativeLayout) Utils.findRequiredViewAsType(source, R.attr.rlRow8, "field 'rlRow8'", RelativeLayout.class);
        target.tvRowName8 = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRowName8, "field 'tvRowName8'", MryTextView.class);
        target.tvRowAddress8 = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRowAddress8, "field 'tvRowAddress8'", MryTextView.class);
        target.llCurrencyContainer = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.llCurrencyContainer, "field 'llCurrencyContainer'", LinearLayout.class);
        target.llCurrencyInfo1 = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.llCurrencyInfo1, "field 'llCurrencyInfo1'", LinearLayout.class);
        target.rlCurrencyRow1 = (RelativeLayout) Utils.findRequiredViewAsType(source, R.attr.rlCurrencyRow1, "field 'rlCurrencyRow1'", RelativeLayout.class);
        target.rlCurrencyRow2 = (RelativeLayout) Utils.findRequiredViewAsType(source, R.attr.rlCurrencyRow2, "field 'rlCurrencyRow2'", RelativeLayout.class);
        target.rlCurrencyRow4 = (RelativeLayout) Utils.findRequiredViewAsType(source, R.attr.rlCurrencyRow4, "field 'rlCurrencyRow4'", RelativeLayout.class);
        target.rlCurrencyRow5 = (RelativeLayout) Utils.findRequiredViewAsType(source, R.attr.rlCurrencyRow5, "field 'rlCurrencyRow5'", RelativeLayout.class);
        target.tvRow1Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvRow1Name, "field 'tvRow1Name'", TextView.class);
        target.tvRow1Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRow1Info, "field 'tvRow1Info'", MryTextView.class);
        target.tvRow2Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvRow2Name, "field 'tvRow2Name'", TextView.class);
        target.tvRow2Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRow2Info, "field 'tvRow2Info'", MryTextView.class);
        target.tvRow3Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvRow3Name, "field 'tvRow3Name'", TextView.class);
        target.tvRow3Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRow3Info, "field 'tvRow3Info'", MryTextView.class);
        target.tvRow4Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvRow4Name, "field 'tvRow4Name'", TextView.class);
        target.tvRow4Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRow4Info, "field 'tvRow4Info'", MryTextView.class);
        target.tvRow5Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvRow5Name, "field 'tvRow5Name'", TextView.class);
        target.tvRow5Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRow5Info, "field 'tvRow5Info'", MryTextView.class);
        target.tvRow6Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvRow6Name, "field 'tvRow6Name'", TextView.class);
        target.tvRow6Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRow6Info, "field 'tvRow6Info'", MryTextView.class);
        View view4 = Utils.findRequiredView(source, R.attr.ivRow6Copy, "field 'ivRow6Copy' and method 'onViewClicked'");
        target.ivRow6Copy = (MryImageView) Utils.castView(view4, R.attr.ivRow6Copy, "field 'ivRow6Copy'", MryImageView.class);
        this.view7f0901fb = view4;
        view4.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.BillDetailsActivity_ViewBinding.4
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.tvRow7Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvRow7Name, "field 'tvRow7Name'", TextView.class);
        target.tvRow7Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRow7Info, "field 'tvRow7Info'", MryTextView.class);
        target.tvRow8Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvRow8Name, "field 'tvRow8Name'", TextView.class);
        target.tvRow8Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRow8Info, "field 'tvRow8Info'", MryTextView.class);
        target.tvRow9Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvRow9Name, "field 'tvRow9Name'", TextView.class);
        target.tvRow9Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRow9Info, "field 'tvRow9Info'", MryTextView.class);
        target.tvRow10Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvRow10Name, "field 'tvRow10Name'", TextView.class);
        target.tvRow10Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRow10Info, "field 'tvRow10Info'", MryTextView.class);
        target.tvRow11Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvRow11Name, "field 'tvRow11Name'", TextView.class);
        target.tvRow11Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvRow11Info, "field 'tvRow11Info'", MryTextView.class);
        target.llFiatContainer = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.llFiatContainer, "field 'llFiatContainer'", LinearLayout.class);
        target.llFiatInfo1 = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.llFiatInfo1, "field 'llFiatInfo1'", LinearLayout.class);
        target.tvFiatRow1Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow1Name, "field 'tvFiatRow1Name'", TextView.class);
        target.tvFiatRow1Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow1Info, "field 'tvFiatRow1Info'", MryTextView.class);
        target.tvFiatRow2Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow2Name, "field 'tvFiatRow2Name'", TextView.class);
        target.tvFiatRow2Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow2Info, "field 'tvFiatRow2Info'", MryTextView.class);
        target.tvFiatRow3Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow3Name, "field 'tvFiatRow3Name'", TextView.class);
        target.tvFiatRow3Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow3Info, "field 'tvFiatRow3Info'", MryTextView.class);
        target.tvFiatRow4Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow4Name, "field 'tvFiatRow4Name'", TextView.class);
        target.tvFiatRow4Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow4Info, "field 'tvFiatRow4Info'", MryTextView.class);
        target.tvFiatRow5Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow5Name, "field 'tvFiatRow5Name'", TextView.class);
        target.tvFiatRow5Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow5Info, "field 'tvFiatRow5Info'", MryTextView.class);
        target.tvFiatRow6Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow6Name, "field 'tvFiatRow6Name'", TextView.class);
        target.tvFiatRow6Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow6Info, "field 'tvFiatRow6Info'", MryTextView.class);
        target.tvFiatRow7Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow7Name, "field 'tvFiatRow7Name'", TextView.class);
        target.tvFiatRow7Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow7Info, "field 'tvFiatRow7Info'", MryTextView.class);
        target.tvFiatRow8Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow8Name, "field 'tvFiatRow8Name'", TextView.class);
        target.tvFiatRow8Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow8Info, "field 'tvFiatRow8Info'", MryTextView.class);
        target.tvFiatRow9Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow9Name, "field 'tvFiatRow9Name'", TextView.class);
        target.tvFiatRow9Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow9Info, "field 'tvFiatRow9Info'", MryTextView.class);
        target.tvFiatRow10Name = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow10Name, "field 'tvFiatRow10Name'", TextView.class);
        target.tvFiatRow10Info = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvFiatRow10Info, "field 'tvFiatRow10Info'", MryTextView.class);
        View view5 = Utils.findRequiredView(source, R.attr.ivFiat5Copy, "method 'onViewClicked'");
        this.view7f0901e3 = view5;
        view5.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.BillDetailsActivity_ViewBinding.5
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        BillDetailsActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.ivIcon = null;
        target.tvAmount = null;
        target.llIconView = null;
        target.ivIcon2 = null;
        target.tvAmount2 = null;
        target.llContainer = null;
        target.tvRowName1 = null;
        target.tvRowAddress1 = null;
        target.ivRowCopy1 = null;
        target.tvRowName2 = null;
        target.tvRowAddress2 = null;
        target.ivRowCopy2 = null;
        target.tvRowName3 = null;
        target.tvRowAddress3 = null;
        target.ivRowCopy3 = null;
        target.tvRowName4 = null;
        target.tvRowAddress4 = null;
        target.tvRowName5 = null;
        target.tvRowAddress5 = null;
        target.rlRow6 = null;
        target.tvRowName6 = null;
        target.tvRowAddress6 = null;
        target.tvRowName7 = null;
        target.tvRowAddress7 = null;
        target.rlRow8 = null;
        target.tvRowName8 = null;
        target.tvRowAddress8 = null;
        target.llCurrencyContainer = null;
        target.llCurrencyInfo1 = null;
        target.rlCurrencyRow1 = null;
        target.rlCurrencyRow2 = null;
        target.rlCurrencyRow4 = null;
        target.rlCurrencyRow5 = null;
        target.tvRow1Name = null;
        target.tvRow1Info = null;
        target.tvRow2Name = null;
        target.tvRow2Info = null;
        target.tvRow3Name = null;
        target.tvRow3Info = null;
        target.tvRow4Name = null;
        target.tvRow4Info = null;
        target.tvRow5Name = null;
        target.tvRow5Info = null;
        target.tvRow6Name = null;
        target.tvRow6Info = null;
        target.ivRow6Copy = null;
        target.tvRow7Name = null;
        target.tvRow7Info = null;
        target.tvRow8Name = null;
        target.tvRow8Info = null;
        target.tvRow9Name = null;
        target.tvRow9Info = null;
        target.tvRow10Name = null;
        target.tvRow10Info = null;
        target.tvRow11Name = null;
        target.tvRow11Info = null;
        target.llFiatContainer = null;
        target.llFiatInfo1 = null;
        target.tvFiatRow1Name = null;
        target.tvFiatRow1Info = null;
        target.tvFiatRow2Name = null;
        target.tvFiatRow2Info = null;
        target.tvFiatRow3Name = null;
        target.tvFiatRow3Info = null;
        target.tvFiatRow4Name = null;
        target.tvFiatRow4Info = null;
        target.tvFiatRow5Name = null;
        target.tvFiatRow5Info = null;
        target.tvFiatRow6Name = null;
        target.tvFiatRow6Info = null;
        target.tvFiatRow7Name = null;
        target.tvFiatRow7Info = null;
        target.tvFiatRow8Name = null;
        target.tvFiatRow8Info = null;
        target.tvFiatRow9Name = null;
        target.tvFiatRow9Info = null;
        target.tvFiatRow10Name = null;
        target.tvFiatRow10Info = null;
        this.view7f0901fc.setOnClickListener(null);
        this.view7f0901fc = null;
        this.view7f0901fd.setOnClickListener(null);
        this.view7f0901fd = null;
        this.view7f0901fe.setOnClickListener(null);
        this.view7f0901fe = null;
        this.view7f0901fb.setOnClickListener(null);
        this.view7f0901fb = null;
        this.view7f0901e3.setOnClickListener(null);
        this.view7f0901e3 = null;
    }
}
