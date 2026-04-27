package im.uwrkaxlmjj.ui.hui.cdnvip;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import butterknife.Unbinder;
import butterknife.internal.DebouncingOnClickListener;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class CdnVipCenterActivity_ViewBinding implements Unbinder {
    private CdnVipCenterActivity target;
    private View view7f090097;

    public CdnVipCenterActivity_ViewBinding(final CdnVipCenterActivity target, View source) {
        this.target = target;
        target.actionBarContainer = (FrameLayout) Utils.findRequiredViewAsType(source, R.attr.actionBarContainer, "field 'actionBarContainer'", FrameLayout.class);
        target.ivAvatar = (BackupImageView) Utils.findRequiredViewAsType(source, R.attr.ivAvatar, "field 'ivAvatar'", BackupImageView.class);
        target.tvUserName = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvUserName, "field 'tvUserName'", MryTextView.class);
        target.llBottom = Utils.findRequiredView(source, R.attr.llBottom, "field 'llBottom'");
        target.ivBgTop = (ImageView) Utils.findRequiredViewAsType(source, R.attr.ivBgTop, "field 'ivBgTop'", ImageView.class);
        target.ivBgBottom = (ImageView) Utils.findRequiredViewAsType(source, R.attr.ivBgBottom, "field 'ivBgBottom'", ImageView.class);
        target.tvVipTop = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvVipTop, "field 'tvVipTop'", MryTextView.class);
        target.tvStatusOrTime = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvStatusOrTime, "field 'tvStatusOrTime'", MryTextView.class);
        target.card = Utils.findRequiredView(source, R.attr.card, "field 'card'");
        target.tvTime = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvTime, "field 'tvTime'", MryTextView.class);
        target.tvUnitPrice = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvUnitPrice, "field 'tvUnitPrice'", MryTextView.class);
        target.tvTips = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvTips, "field 'tvTips'", MryTextView.class);
        View view = Utils.findRequiredView(source, R.attr.btn, "field 'btn' and method 'onClick'");
        target.btn = (MryTextView) Utils.castView(view, R.attr.btn, "field 'btn'", MryTextView.class);
        this.view7f090097 = view;
        view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.CdnVipCenterActivity_ViewBinding.1
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onClick(p0);
            }
        });
        target.tvTeQuan = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvTeQuan, "field 'tvTeQuan'", MryTextView.class);
        target.rv = (RecyclerListView) Utils.findRequiredViewAsType(source, R.attr.rv, "field 'rv'", RecyclerListView.class);
        target.tvBottomTips = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvBottomTips, "field 'tvBottomTips'", TextView.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        CdnVipCenterActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.actionBarContainer = null;
        target.ivAvatar = null;
        target.tvUserName = null;
        target.llBottom = null;
        target.ivBgTop = null;
        target.ivBgBottom = null;
        target.tvVipTop = null;
        target.tvStatusOrTime = null;
        target.card = null;
        target.tvTime = null;
        target.tvUnitPrice = null;
        target.tvTips = null;
        target.btn = null;
        target.tvTeQuan = null;
        target.rv = null;
        target.tvBottomTips = null;
        this.view7f090097.setOnClickListener(null);
        this.view7f090097 = null;
    }
}
