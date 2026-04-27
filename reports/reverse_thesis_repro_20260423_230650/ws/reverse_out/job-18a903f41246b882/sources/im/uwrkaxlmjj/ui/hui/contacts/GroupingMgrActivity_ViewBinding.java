package im.uwrkaxlmjj.ui.hui.contacts;

import android.view.View;
import butterknife.Unbinder;
import butterknife.internal.DebouncingOnClickListener;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class GroupingMgrActivity_ViewBinding implements Unbinder {
    private GroupingMgrActivity target;
    private View view7f0905ad;

    public GroupingMgrActivity_ViewBinding(final GroupingMgrActivity target, View source) {
        this.target = target;
        View view = Utils.findRequiredView(source, R.attr.tv_add_group, "field 'mTvAddGroup' and method 'onViewClicked'");
        target.mTvAddGroup = (MryTextView) Utils.castView(view, R.attr.tv_add_group, "field 'mTvAddGroup'", MryTextView.class);
        this.view7f0905ad = view;
        view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.GroupingMgrActivity_ViewBinding.1
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked();
            }
        });
        target.mRcvList = (RecyclerListView) Utils.findRequiredViewAsType(source, R.attr.rcvList, "field 'mRcvList'", RecyclerListView.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        GroupingMgrActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.mTvAddGroup = null;
        target.mRcvList = null;
        this.view7f0905ad.setOnClickListener(null);
        this.view7f0905ad = null;
    }
}
