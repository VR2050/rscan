package im.uwrkaxlmjj.ui.hui.contacts;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import butterknife.Unbinder;
import butterknife.internal.DebouncingOnClickListener;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hviews.MryEditText;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.sidebar.SideBar;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class CreateGroupingActivity_ViewBinding implements Unbinder {
    private CreateGroupingActivity target;
    private View view7f090217;
    private View view7f0905ae;

    public CreateGroupingActivity_ViewBinding(final CreateGroupingActivity target, View source) {
        this.target = target;
        target.mEtGroupName = (MryEditText) Utils.findRequiredViewAsType(source, R.attr.et_group_name, "field 'mEtGroupName'", MryEditText.class);
        View view = Utils.findRequiredView(source, R.attr.iv_clear, "field 'mIvClear' and method 'onViewClicked'");
        target.mIvClear = (ImageView) Utils.castView(view, R.attr.iv_clear, "field 'mIvClear'", ImageView.class);
        this.view7f090217 = view;
        view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.CreateGroupingActivity_ViewBinding.1
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.mFlGroupName = (FrameLayout) Utils.findRequiredViewAsType(source, R.attr.fl_group_name, "field 'mFlGroupName'", FrameLayout.class);
        View view2 = Utils.findRequiredView(source, R.attr.tv_add_user, "field 'mTvAddUser' and method 'onViewClicked'");
        target.mTvAddUser = (TextView) Utils.castView(view2, R.attr.tv_add_user, "field 'mTvAddUser'", TextView.class);
        this.view7f0905ae = view2;
        view2.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.CreateGroupingActivity_ViewBinding.2
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.mRvUsers = (RecyclerListView) Utils.findRequiredViewAsType(source, R.attr.rv_users, "field 'mRvUsers'", RecyclerListView.class);
        target.mTvChar = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tv_char, "field 'mTvChar'", MryTextView.class);
        target.mSideBar = (SideBar) Utils.findRequiredViewAsType(source, R.attr.sideBar, "field 'mSideBar'", SideBar.class);
        target.mLlNotSupportEmojiTips = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.ll_not_support_emoji_tips, "field 'mLlNotSupportEmojiTips'", LinearLayout.class);
        target.mLlContainer = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.ll_container, "field 'mLlContainer'", LinearLayout.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        CreateGroupingActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.mEtGroupName = null;
        target.mIvClear = null;
        target.mFlGroupName = null;
        target.mTvAddUser = null;
        target.mRvUsers = null;
        target.mTvChar = null;
        target.mSideBar = null;
        target.mLlNotSupportEmojiTips = null;
        target.mLlContainer = null;
        this.view7f090217.setOnClickListener(null);
        this.view7f090217 = null;
        this.view7f0905ae.setOnClickListener(null);
        this.view7f0905ae = null;
    }
}
