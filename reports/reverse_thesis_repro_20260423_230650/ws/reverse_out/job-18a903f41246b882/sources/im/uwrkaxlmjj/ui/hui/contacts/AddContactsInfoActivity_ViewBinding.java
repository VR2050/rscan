package im.uwrkaxlmjj.ui.hui.contacts;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import butterknife.Unbinder;
import butterknife.internal.DebouncingOnClickListener;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class AddContactsInfoActivity_ViewBinding implements Unbinder {
    private AddContactsInfoActivity target;
    private View view7f09049e;
    private View view7f09050f;
    private View view7f09052d;

    public AddContactsInfoActivity_ViewBinding(final AddContactsInfoActivity target, View source) {
        this.target = target;
        target.avatarImage = (BackupImageView) Utils.findRequiredViewAsType(source, R.attr.avatarImage, "field 'avatarImage'", BackupImageView.class);
        target.mryNameView = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.mryNameView, "field 'mryNameView'", MryTextView.class);
        target.tvReplyText = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvReplyText, "field 'tvReplyText'", TextView.class);
        target.rcvReplyList = (RecyclerListView) Utils.findRequiredViewAsType(source, R.attr.rcvReplyList, "field 'rcvReplyList'", RecyclerListView.class);
        View view = Utils.findRequiredView(source, R.attr.tvReplyButton, "field 'tvReplyButton' and method 'onClick'");
        target.tvReplyButton = (TextView) Utils.castView(view, R.attr.tvReplyButton, "field 'tvReplyButton'", TextView.class);
        this.view7f09052d = view;
        view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.AddContactsInfoActivity_ViewBinding.1
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onClick(p0);
            }
        });
        target.flReplyLayout = (FrameLayout) Utils.findRequiredViewAsType(source, R.attr.flReplyLayout, "field 'flReplyLayout'", FrameLayout.class);
        target.llInfoLayout = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.llInfoLayout, "field 'llInfoLayout'", LinearLayout.class);
        View view2 = Utils.findRequiredView(source, R.attr.tvNoteSettingView, "field 'tvNoteSettingView' and method 'onClick'");
        target.tvNoteSettingView = (TextView) Utils.castView(view2, R.attr.tvNoteSettingView, "field 'tvNoteSettingView'", TextView.class);
        this.view7f09050f = view2;
        view2.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.AddContactsInfoActivity_ViewBinding.2
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onClick(p0);
            }
        });
        target.tvBioText = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvBioText, "field 'tvBioText'", TextView.class);
        target.llBioSettingView = (RelativeLayout) Utils.findRequiredViewAsType(source, R.attr.rlBioSettingView, "field 'llBioSettingView'", RelativeLayout.class);
        target.tvOriginalText = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvOriginalText, "field 'tvOriginalText'", TextView.class);
        target.llOriginalView = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.llOriginalView, "field 'llOriginalView'", LinearLayout.class);
        View view3 = Utils.findRequiredView(source, R.attr.tvAddContactStatus, "field 'tvAddContactStatus' and method 'onClick'");
        target.tvAddContactStatus = (TextView) Utils.castView(view3, R.attr.tvAddContactStatus, "field 'tvAddContactStatus'", TextView.class);
        this.view7f09049e = view3;
        view3.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.AddContactsInfoActivity_ViewBinding.3
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onClick(p0);
            }
        });
        target.tvBioDesc = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvBioDesc, "field 'tvBioDesc'", TextView.class);
        target.tvOriginalDesc = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvOriginalDesc, "field 'tvOriginalDesc'", TextView.class);
        target.ivGender = (ImageView) Utils.findRequiredViewAsType(source, R.attr.ivGender, "field 'ivGender'", ImageView.class);
        target.tvUpdateTime = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tv_update_time, "field 'tvUpdateTime'", MryTextView.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        AddContactsInfoActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.avatarImage = null;
        target.mryNameView = null;
        target.tvReplyText = null;
        target.rcvReplyList = null;
        target.tvReplyButton = null;
        target.flReplyLayout = null;
        target.llInfoLayout = null;
        target.tvNoteSettingView = null;
        target.tvBioText = null;
        target.llBioSettingView = null;
        target.tvOriginalText = null;
        target.llOriginalView = null;
        target.tvAddContactStatus = null;
        target.tvBioDesc = null;
        target.tvOriginalDesc = null;
        target.ivGender = null;
        target.tvUpdateTime = null;
        this.view7f09052d.setOnClickListener(null);
        this.view7f09052d = null;
        this.view7f09050f.setOnClickListener(null);
        this.view7f09050f = null;
        this.view7f09049e.setOnClickListener(null);
        this.view7f09049e = null;
    }
}
