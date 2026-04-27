package im.uwrkaxlmjj.ui.hui.chats;

import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import butterknife.Unbinder;
import butterknife.internal.DebouncingOnClickListener;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class NewProfileActivity_ViewBinding implements Unbinder {
    private NewProfileActivity target;
    private View view7f0905ac;
    private View view7f090627;
    private View view7f09062a;

    public NewProfileActivity_ViewBinding(final NewProfileActivity target, View source) {
        this.target = target;
        target.listView = (RecyclerListView) Utils.findRequiredViewAsType(source, R.attr.listview, "field 'listView'", RecyclerListView.class);
        View view = Utils.findRequiredView(source, R.attr.tv_add_friend, "field 'tvAddFriend' and method 'onClick'");
        target.tvAddFriend = (TextView) Utils.castView(view, R.attr.tv_add_friend, "field 'tvAddFriend'", TextView.class);
        this.view7f0905ac = view;
        view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity_ViewBinding.1
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onClick(p0);
            }
        });
        View view2 = Utils.findRequiredView(source, R.attr.tv_send_message, "field 'tvSendMessage' and method 'onClick'");
        target.tvSendMessage = (TextView) Utils.castView(view2, R.attr.tv_send_message, "field 'tvSendMessage'", TextView.class);
        this.view7f09062a = view2;
        view2.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity_ViewBinding.2
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onClick(p0);
            }
        });
        View view3 = Utils.findRequiredView(source, R.attr.tv_secret_chat, "field 'tvSecretChat' and method 'onClick'");
        target.tvSecretChat = (TextView) Utils.castView(view3, R.attr.tv_secret_chat, "field 'tvSecretChat'", TextView.class);
        this.view7f090627 = view3;
        view3.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity_ViewBinding.3
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onClick(p0);
            }
        });
        target.mLlBottomBtn = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.ll_bottom_btn, "field 'mLlBottomBtn'", LinearLayout.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        NewProfileActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.listView = null;
        target.tvAddFriend = null;
        target.tvSendMessage = null;
        target.tvSecretChat = null;
        target.mLlBottomBtn = null;
        this.view7f0905ac.setOnClickListener(null);
        this.view7f0905ac = null;
        this.view7f09062a.setOnClickListener(null);
        this.view7f09062a = null;
        this.view7f090627.setOnClickListener(null);
        this.view7f090627 = null;
    }
}
