package im.uwrkaxlmjj.ui.hui.contacts;

import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.WalletDialog;
import im.uwrkaxlmjj.ui.hcells.MryDividerCell;
import im.uwrkaxlmjj.ui.hviews.MryEmptyView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class SelectGroupingActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private static final int item_done = 1;
    private int contactsHash;
    private Context context;
    private int defaultGroupId;
    private MryEmptyView emptyView;
    private List<TLRPCContacts.TL_contactsGroupInfo> groupInfos;
    private ListAdapter listAdapter;
    RecyclerListView listView;
    private SelectGroupingActivityDelegate mDelegate;
    private TLRPCContacts.TL_contactsGroupInfo selectedGroup;
    private TLRPC.User user;
    private int user_id;

    public interface SelectGroupingActivityDelegate {
        void onFinish(TLRPCContacts.TL_contactsGroupInfo tL_contactsGroupInfo);
    }

    public SelectGroupingActivity(Bundle args) {
        super(args);
        this.groupInfos = new ArrayList();
    }

    public void setDelegate(SelectGroupingActivityDelegate delegate) {
        this.mDelegate = delegate;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        this.swipeBackEnabled = false;
        if (this.arguments != null) {
            this.user_id = this.arguments.getInt("user_id");
            this.defaultGroupId = this.arguments.getInt("groupId");
        }
        TLRPC.User user = getMessagesController().getUser(Integer.valueOf(this.user_id));
        this.user = user;
        if (user == null) {
            return false;
        }
        getNotificationCenter().addObserver(this, NotificationCenter.groupingChanged);
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        getNotificationCenter().removeObserver(this, NotificationCenter.groupingChanged);
        super.onFragmentDestroy();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.context = context;
        this.fragmentView = new FrameLayout(context);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        useButterKnife();
        initActionBar();
        initEmptyView();
        initList();
        initData();
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString("SelectGrouping", R.string.SelectGrouping));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.contacts.SelectGroupingActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == 1) {
                    if (SelectGroupingActivity.this.selectedGroup != null && SelectGroupingActivity.this.selectedGroup.group_id != SelectGroupingActivity.this.defaultGroupId) {
                        SelectGroupingActivity.this.saveGroup();
                    } else {
                        SelectGroupingActivity.this.finishFragment();
                    }
                }
            }
        });
        this.actionBar.setBackTitle(LocaleController.getString("Cancel", R.string.Cancel));
        this.actionBar.getBackTitleTextView().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$SelectGroupingActivity$VPZ86b9Mc7WJ_YRbrsCHYaBv9bE
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initActionBar$0$SelectGroupingActivity(view);
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        menu.addItem(1, LocaleController.getString("Done", R.string.Done));
    }

    public /* synthetic */ void lambda$initActionBar$0$SelectGroupingActivity(View v) {
        TLRPCContacts.TL_contactsGroupInfo tL_contactsGroupInfo = this.selectedGroup;
        if (tL_contactsGroupInfo != null && tL_contactsGroupInfo.group_id != this.defaultGroupId) {
            showSaveDialog();
        } else {
            finishFragment();
        }
    }

    private void initList() {
        RecyclerListView recyclerListView = new RecyclerListView(this.context);
        this.listView = recyclerListView;
        recyclerListView.setLayoutManager(new LinearLayoutManager(this.context));
        RecyclerListView recyclerListView2 = this.listView;
        ListAdapter listAdapter = new ListAdapter();
        this.listAdapter = listAdapter;
        recyclerListView2.setAdapter(listAdapter);
        this.listView.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        ((FrameLayout) this.fragmentView).addView(this.listView, LayoutHelper.createFrame(-1, -2, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f)));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$SelectGroupingActivity$xYqeick6bOVeaOsy0fm8BQGAQFA
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initList$1$SelectGroupingActivity(view, i);
            }
        });
    }

    public /* synthetic */ void lambda$initList$1$SelectGroupingActivity(View view, int position) {
        this.selectedGroup = this.groupInfos.get(position);
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    private void initEmptyView() {
        MryEmptyView mryEmptyView = new MryEmptyView(getParentActivity());
        this.emptyView = mryEmptyView;
        mryEmptyView.attach(this);
        this.emptyView.setEmptyText("暂无分组");
        this.emptyView.setEmptyBtnText(LocaleController.getString("AddGrouping", R.string.AddGrouping));
        this.emptyView.setEmptyResId(R.id.img_empty_default);
        this.emptyView.setErrorResId(R.id.img_empty_default);
        this.emptyView.setOnEmptyClickListener(new MryEmptyView.OnEmptyOrErrorClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$SelectGroupingActivity$ydzlC9YERI4wGcLEiXR8MWVrmgc
            @Override // im.uwrkaxlmjj.ui.hviews.MryEmptyView.OnEmptyOrErrorClickListener
            public final boolean onEmptyViewButtonClick(boolean z) {
                return this.f$0.lambda$initEmptyView$2$SelectGroupingActivity(z);
            }
        });
    }

    public /* synthetic */ boolean lambda$initEmptyView$2$SelectGroupingActivity(boolean isEmptyButton) {
        if (isEmptyButton) {
            presentFragment(new CreateGroupingActivity());
            return false;
        }
        getContacts();
        return false;
    }

    private void initData() {
        getContacts();
    }

    private void showSaveDialog() {
        WalletDialog dialog = new WalletDialog(getParentActivity());
        dialog.setMessage(LocaleController.getString("SaveGroupingChangeTips", R.string.SaveGroupingChangeTips));
        dialog.setPositiveButton(LocaleController.getString("Save", R.string.Save), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$SelectGroupingActivity$4-jFRw0Xmt2k9Q3lRxqvf2dAUMs
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showSaveDialog$3$SelectGroupingActivity(dialogInterface, i);
            }
        });
        dialog.setNegativeButton(LocaleController.getString("NotSave", R.string.NotSave), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$SelectGroupingActivity$a3x7qX-kx3u-v7-8WuMN9QVLvCU
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showSaveDialog$4$SelectGroupingActivity(dialogInterface, i);
            }
        });
        showDialog(dialog);
    }

    public /* synthetic */ void lambda$showSaveDialog$3$SelectGroupingActivity(DialogInterface dialogInterface, int i) {
        saveGroup();
    }

    public /* synthetic */ void lambda$showSaveDialog$4$SelectGroupingActivity(DialogInterface dialogInterface, int i) {
        finishFragment();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void saveGroup() {
        if (this.user != null) {
            final AlertDialog alertDialog = new AlertDialog(getParentActivity(), 3);
            TLRPCContacts.TL_setUserGroup req = new TLRPCContacts.TL_setUserGroup();
            req.group_id = this.selectedGroup.group_id;
            TLRPCContacts.TL_inputPeerUserChange inputPeer = new TLRPCContacts.TL_inputPeerUserChange();
            inputPeer.access_hash = this.user.access_hash;
            inputPeer.user_id = this.user.id;
            inputPeer.fist_name = this.user.first_name;
            req.users.add(inputPeer);
            final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$SelectGroupingActivity$Lkc5j8kFQ_jyDYHYzOgpV-XvMtA
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$saveGroup$6$SelectGroupingActivity(alertDialog, tLObject, tL_error);
                }
            });
            getConnectionsManager().bindRequestToGuid(reqId, this.classGuid);
            alertDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$SelectGroupingActivity$OPYYAYw4E10vs64kl6ui4sCr8pI
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$saveGroup$7$SelectGroupingActivity(reqId, dialogInterface);
                }
            });
            showDialog(alertDialog);
        }
    }

    public /* synthetic */ void lambda$saveGroup$6$SelectGroupingActivity(final AlertDialog alertDialog, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$SelectGroupingActivity$zpV6_21YmF_oUz8wADyd7pNjFAc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$5$SelectGroupingActivity(alertDialog, error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$5$SelectGroupingActivity(AlertDialog alertDialog, TLRPC.TL_error error, TLObject response) {
        alertDialog.dismiss();
        if (error == null) {
            if (response instanceof TLRPC.TL_boolTrue) {
                SelectGroupingActivityDelegate selectGroupingActivityDelegate = this.mDelegate;
                if (selectGroupingActivityDelegate != null) {
                    selectGroupingActivityDelegate.onFinish(this.selectedGroup);
                }
                finishFragment();
                return;
            }
            ToastUtils.show((CharSequence) "修改分组失败，请稍后重试");
            return;
        }
        ToastUtils.show((CharSequence) error.text);
    }

    public /* synthetic */ void lambda$saveGroup$7$SelectGroupingActivity(int reqId, DialogInterface dialog1) {
        getConnectionsManager().cancelRequest(reqId, true);
    }

    public void getContacts() {
        this.emptyView.showLoading();
        TLRPCContacts.TL_getContactsV1 req = new TLRPCContacts.TL_getContactsV1();
        req.hash = this.contactsHash;
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$SelectGroupingActivity$IuUh0ft4svXD3QCcI_Z_fmCkqIE
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getContacts$9$SelectGroupingActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$getContacts$9$SelectGroupingActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$SelectGroupingActivity$Ti8siwmXcR5QKxTrUzZVt4U1aDY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$8$SelectGroupingActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$8$SelectGroupingActivity(TLRPC.TL_error error, TLObject response) {
        if (error == null) {
            if (response instanceof TLRPCContacts.TL_contactsV1) {
                TLRPCContacts.TL_contactsV1 contacts = (TLRPCContacts.TL_contactsV1) response;
                this.contactsHash = contacts.hash;
                if (!contacts.users.isEmpty()) {
                    for (TLRPC.User user : contacts.users) {
                        getMessagesController().putUser(user, false);
                    }
                }
                this.groupInfos.clear();
                this.groupInfos.addAll(contacts.group_infos);
                if (this.groupInfos.isEmpty()) {
                    this.emptyView.showEmpty();
                } else {
                    Iterator<TLRPCContacts.TL_contactsGroupInfo> it = this.groupInfos.iterator();
                    while (true) {
                        if (!it.hasNext()) {
                            break;
                        }
                        TLRPCContacts.TL_contactsGroupInfo groupInfo = it.next();
                        if (groupInfo.group_id == this.defaultGroupId) {
                            this.selectedGroup = groupInfo;
                            break;
                        }
                    }
                    this.emptyView.showContent();
                }
                ListAdapter listAdapter = this.listAdapter;
                if (listAdapter != null) {
                    listAdapter.notifyDataSetChanged();
                    return;
                }
                return;
            }
            return;
        }
        this.emptyView.showError(error.text);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.groupingChanged) {
            getContacts();
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private ListAdapter() {
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(SelectGroupingActivity.this.context).inflate(R.layout.item_select_grouping, parent, false);
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            MryTextView tvGroupName = (MryTextView) holder.itemView.findViewById(R.attr.tv_group_name);
            ImageView ivSelector = (ImageView) holder.itemView.findViewById(R.attr.iv_selector);
            MryDividerCell divider = (MryDividerCell) holder.itemView.findViewById(R.attr.divider);
            tvGroupName.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            if (position == getItemCount() - 1) {
                divider.setVisibility(position != getItemCount() + (-1) ? 0 : 8);
            }
            TLRPCContacts.TL_contactsGroupInfo groupInfo = (TLRPCContacts.TL_contactsGroupInfo) SelectGroupingActivity.this.groupInfos.get(position);
            tvGroupName.setText(groupInfo.title);
            ivSelector.setVisibility((SelectGroupingActivity.this.selectedGroup == null || SelectGroupingActivity.this.selectedGroup.group_id != groupInfo.group_id) ? 8 : 0);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return SelectGroupingActivity.this.groupInfos.size();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        TLRPCContacts.TL_contactsGroupInfo tL_contactsGroupInfo = this.selectedGroup;
        if (tL_contactsGroupInfo != null && tL_contactsGroupInfo.group_id != this.defaultGroupId) {
            showSaveDialog();
            return false;
        }
        return super.onBackPressed();
    }
}
