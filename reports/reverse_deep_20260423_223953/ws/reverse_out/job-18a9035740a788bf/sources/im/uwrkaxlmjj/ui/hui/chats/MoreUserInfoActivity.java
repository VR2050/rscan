package im.uwrkaxlmjj.ui.hui.chats;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.CommonGroupsActivity;
import im.uwrkaxlmjj.ui.MediaActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hcells.TextSettingCell;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class MoreUserInfoActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private ListAdapter adapter;
    private long dialog_id;
    private int groupRow;
    private int[] lastMediaCount;
    private int rowCount;
    private int shareMediaRow;
    private MediaActivity.SharedMediaData[] sharedMediaData;
    private int sourceRow;
    private int userId;
    private TLRPCContacts.CL_userFull_v1 userInfo;

    public MoreUserInfoActivity(int userId, long dialog_id, int[] lastMediaCount) {
        this.userId = userId;
        this.dialog_id = dialog_id;
        this.lastMediaCount = lastMediaCount;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        if (this.userInfo == null) {
            TLRPC.UserFull full = MessagesController.getInstance(this.currentAccount).getUserFull(getUserConfig().getClientUserId());
            if (full instanceof TLRPCContacts.CL_userFull_v1) {
                this.userInfo = (TLRPCContacts.CL_userFull_v1) full;
            }
            if (this.userInfo == null) {
                MessagesController.getInstance(this.currentAccount).loadFullUser(getUserConfig().getClientUserId(), this.classGuid, true);
            }
            getNotificationCenter().addObserver(this, NotificationCenter.userFullInfoDidLoad);
        }
        this.sharedMediaData = new MediaActivity.SharedMediaData[5];
        int a = 0;
        while (true) {
            MediaActivity.SharedMediaData[] sharedMediaDataArr = this.sharedMediaData;
            if (a < sharedMediaDataArr.length) {
                sharedMediaDataArr[a] = new MediaActivity.SharedMediaData();
                this.sharedMediaData[a].setMaxId(0, this.dialog_id != 0 ? Integer.MIN_VALUE : Integer.MAX_VALUE);
                a++;
            } else {
                return super.onFragmentCreate();
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = new FrameLayout(context);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initActionBar();
        initList(context);
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitle(LocaleController.getString("MoreInformation", R.string.MoreInformation));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.chats.MoreUserInfoActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    MoreUserInfoActivity.this.finishFragment();
                }
            }
        });
    }

    private void initList(Context context) {
        RecyclerListView listView = new RecyclerListView(context);
        listView.setLayoutManager(new LinearLayoutManager(context));
        ListAdapter listAdapter = new ListAdapter(context);
        this.adapter = listAdapter;
        listView.setAdapter(listAdapter);
        listView.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        ((FrameLayout) this.fragmentView).addView(listView, LayoutHelper.createFrame(-1, -2, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f)));
        listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MoreUserInfoActivity$1BxdOEqiY72b6UcEpx6npp5zWI0
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initList$0$MoreUserInfoActivity(view, i);
            }
        });
        updateRow();
    }

    public /* synthetic */ void lambda$initList$0$MoreUserInfoActivity(View view, int position) {
        if (position == this.shareMediaRow) {
            Bundle args = new Bundle();
            int i = this.userId;
            if (i != 0) {
                long j = this.dialog_id;
                if (j == 0) {
                    j = i;
                }
                args.putLong("dialog_id", j);
            }
            int[] media = new int[5];
            System.arraycopy(this.lastMediaCount, 0, media, 0, media.length);
            MediaActivity mediaActivity = new MediaActivity(args, media, this.sharedMediaData, 0);
            presentFragment(mediaActivity);
            return;
        }
        if (position == this.groupRow) {
            presentFragment(new CommonGroupsActivity(this.userId));
        }
    }

    private void updateRow() {
        this.rowCount = 0;
        this.shareMediaRow = -1;
        this.groupRow = -1;
        this.sourceRow = -1;
        int i = 0 + 1;
        this.rowCount = i;
        this.shareMediaRow = 0;
        int i2 = i + 1;
        this.rowCount = i2;
        this.groupRow = i;
        this.rowCount = i2 + 1;
        this.sourceRow = i2;
        ListAdapter listAdapter = this.adapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    public void setUserInfo(TLRPCContacts.CL_userFull_v1 userInfo) {
        this.userInfo = userInfo;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        getNotificationCenter().removeObserver(this, NotificationCenter.userFullInfoDidLoad);
        super.onFragmentDestroy();
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.userFullInfoDidLoad) {
            int userId = ((Integer) args[0]).intValue();
            if (userId == getUserConfig().getClientUserId() && (args[1] instanceof TLRPCContacts.CL_userFull_v1)) {
                this.userInfo = (TLRPCContacts.CL_userFull_v1) args[1];
                updateRow();
            }
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int position = holder.getAdapterPosition();
            return position == MoreUserInfoActivity.this.shareMediaRow || position == MoreUserInfoActivity.this.groupRow;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 0) {
                view = new TextSettingCell(this.mContext);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            TLRPCContacts.CL_userFull_v1_Bean extendBean;
            int viewType = holder.getItemViewType();
            if (viewType == 0) {
                TextSettingCell cell = (TextSettingCell) holder.itemView;
                if (position == MoreUserInfoActivity.this.shareMediaRow) {
                    cell.setText(LocaleController.getString("SharedMedia", R.string.SharedMedia), position != MoreUserInfoActivity.this.rowCount - 1, true);
                    return;
                }
                if (position == MoreUserInfoActivity.this.groupRow) {
                    TLRPC.UserFull userFull = MoreUserInfoActivity.this.getMessagesController().getUserFull(MoreUserInfoActivity.this.userId);
                    cell.setTextAndValue(LocaleController.getString("GroupsInCommonTitle", R.string.GroupsInCommonTitle), userFull != null ? String.valueOf(userFull.common_chats_count) : "", position != MoreUserInfoActivity.this.rowCount - 1, true);
                    return;
                }
                if (position == MoreUserInfoActivity.this.sourceRow) {
                    String sourceStr = "";
                    if (MoreUserInfoActivity.this.userInfo != null && (extendBean = MoreUserInfoActivity.this.userInfo.getExtendBean()) != null) {
                        int source = extendBean.source;
                        switch (source) {
                            case 1:
                                sourceStr = LocaleController.getString(R.string.AddContactByScanQrCode);
                                break;
                            case 2:
                                sourceStr = LocaleController.getString(R.string.AddContactByGroup);
                                break;
                            case 3:
                                sourceStr = LocaleController.getString(R.string.AddContactByPhoneNumber);
                                break;
                            case 4:
                                sourceStr = LocaleController.getString(R.string.AddContactByAccount);
                                break;
                            case 5:
                                sourceStr = LocaleController.getString(R.string.AddContactByNearBy);
                                break;
                            case 6:
                                sourceStr = LocaleController.getString(R.string.AddContactByPhoneBook);
                                break;
                        }
                    }
                    cell.setTextAndValue(LocaleController.getString("FriendSource", R.string.FriendSource), sourceStr, position != MoreUserInfoActivity.this.rowCount - 1, false);
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return MoreUserInfoActivity.this.rowCount;
        }
    }
}
