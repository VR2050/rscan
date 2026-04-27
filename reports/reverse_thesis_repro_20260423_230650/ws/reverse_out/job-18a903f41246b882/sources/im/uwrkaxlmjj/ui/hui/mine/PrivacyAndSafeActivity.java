package im.uwrkaxlmjj.ui.hui.mine;

import android.content.Context;
import android.content.Intent;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.PasscodeActivity;
import im.uwrkaxlmjj.ui.PrivacyControlActivity;
import im.uwrkaxlmjj.ui.PrivacyUsersActivity;
import im.uwrkaxlmjj.ui.ProxyListActivity;
import im.uwrkaxlmjj.ui.TwoStepVerificationActivityNew;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.EmptyCell;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.TextCheckCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.DialogCommonList;
import im.uwrkaxlmjj.ui.hcells.TextSettingCell;
import im.uwrkaxlmjj.ui.hviews.sliding.SlidingLayout;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PrivacyAndSafeActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private int accountSectionRow;
    private int blockedRow;
    private int callsRow;
    private boolean[] clear = new boolean[2];
    private boolean currentSuggest;
    private boolean currentSync;
    private int dataUsageDetailRow;
    private int dataUsageRow;
    private int deleteAccountDetailRow;
    private int deleteAccountRow;
    private int emptyRow;
    private int forwardsRow;
    private int friendsHubRow;
    private int groupsDetailRow;
    private int groupsRow;
    private int lastSeenRow;
    private LinearLayoutManager layoutManager;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private boolean newSuggest;
    private boolean newSync;
    private int passcodeRow;
    private int passwordRow;
    private int phoneNumberRow;
    private int privacyHeaderRow;
    private int profilePhotoRow;
    private AlertDialog progressDialog;
    private int proxySetRow;
    private int rowCount;
    private int securityHeaderRow;
    private int sessionsDetailRow;
    private int sessionsRow;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        getContactsController().loadPrivacySettings();
        getMessagesController().getBlockedUsers(true);
        boolean z = getUserConfig().syncContacts;
        this.newSync = z;
        this.currentSync = z;
        boolean z2 = getUserConfig().suggestContacts;
        this.newSuggest = z2;
        this.currentSuggest = z2;
        updateRows();
        loadPasswordSettings();
        getNotificationCenter().addObserver(this, NotificationCenter.privacyRulesUpdated);
        getNotificationCenter().addObserver(this, NotificationCenter.blockedUsersDidLoad);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        getNotificationCenter().removeObserver(this, NotificationCenter.privacyRulesUpdated);
        getNotificationCenter().removeObserver(this, NotificationCenter.blockedUsersDidLoad);
        if (this.currentSync != this.newSync) {
            getUserConfig().syncContacts = this.newSync;
            getUserConfig().saveConfig(false);
            if (this.newSync) {
                getContactsController().forceImportContacts();
                if (getParentActivity() != null) {
                    ToastUtils.show(R.string.SyncContactsAdded);
                }
            }
        }
        boolean z = this.newSuggest;
        if (z != this.currentSuggest) {
            if (!z) {
                getMediaDataController().clearTopPeers();
            }
            getUserConfig().suggestContacts = this.newSuggest;
            getUserConfig().saveConfig(false);
            TLRPC.TL_contacts_toggleTopPeers req = new TLRPC.TL_contacts_toggleTopPeers();
            req.enabled = this.newSuggest;
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$PrivacyAndSafeActivity$f1sbs1S5T_UWGo_7YwCDTz_Fwqk
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    PrivacyAndSafeActivity.lambda$onFragmentDestroy$0(tLObject, tL_error);
                }
            });
        }
    }

    static /* synthetic */ void lambda$onFragmentDestroy$0(TLObject response, TLRPC.TL_error error) {
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle(LocaleController.getString("PrivacySettings", R.string.PrivacySettings));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.mine.PrivacyAndSafeActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    PrivacyAndSafeActivity.this.finishFragment();
                }
            }
        });
        this.listAdapter = new ListAdapter(context);
        this.fragmentView = new SlidingLayout(context);
        SlidingLayout slidingLayout = (SlidingLayout) this.fragmentView;
        slidingLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, false) { // from class: im.uwrkaxlmjj.ui.hui.mine.PrivacyAndSafeActivity.2
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        };
        this.layoutManager = linearLayoutManager;
        recyclerListView.setLayoutManager(linearLayoutManager);
        this.listView.setVerticalScrollBarEnabled(false);
        this.listView.setItemAnimator(null);
        this.listView.setLayoutAnimation(null);
        slidingLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1.0f));
        this.listView.setAdapter(this.listAdapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$PrivacyAndSafeActivity$JYFkE9wWBTFFYEKU0u4xuMemZsE
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$createView$1$PrivacyAndSafeActivity(view, i);
            }
        });
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$1$PrivacyAndSafeActivity(View view, int position) {
        if (!view.isEnabled()) {
            return;
        }
        if (position == this.blockedRow) {
            presentFragment(new PrivacyUsersActivity());
            return;
        }
        if (position == this.sessionsRow) {
            presentFragment(new MrySessionsActivity(0));
            return;
        }
        if (position != this.lastSeenRow) {
            if (position == this.phoneNumberRow) {
                presentFragment(new PrivacyControlActivity(6));
                return;
            }
            if (position == this.groupsRow) {
                presentFragment(new PrivacyControlActivity(1));
                return;
            }
            if (position == this.friendsHubRow) {
                presentFragment(new PrivacyControlActivity(8));
                return;
            }
            if (position == this.callsRow) {
                presentFragment(new PrivacyControlActivity(2));
                return;
            }
            if (position == this.profilePhotoRow) {
                presentFragment(new PrivacyControlActivity(4));
                return;
            }
            if (position == this.forwardsRow) {
                presentFragment(new PrivacyControlActivity(5));
                return;
            }
            if (position == this.passwordRow) {
                getParentActivity().startActivity(new Intent(getParentActivity(), (Class<?>) TwoStepVerificationActivityNew.class));
                return;
            }
            if (position == this.passcodeRow) {
                if (SharedConfig.passcodeHash.length() > 0) {
                    presentFragment(new PasscodeActivity(2));
                    return;
                } else {
                    presentFragment(new PasscodeActivity(0));
                    return;
                }
            }
            if (position == this.dataUsageRow) {
                presentFragment(new DataUsageActivity());
                return;
            }
            if (position == this.proxySetRow) {
                presentFragment(new ProxyListActivity());
                return;
            }
            if (position == this.deleteAccountRow) {
                List<String> list = new ArrayList<>();
                list.add(LocaleController.formatPluralString("Months", 1));
                list.add(LocaleController.formatPluralString("Months", 3));
                list.add(LocaleController.formatPluralString("Months", 6));
                list.add(LocaleController.formatPluralString("Years", 1));
                DialogCommonList dialogCommonList = new DialogCommonList(getParentActivity(), list, (List<Integer>) null, 0, new AnonymousClass3(), 1);
                dialogCommonList.show();
            }
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.mine.PrivacyAndSafeActivity$3, reason: invalid class name */
    class AnonymousClass3 implements DialogCommonList.RecyclerviewItemClickCallBack {
        AnonymousClass3() {
        }

        @Override // im.uwrkaxlmjj.ui.dialogs.DialogCommonList.RecyclerviewItemClickCallBack
        public void onRecyclerviewItemClick(int position) {
            int value = 0;
            if (position == 0) {
                value = 30;
            } else if (position == 1) {
                value = 90;
            } else if (position == 2) {
                value = 182;
            } else if (position == 3) {
                value = 365;
            }
            final TLRPC.TL_account_setAccountTTL req = new TLRPC.TL_account_setAccountTTL();
            req.ttl = new TLRPC.TL_accountDaysTTL();
            req.ttl.days = value;
            PrivacyAndSafeActivity.this.getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$PrivacyAndSafeActivity$3$_YBi3KcrurqUYEJUYoVws0jXYng
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$onRecyclerviewItemClick$1$PrivacyAndSafeActivity$3(req, tLObject, tL_error);
                }
            });
        }

        public /* synthetic */ void lambda$onRecyclerviewItemClick$1$PrivacyAndSafeActivity$3(final TLRPC.TL_account_setAccountTTL req, final TLObject response, TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$PrivacyAndSafeActivity$3$w-o-efpNRCjJDU89y_Vlcn4S0hs
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$PrivacyAndSafeActivity$3(response, req);
                }
            });
        }

        public /* synthetic */ void lambda$null$0$PrivacyAndSafeActivity$3(TLObject response, TLRPC.TL_account_setAccountTTL req) {
            try {
                PrivacyAndSafeActivity.this.progressDialog.dismiss();
            } catch (Exception e) {
                FileLog.e(e);
            }
            if (response instanceof TLRPC.TL_boolTrue) {
                PrivacyAndSafeActivity.this.getContactsController().setDeleteAccountTTL(req.ttl.days);
                PrivacyAndSafeActivity.this.listAdapter.notifyDataSetChanged();
            }
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.privacyRulesUpdated) {
            ListAdapter listAdapter = this.listAdapter;
            if (listAdapter != null) {
                listAdapter.notifyDataSetChanged();
                return;
            }
            return;
        }
        if (id == NotificationCenter.blockedUsersDidLoad) {
            this.listAdapter.notifyItemChanged(this.blockedRow);
        }
    }

    private void updateRows() {
        this.rowCount = 0;
        this.friendsHubRow = -1;
        int i = 0 + 1;
        this.rowCount = i;
        this.emptyRow = 0;
        int i2 = i + 1;
        this.rowCount = i2;
        this.securityHeaderRow = i;
        int i3 = i2 + 1;
        this.rowCount = i3;
        this.blockedRow = i2;
        this.sessionsRow = -1;
        int i4 = i3 + 1;
        this.rowCount = i4;
        this.passwordRow = i3;
        int i5 = i4 + 1;
        this.rowCount = i5;
        this.passcodeRow = i4;
        int i6 = i5 + 1;
        this.rowCount = i6;
        this.sessionsDetailRow = i5;
        int i7 = i6 + 1;
        this.rowCount = i7;
        this.privacyHeaderRow = i6;
        int i8 = i7 + 1;
        this.rowCount = i8;
        this.phoneNumberRow = i7;
        int i9 = i8 + 1;
        this.rowCount = i9;
        this.groupsRow = i8;
        int i10 = i9 + 1;
        this.rowCount = i10;
        this.groupsDetailRow = i9;
        int i11 = i10 + 1;
        this.rowCount = i11;
        this.accountSectionRow = i10;
        int i12 = i11 + 1;
        this.rowCount = i12;
        this.deleteAccountRow = i11;
        int i13 = i12 + 1;
        this.rowCount = i13;
        this.deleteAccountDetailRow = i12;
        int i14 = i13 + 1;
        this.rowCount = i14;
        this.dataUsageRow = i13;
        int i15 = i14 + 1;
        this.rowCount = i15;
        this.dataUsageDetailRow = i14;
        this.rowCount = i15 + 1;
        this.proxySetRow = i15;
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    private void loadPasswordSettings() {
        if (getUserConfig().hasSecureData) {
            return;
        }
        TLRPC.TL_account_getPassword req = new TLRPC.TL_account_getPassword();
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$PrivacyAndSafeActivity$n6sfR3-xxZJpkM6BxZELRFpc9sM
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadPasswordSettings$3$PrivacyAndSafeActivity(tLObject, tL_error);
            }
        }, 10);
    }

    public /* synthetic */ void lambda$loadPasswordSettings$3$PrivacyAndSafeActivity(TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            TLRPC.TL_account_password password = (TLRPC.TL_account_password) response;
            if (password.has_secure_values) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$PrivacyAndSafeActivity$7MuaTrHJB9AXBoT2cz2KlVF3wHo
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$2$PrivacyAndSafeActivity();
                    }
                });
            }
        }
    }

    public /* synthetic */ void lambda$null$2$PrivacyAndSafeActivity() {
        getUserConfig().hasSecureData = true;
        getUserConfig().saveConfig(false);
        updateRows();
    }

    public static String formatRulesString(AccountInstance accountInstance, int rulesType) {
        ArrayList<TLRPC.PrivacyRule> privacyRules = accountInstance.getContactsController().getPrivacyRules(rulesType);
        if (privacyRules.size() == 0) {
            if (rulesType == 3) {
                return LocaleController.getString("P2PNobody", R.string.P2PNobody);
            }
            return LocaleController.getString("LastSeenNobody", R.string.LastSeenNobody);
        }
        int type = -1;
        int plus = 0;
        int minus = 0;
        for (int a = 0; a < privacyRules.size(); a++) {
            TLRPC.PrivacyRule rule = privacyRules.get(a);
            if (rule instanceof TLRPC.TL_privacyValueAllowChatParticipants) {
                TLRPC.TL_privacyValueAllowChatParticipants participants = (TLRPC.TL_privacyValueAllowChatParticipants) rule;
                int N = participants.chats.size();
                for (int b = 0; b < N; b++) {
                    TLRPC.Chat chat = accountInstance.getMessagesController().getChat(participants.chats.get(b));
                    if (chat != null) {
                        plus += chat.participants_count;
                    }
                }
            } else if (rule instanceof TLRPC.TL_privacyValueDisallowChatParticipants) {
                TLRPC.TL_privacyValueDisallowChatParticipants participants2 = (TLRPC.TL_privacyValueDisallowChatParticipants) rule;
                int N2 = participants2.chats.size();
                for (int b2 = 0; b2 < N2; b2++) {
                    TLRPC.Chat chat2 = accountInstance.getMessagesController().getChat(participants2.chats.get(b2));
                    if (chat2 != null) {
                        minus += chat2.participants_count;
                    }
                }
            } else if (rule instanceof TLRPC.TL_privacyValueAllowUsers) {
                TLRPC.TL_privacyValueAllowUsers privacyValueAllowUsers = (TLRPC.TL_privacyValueAllowUsers) rule;
                plus += privacyValueAllowUsers.users.size();
            } else if (rule instanceof TLRPC.TL_privacyValueDisallowUsers) {
                TLRPC.TL_privacyValueDisallowUsers privacyValueDisallowUsers = (TLRPC.TL_privacyValueDisallowUsers) rule;
                minus += privacyValueDisallowUsers.users.size();
            } else if (type == -1) {
                if (rule instanceof TLRPC.TL_privacyValueAllowAll) {
                    type = 0;
                } else if (rule instanceof TLRPC.TL_privacyValueDisallowAll) {
                    type = 1;
                } else {
                    type = 2;
                }
            }
        }
        if (type == 0 || (type == -1 && minus > 0)) {
            if (rulesType == 3) {
                if (minus == 0) {
                    return LocaleController.getString("P2PEverybody", R.string.P2PEverybody);
                }
                return LocaleController.formatString("P2PEverybodyMinus", R.string.P2PEverybodyMinus, Integer.valueOf(minus));
            }
            if (minus == 0) {
                return LocaleController.getString("LastSeenEverybody", R.string.LastSeenEverybody);
            }
            return LocaleController.formatString("LastSeenEverybodyMinus", R.string.LastSeenEverybodyMinus, Integer.valueOf(minus));
        }
        if (type == 2 || (type == -1 && minus > 0 && plus > 0)) {
            if (rulesType == 3) {
                if (plus == 0 && minus == 0) {
                    return LocaleController.getString("P2PContacts", R.string.P2PContacts);
                }
                if (plus != 0 && minus != 0) {
                    return LocaleController.formatString("P2PContactsMinusPlus", R.string.P2PContactsMinusPlus, Integer.valueOf(minus), Integer.valueOf(plus));
                }
                if (minus != 0) {
                    return LocaleController.formatString("P2PContactsMinus", R.string.P2PContactsMinus, Integer.valueOf(minus));
                }
                return LocaleController.formatString("P2PContactsPlus", R.string.P2PContactsPlus, Integer.valueOf(plus));
            }
            if (plus == 0 && minus == 0) {
                return LocaleController.getString("LastSeenContacts", R.string.LastSeenContacts);
            }
            if (plus != 0 && minus != 0) {
                return LocaleController.formatString("LastSeenContactsMinusPlus", R.string.LastSeenContactsMinusPlus, Integer.valueOf(minus), Integer.valueOf(plus));
            }
            if (minus != 0) {
                return LocaleController.formatString("LastSeenContactsMinus", R.string.LastSeenContactsMinus, Integer.valueOf(minus));
            }
            return LocaleController.formatString("LastSeenContactsPlus", R.string.LastSeenContactsPlus, Integer.valueOf(plus));
        }
        if (type == 1 || plus > 0) {
            if (rulesType == 3) {
                if (plus == 0) {
                    return LocaleController.getString("P2PNobody", R.string.P2PNobody);
                }
                return LocaleController.formatString("P2PNobodyPlus", R.string.P2PNobodyPlus, Integer.valueOf(plus));
            }
            if (plus == 0) {
                return LocaleController.getString("LastSeenNobody", R.string.LastSeenNobody);
            }
            return LocaleController.formatString("LastSeenNobodyPlus", R.string.LastSeenNobodyPlus, Integer.valueOf(plus));
        }
        return "unknown";
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
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
            return position == PrivacyAndSafeActivity.this.passcodeRow || position == PrivacyAndSafeActivity.this.passwordRow || position == PrivacyAndSafeActivity.this.blockedRow || position == PrivacyAndSafeActivity.this.sessionsRow || position == PrivacyAndSafeActivity.this.dataUsageRow || position == PrivacyAndSafeActivity.this.proxySetRow || (position == PrivacyAndSafeActivity.this.groupsRow && !PrivacyAndSafeActivity.this.getContactsController().getLoadingPrivicyInfo(1)) || ((position == PrivacyAndSafeActivity.this.friendsHubRow && !PrivacyAndSafeActivity.this.getContactsController().getLoadingPrivicyInfo(8)) || ((position == PrivacyAndSafeActivity.this.lastSeenRow && !PrivacyAndSafeActivity.this.getContactsController().getLoadingPrivicyInfo(0)) || ((position == PrivacyAndSafeActivity.this.callsRow && !PrivacyAndSafeActivity.this.getContactsController().getLoadingPrivicyInfo(2)) || ((position == PrivacyAndSafeActivity.this.profilePhotoRow && !PrivacyAndSafeActivity.this.getContactsController().getLoadingPrivicyInfo(4)) || ((position == PrivacyAndSafeActivity.this.forwardsRow && !PrivacyAndSafeActivity.this.getContactsController().getLoadingPrivicyInfo(5)) || ((position == PrivacyAndSafeActivity.this.phoneNumberRow && !PrivacyAndSafeActivity.this.getContactsController().getLoadingPrivicyInfo(6)) || (position == PrivacyAndSafeActivity.this.deleteAccountRow && !PrivacyAndSafeActivity.this.getContactsController().getLoadingDeleteInfo())))))));
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return PrivacyAndSafeActivity.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new TextSettingCell(this.mContext);
                RecyclerView.LayoutParams layoutParams = new RecyclerView.LayoutParams(-1, -2);
                layoutParams.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams.rightMargin = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 1) {
                view = new TextInfoPrivacyCell(this.mContext);
                RecyclerView.LayoutParams layoutParams2 = new RecyclerView.LayoutParams(-1, -2);
                layoutParams2.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams2.rightMargin = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams2);
            } else if (viewType == 2) {
                view = new HeaderCell(this.mContext);
                RecyclerView.LayoutParams layoutParams3 = new RecyclerView.LayoutParams(-1, -2);
                layoutParams3.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams3.rightMargin = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams3);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 3) {
                view = new EmptyCell(this.mContext, AndroidUtilities.dp(10.0f));
            } else {
                view = new TextCheckCell(this.mContext);
                RecyclerView.LayoutParams layoutParams4 = new RecyclerView.LayoutParams(-1, -2);
                layoutParams4.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams4.rightMargin = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams4);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String value;
            String value2;
            String value3;
            String value4;
            String value5;
            String value6;
            String value7;
            String value8;
            int itemViewType = holder.getItemViewType();
            if (itemViewType != 0) {
                if (itemViewType != 1) {
                    if (itemViewType == 2) {
                        HeaderCell headerCell = (HeaderCell) holder.itemView;
                        headerCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                        if (position != PrivacyAndSafeActivity.this.privacyHeaderRow) {
                            if (position != PrivacyAndSafeActivity.this.securityHeaderRow) {
                                if (position == PrivacyAndSafeActivity.this.accountSectionRow) {
                                    headerCell.setText(LocaleController.getString("PrivacyAdvanced", R.string.PrivacyAdvanced));
                                    return;
                                }
                                return;
                            }
                            headerCell.setText(LocaleController.getString("SecurityTitle", R.string.SecurityTitle));
                            return;
                        }
                        headerCell.setText(LocaleController.getString("PrivacyTitle", R.string.PrivacyTitle));
                        return;
                    }
                    return;
                }
                TextInfoPrivacyCell privacyCell = (TextInfoPrivacyCell) holder.itemView;
                if (position != PrivacyAndSafeActivity.this.deleteAccountDetailRow) {
                    if (position != PrivacyAndSafeActivity.this.groupsDetailRow) {
                        if (position != PrivacyAndSafeActivity.this.sessionsDetailRow) {
                            if (position == PrivacyAndSafeActivity.this.dataUsageDetailRow) {
                                privacyCell.setText(LocaleController.getString("DataUsageDetailText", R.string.DataUsageDetailText));
                                return;
                            }
                            return;
                        }
                        privacyCell.setText(LocaleController.getString("SessionsInfo", R.string.SessionsInfo));
                        return;
                    }
                    privacyCell.setText(LocaleController.getString("GroupsAndChannelsHelp", R.string.GroupsAndChannelsHelp));
                    return;
                }
                privacyCell.setText(LocaleController.getString("DeleteAccountHelp", R.string.DeleteAccountHelp));
                return;
            }
            TextSettingCell textCell = (TextSettingCell) holder.itemView;
            if (position != PrivacyAndSafeActivity.this.sessionsRow) {
                if (position != PrivacyAndSafeActivity.this.passwordRow) {
                    if (position != PrivacyAndSafeActivity.this.passcodeRow) {
                        if (position == PrivacyAndSafeActivity.this.blockedRow) {
                            int totalCount = PrivacyAndSafeActivity.this.getMessagesController().totalBlockedCount;
                            if (totalCount == 0) {
                                textCell.setTextAndValueAndIcon(LocaleController.getString("BlockedUsers", R.string.BlockedUsers), LocaleController.getString("BlockedEmpty", R.string.BlockedEmpty), R.id.ic_privacy_block, true, true);
                                return;
                            } else if (totalCount > 0) {
                                textCell.setTextAndValueAndIcon(LocaleController.getString("BlockedUsers", R.string.BlockedUsers), String.format("%d", Integer.valueOf(totalCount)), R.id.ic_privacy_block, true, true);
                                return;
                            } else {
                                textCell.setTextAndValueAndIcon(LocaleController.getString("BlockedUsers", R.string.BlockedUsers), R.id.ic_privacy_block, true, true);
                                return;
                            }
                        }
                        if (position == PrivacyAndSafeActivity.this.phoneNumberRow) {
                            if (PrivacyAndSafeActivity.this.getContactsController().getLoadingPrivicyInfo(6)) {
                                value8 = LocaleController.getString("Loading", R.string.Loading);
                            } else {
                                value8 = PrivacyAndSafeActivity.formatRulesString(PrivacyAndSafeActivity.this.getAccountInstance(), 6);
                            }
                            textCell.setTextAndValue(LocaleController.getString("PrivacyPhone", R.string.PrivacyPhone), value8, true, true);
                            return;
                        }
                        if (position == PrivacyAndSafeActivity.this.lastSeenRow) {
                            if (PrivacyAndSafeActivity.this.getContactsController().getLoadingPrivicyInfo(0)) {
                                value7 = LocaleController.getString("Loading", R.string.Loading);
                            } else {
                                value7 = PrivacyAndSafeActivity.formatRulesString(PrivacyAndSafeActivity.this.getAccountInstance(), 0);
                            }
                            textCell.setTextAndValue(LocaleController.getString("PrivacyLastSeen", R.string.PrivacyLastSeen), value7, true, true);
                            return;
                        }
                        if (position == PrivacyAndSafeActivity.this.groupsRow) {
                            if (PrivacyAndSafeActivity.this.getContactsController().getLoadingPrivicyInfo(1)) {
                                value6 = LocaleController.getString("Loading", R.string.Loading);
                            } else {
                                value6 = PrivacyAndSafeActivity.formatRulesString(PrivacyAndSafeActivity.this.getAccountInstance(), 1);
                            }
                            textCell.setTextAndValue(LocaleController.getString("GroupsAndChannels", R.string.GroupsAndChannels), value6, false, true);
                            textCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                            return;
                        }
                        if (position == PrivacyAndSafeActivity.this.friendsHubRow) {
                            if (PrivacyAndSafeActivity.this.getContactsController().getLoadingPrivicyInfo(8)) {
                                value5 = LocaleController.getString("Loading", R.string.Loading);
                            } else {
                                value5 = PrivacyAndSafeActivity.formatRulesString(PrivacyAndSafeActivity.this.getAccountInstance(), 8);
                            }
                            textCell.setTextAndValue(LocaleController.getString("FriendHub", R.string.FriendHub), value5, true, true);
                            textCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                            return;
                        }
                        if (position == PrivacyAndSafeActivity.this.callsRow) {
                            if (PrivacyAndSafeActivity.this.getContactsController().getLoadingPrivicyInfo(2)) {
                                value4 = LocaleController.getString("Loading", R.string.Loading);
                            } else {
                                value4 = PrivacyAndSafeActivity.formatRulesString(PrivacyAndSafeActivity.this.getAccountInstance(), 2);
                            }
                            textCell.setTextAndValue(LocaleController.getString("Calls", R.string.Calls), value4, true, true);
                            return;
                        }
                        if (position == PrivacyAndSafeActivity.this.profilePhotoRow) {
                            if (PrivacyAndSafeActivity.this.getContactsController().getLoadingPrivicyInfo(4)) {
                                value3 = LocaleController.getString("Loading", R.string.Loading);
                            } else {
                                value3 = PrivacyAndSafeActivity.formatRulesString(PrivacyAndSafeActivity.this.getAccountInstance(), 4);
                            }
                            textCell.setTextAndValue(LocaleController.getString("PrivacyProfilePhoto", R.string.PrivacyProfilePhoto), value3, true, true);
                            return;
                        }
                        if (position == PrivacyAndSafeActivity.this.forwardsRow) {
                            if (PrivacyAndSafeActivity.this.getContactsController().getLoadingPrivicyInfo(5)) {
                                value2 = LocaleController.getString("Loading", R.string.Loading);
                            } else {
                                value2 = PrivacyAndSafeActivity.formatRulesString(PrivacyAndSafeActivity.this.getAccountInstance(), 5);
                            }
                            textCell.setTextAndValue(LocaleController.getString("PrivacyForwards", R.string.PrivacyForwards), value2, true, true);
                            return;
                        }
                        if (position == PrivacyAndSafeActivity.this.deleteAccountRow) {
                            if (!PrivacyAndSafeActivity.this.getContactsController().getLoadingDeleteInfo()) {
                                int ttl = PrivacyAndSafeActivity.this.getContactsController().getDeleteAccountTTL();
                                if (ttl <= 182) {
                                    value = LocaleController.formatPluralString("Months", ttl / 30);
                                } else if (ttl == 365) {
                                    value = LocaleController.formatPluralString("Years", ttl / 365);
                                } else {
                                    value = LocaleController.formatPluralString("Days", ttl);
                                }
                            } else {
                                value = LocaleController.getString("Loading", R.string.Loading);
                            }
                            textCell.setTextAndValue(LocaleController.getString("DeleteAccountIfAwayFor2", R.string.DeleteAccountIfAwayFor2), value, false, true);
                            textCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                            return;
                        }
                        if (position != PrivacyAndSafeActivity.this.dataUsageRow) {
                            if (position == PrivacyAndSafeActivity.this.proxySetRow) {
                                textCell.setText(LocaleController.getString("ProxySettings", R.string.ProxySettings), false, true);
                                textCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                                return;
                            }
                            return;
                        }
                        textCell.setText(LocaleController.getString("DataUsageSetting", R.string.DataUsageSetting), false, true);
                        textCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                        return;
                    }
                    textCell.setTextAndValueAndIcon(LocaleController.getString("Passcode", R.string.Passcode), "", R.id.ic_privacy_lock_code, false, true);
                    textCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                }
                textCell.setTextAndValueAndIcon(LocaleController.getString("TwoStepVerification", R.string.TwoStepVerification), "", R.id.ic_privacy_two_steps, true, true);
                return;
            }
            textCell.setTextAndValueAndIcon(LocaleController.getString("SessionsTitle", R.string.SessionsTitle), "", R.id.ic_privacy_sessions, true, true);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == PrivacyAndSafeActivity.this.lastSeenRow || position == PrivacyAndSafeActivity.this.phoneNumberRow || position == PrivacyAndSafeActivity.this.blockedRow || position == PrivacyAndSafeActivity.this.deleteAccountRow || position == PrivacyAndSafeActivity.this.sessionsRow || position == PrivacyAndSafeActivity.this.passwordRow || position == PrivacyAndSafeActivity.this.passcodeRow || position == PrivacyAndSafeActivity.this.groupsRow || position == PrivacyAndSafeActivity.this.dataUsageRow || position == PrivacyAndSafeActivity.this.friendsHubRow || position == PrivacyAndSafeActivity.this.proxySetRow) {
                return 0;
            }
            if (position != PrivacyAndSafeActivity.this.deleteAccountDetailRow && position != PrivacyAndSafeActivity.this.groupsDetailRow && position != PrivacyAndSafeActivity.this.sessionsDetailRow && position != PrivacyAndSafeActivity.this.dataUsageDetailRow) {
                if (position == PrivacyAndSafeActivity.this.securityHeaderRow || position == PrivacyAndSafeActivity.this.accountSectionRow || position == PrivacyAndSafeActivity.this.privacyHeaderRow) {
                    return 2;
                }
                return position == PrivacyAndSafeActivity.this.emptyRow ? 3 : 0;
            }
            return 1;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{TextSettingsCell.class, HeaderCell.class, TextCheckCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText), new ThemeDescription(this.listView, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueHeader), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrack), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackChecked)};
    }
}
