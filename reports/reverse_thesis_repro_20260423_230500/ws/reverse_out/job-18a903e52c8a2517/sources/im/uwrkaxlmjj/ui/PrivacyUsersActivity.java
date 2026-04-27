package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.phoneformat.PhoneFormat;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ContactsActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.ManageChatTextCell;
import im.uwrkaxlmjj.ui.cells.ManageChatUserCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity;
import im.uwrkaxlmjj.ui.hui.contacts.AddContactsInfoActivity;
import im.uwrkaxlmjj.ui.hui.contacts.AddGroupingUserActivity;
import im.uwrkaxlmjj.ui.hui.decoration.TopBottomDecoration;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
public class PrivacyUsersActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate, ContactsActivity.ContactsActivityDelegate {
    public static final int PRIVACY_RULES_TYPE_ADDED_BY_PHONE = 7;
    public static final int PRIVACY_RULES_TYPE_CALLS = 2;
    public static final int PRIVACY_RULES_TYPE_FORWARDS = 5;
    public static final int PRIVACY_RULES_TYPE_INVITE = 1;
    public static final int PRIVACY_RULES_TYPE_LASTSEEN = 0;
    public static final int PRIVACY_RULES_TYPE_MOMENT = 8;
    public static final int PRIVACY_RULES_TYPE_P2P = 3;
    public static final int PRIVACY_RULES_TYPE_PHONE = 6;
    public static final int PRIVACY_RULES_TYPE_PHOTO = 4;
    private int blockUserDetailRow;
    private int blockUserRow;
    private boolean blockedUsersActivity = true;
    private int currentSubType;
    private int currentType;
    private PrivacyActivityDelegate delegate;
    private EmptyTextProgressView emptyView;
    private boolean isAlwaysShare;
    private boolean isGroup;
    private LinearLayoutManager layoutManager;
    private RecyclerListView listView;
    private ListAdapter listViewAdapter;
    private int rowCount;
    private int rulesType;
    private ArrayList<Integer> uidArray;
    private int usersDetailRow;
    private int usersEndRow;
    private int usersHeaderRow;
    private int usersStartRow;

    public interface PrivacyActivityDelegate {
        void didUpdateUserList(ArrayList<Integer> arrayList, boolean z);
    }

    public PrivacyUsersActivity() {
    }

    public PrivacyUsersActivity(ArrayList<Integer> users, boolean group, boolean always, int rulesType, int currentType, int currentSubType) {
        this.uidArray = users;
        this.isAlwaysShare = always;
        this.isGroup = group;
        this.rulesType = rulesType;
        this.currentType = currentType;
        this.currentSubType = currentSubType;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.updateInterfaces);
        if (this.blockedUsersActivity) {
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.blockedUsersDidLoad);
            return true;
        }
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.updateInterfaces);
        if (this.blockedUsersActivity) {
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.blockedUsersDidLoad);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        if (this.blockedUsersActivity) {
            this.actionBar.setTitle(LocaleController.getString("BlockedUsers", R.string.BlockedUsers));
        } else if (this.isGroup) {
            if (this.isAlwaysShare) {
                this.actionBar.setTitle(LocaleController.getString("AlwaysAllow", R.string.AlwaysAllow));
            } else {
                this.actionBar.setTitle(LocaleController.getString("NeverAllow", R.string.NeverAllow));
            }
        } else if (this.isAlwaysShare) {
            this.actionBar.setTitle(LocaleController.getString("AlwaysShareWithTitle", R.string.AlwaysShareWithTitle));
        } else {
            this.actionBar.setTitle(LocaleController.getString("NeverShareWithTitle", R.string.NeverShareWithTitle));
        }
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.PrivacyUsersActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    PrivacyUsersActivity.this.finishFragment();
                }
            }
        });
        this.fragmentView = new FrameLayout(context);
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
        this.emptyView = emptyTextProgressView;
        if (this.blockedUsersActivity) {
            emptyTextProgressView.setText(LocaleController.getString("NoBlocked", R.string.NoBlocked));
        } else {
            emptyTextProgressView.setText(LocaleController.getString("NoContacts", R.string.NoContacts));
        }
        frameLayout.addView(this.emptyView, LayoutHelper.createFrame(-1, -1.0f));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setOverScrollMode(2);
        this.listView.setEmptyView(this.emptyView);
        RecyclerListView recyclerListView2 = this.listView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, false);
        this.layoutManager = linearLayoutManager;
        recyclerListView2.setLayoutManager(linearLayoutManager);
        this.listView.setVerticalScrollBarEnabled(false);
        RecyclerListView recyclerListView3 = this.listView;
        ListAdapter listAdapter = new ListAdapter(context);
        this.listViewAdapter = listAdapter;
        recyclerListView3.setAdapter(listAdapter);
        this.listView.setVerticalScrollbarPosition(LocaleController.isRTL ? 1 : 2);
        this.listView.addItemDecoration(new TopBottomDecoration());
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1, AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyUsersActivity$Ln5NWnFouoUi1aiqLqLtCTTJCcg
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$createView$1$PrivacyUsersActivity(view, i);
            }
        });
        this.listView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyUsersActivity$Q9eFcvMBI1WopRouSfFn9lqFtA0
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
            public final boolean onItemClick(View view, int i) {
                return this.f$0.lambda$createView$2$PrivacyUsersActivity(view, i);
            }
        });
        if (this.blockedUsersActivity) {
            this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.PrivacyUsersActivity.2
                @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
                public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                    if (!PrivacyUsersActivity.this.getMessagesController().blockedEndReached) {
                        int firstVisibleItem = PrivacyUsersActivity.this.layoutManager.findFirstVisibleItemPosition();
                        int visibleItemCount = Math.abs(PrivacyUsersActivity.this.layoutManager.findLastVisibleItemPosition() - firstVisibleItem) + 1;
                        int totalItemCount = recyclerView.getAdapter().getItemCount();
                        if (visibleItemCount > 0 && PrivacyUsersActivity.this.layoutManager.findLastVisibleItemPosition() >= totalItemCount - 10) {
                            PrivacyUsersActivity.this.getMessagesController().getBlockedUsers(false);
                        }
                    }
                }
            });
        }
        if (getMessagesController().totalBlockedCount < 0) {
            this.emptyView.showProgress();
        } else {
            this.emptyView.showTextView();
        }
        updateRows();
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$1$PrivacyUsersActivity(View view, int position) {
        Integer userId;
        if (position == this.blockUserRow) {
            if (this.blockedUsersActivity) {
                presentFragment(new DialogOrContactPickerActivity());
                return;
            }
            List<TLRPC.User> selectUsers = new ArrayList<>();
            AddGroupingUserActivity fragment = new AddGroupingUserActivity(selectUsers, 1, LocaleController.getString("EmpryUsersPlaceholder", R.string.EmpryUsersPlaceholder), false);
            fragment.setDelegate(new AddGroupingUserActivity.AddGroupingUserActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyUsersActivity$VwvF0ZInqNLtEtphxvb-5NiIb28
                @Override // im.uwrkaxlmjj.ui.hui.contacts.AddGroupingUserActivity.AddGroupingUserActivityDelegate
                public final void didSelectedContact(ArrayList arrayList) {
                    this.f$0.lambda$null$0$PrivacyUsersActivity(arrayList);
                }
            });
            presentFragment(fragment);
            return;
        }
        int i = this.usersStartRow;
        if (position >= i && position < this.usersEndRow) {
            if (this.blockedUsersActivity) {
                userId = Integer.valueOf(getMessagesController().blockedUsers.keyAt(position - this.usersStartRow));
            } else {
                userId = this.uidArray.get(position - i);
                if (userId.intValue() < 0) {
                    userId = Integer.valueOf(-userId.intValue());
                }
            }
            TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(userId);
            if (user == null) {
                return;
            }
            Bundle args = new Bundle();
            args.putInt("user_id", userId.intValue());
            if (user.contact) {
                presentFragment(new NewProfileActivity(args));
            } else {
                presentFragment(new AddContactsInfoActivity(null, user));
            }
        }
    }

    public /* synthetic */ void lambda$null$0$PrivacyUsersActivity(ArrayList users) {
        ArrayList<Integer> ids = new ArrayList<>();
        if (users != null && users.size() > 0) {
            Iterator it = users.iterator();
            while (it.hasNext()) {
                TLRPC.User user = (TLRPC.User) it.next();
                if (user != null && user.id > 0) {
                    ids.add(Integer.valueOf(user.id));
                }
            }
        }
        for (Integer id1 : ids) {
            if (!this.uidArray.contains(id1)) {
                this.uidArray.add(id1);
            }
        }
        if (!this.blockedUsersActivity) {
            processDone();
        }
        updateRows();
        PrivacyActivityDelegate privacyActivityDelegate = this.delegate;
        if (privacyActivityDelegate != null) {
            privacyActivityDelegate.didUpdateUserList(this.uidArray, true);
        }
    }

    public /* synthetic */ boolean lambda$createView$2$PrivacyUsersActivity(View view, int position) {
        int i = this.usersStartRow;
        if (position >= i && position < this.usersEndRow) {
            if (this.blockedUsersActivity) {
                showUnblockAlert(getMessagesController().blockedUsers.keyAt(position - this.usersStartRow));
                return true;
            }
            showUnblockAlert(this.uidArray.get(position - i).intValue());
            return true;
        }
        return false;
    }

    private void processDone() {
        if (getParentActivity() == null) {
            return;
        }
        if (this.currentType != 0 && this.rulesType == 0) {
            final SharedPreferences preferences = MessagesController.getGlobalMainSettings();
            boolean showed = preferences.getBoolean("privacyAlertShowed", false);
            if (!showed) {
                AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                if (this.rulesType == 1) {
                    builder.setMessage(LocaleController.getString("WhoCanAddMeInfo", R.string.WhoCanAddMeInfo));
                } else {
                    builder.setMessage(LocaleController.getString("CustomHelp", R.string.CustomHelp));
                }
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyUsersActivity$8dlUdK4gbcw1D9uhq78OqqtIjAw
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$processDone$3$PrivacyUsersActivity(preferences, dialogInterface, i);
                    }
                });
                builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                showDialog(builder.create());
                return;
            }
        }
        applyCurrentPrivacySettings();
    }

    public /* synthetic */ void lambda$processDone$3$PrivacyUsersActivity(SharedPreferences preferences, DialogInterface dialogInterface, int i) {
        applyCurrentPrivacySettings();
        preferences.edit().putBoolean("privacyAlertShowed", true).commit();
    }

    private void applyCurrentPrivacySettings() {
        TLRPC.InputUser inputUser;
        TLRPC.InputUser inputUser2;
        TLRPC.TL_account_setPrivacy req = new TLRPC.TL_account_setPrivacy();
        int i = this.rulesType;
        if (i == 6) {
            req.key = new TLRPC.TL_inputPrivacyKeyPhoneNumber();
            if (this.currentType == 1) {
                TLRPC.TL_account_setPrivacy req2 = new TLRPC.TL_account_setPrivacy();
                req2.key = new TLRPC.TL_inputPrivacyKeyAddedByPhone();
                if (this.currentSubType == 0) {
                    req2.rules.add(new TLRPC.TL_inputPrivacyValueAllowAll());
                } else {
                    req2.rules.add(new TLRPC.TL_inputPrivacyValueAllowContacts());
                }
                ConnectionsManager.getInstance(this.currentAccount).sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyUsersActivity$iNrgMzJ-uWa8xUycmVVPqFwjDe4
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$applyCurrentPrivacySettings$5$PrivacyUsersActivity(tLObject, tL_error);
                    }
                }, 2);
            }
        } else if (i == 5) {
            req.key = new TLRPC.TL_inputPrivacyKeyForwards();
        } else if (i == 4) {
            req.key = new TLRPC.TL_inputPrivacyKeyProfilePhoto();
        } else if (i == 3) {
            req.key = new TLRPC.TL_inputPrivacyKeyPhoneP2P();
        } else if (i == 2) {
            req.key = new TLRPC.TL_inputPrivacyKeyPhoneCall();
        } else if (i == 1) {
            req.key = new TLRPC.TL_inputPrivacyKeyChatInvite();
        } else if (i == 8) {
            req.key = new TLRPC.TL_inputPrivacyKeyMoment();
        } else {
            req.key = new TLRPC.TL_inputPrivacyKeyStatusTimestamp();
        }
        if (this.currentType != 0 && this.uidArray.size() > 0) {
            TLRPC.TL_inputPrivacyValueAllowUsers usersRule = new TLRPC.TL_inputPrivacyValueAllowUsers();
            TLRPC.TL_inputPrivacyValueAllowChatParticipants chatsRule = new TLRPC.TL_inputPrivacyValueAllowChatParticipants();
            for (int a = 0; a < this.uidArray.size(); a++) {
                int id = this.uidArray.get(a).intValue();
                if (id > 0) {
                    TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(id));
                    if (user != null && (inputUser2 = MessagesController.getInstance(this.currentAccount).getInputUser(user)) != null) {
                        usersRule.users.add(inputUser2);
                    }
                } else {
                    chatsRule.chats.add(Integer.valueOf(-id));
                }
            }
            req.rules.add(usersRule);
            req.rules.add(chatsRule);
        } else if (this.currentType != 1 && this.uidArray.size() > 0) {
            TLRPC.TL_inputPrivacyValueDisallowUsers usersRule2 = new TLRPC.TL_inputPrivacyValueDisallowUsers();
            TLRPC.TL_inputPrivacyValueDisallowChatParticipants chatsRule2 = new TLRPC.TL_inputPrivacyValueDisallowChatParticipants();
            for (int a2 = 0; a2 < this.uidArray.size(); a2++) {
                int id2 = this.uidArray.get(a2).intValue();
                if (id2 > 0) {
                    TLRPC.User user2 = getMessagesController().getUser(Integer.valueOf(id2));
                    if (user2 != null && (inputUser = getMessagesController().getInputUser(user2)) != null) {
                        usersRule2.users.add(inputUser);
                    }
                } else {
                    chatsRule2.chats.add(Integer.valueOf(-id2));
                }
            }
            req.rules.add(usersRule2);
            req.rules.add(chatsRule2);
        }
        int i2 = this.currentType;
        if (i2 == 0) {
            req.rules.add(new TLRPC.TL_inputPrivacyValueAllowAll());
        } else if (i2 == 1) {
            req.rules.add(new TLRPC.TL_inputPrivacyValueDisallowAll());
        } else if (i2 == 2) {
            req.rules.add(new TLRPC.TL_inputPrivacyValueAllowContacts());
        }
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyUsersActivity$zB5JiFAG9otE0IcKI0ivCQpRvm0
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$applyCurrentPrivacySettings$7$PrivacyUsersActivity(tLObject, tL_error);
            }
        }, 2);
    }

    public /* synthetic */ void lambda$applyCurrentPrivacySettings$5$PrivacyUsersActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyUsersActivity$piBEQy0wippnz8H-973drPH6HWM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$4$PrivacyUsersActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$4$PrivacyUsersActivity(TLRPC.TL_error error, TLObject response) {
        if (error == null) {
            TLRPC.TL_account_privacyRules privacyRules = (TLRPC.TL_account_privacyRules) response;
            ContactsController.getInstance(this.currentAccount).setPrivacyRules(privacyRules.rules, 7);
        }
    }

    public /* synthetic */ void lambda$applyCurrentPrivacySettings$7$PrivacyUsersActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyUsersActivity$1WiwwceOfe6cFIkMC5RQP3a7vuY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$6$PrivacyUsersActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$6$PrivacyUsersActivity(TLRPC.TL_error error, TLObject response) {
        if (error == null) {
            TLRPC.TL_account_privacyRules privacyRules = (TLRPC.TL_account_privacyRules) response;
            MessagesController.getInstance(this.currentAccount).putUsers(privacyRules.users, false);
            MessagesController.getInstance(this.currentAccount).putChats(privacyRules.chats, false);
            ContactsController.getInstance(this.currentAccount).setPrivacyRules(privacyRules.rules, this.rulesType);
            return;
        }
        showErrorAlert();
    }

    private void showErrorAlert() {
        if (getParentActivity() == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setMessage(LocaleController.getString("PrivacyFloodControlError", R.string.PrivacyFloodControlError));
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        showDialog(builder.create());
    }

    public void setDelegate(PrivacyActivityDelegate privacyActivityDelegate) {
        this.delegate = privacyActivityDelegate;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showUnblockAlert(final int uid) {
        CharSequence[] items;
        if (getParentActivity() == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        if (this.blockedUsersActivity) {
            items = new CharSequence[]{LocaleController.getString("Unblock", R.string.Unblock)};
        } else {
            items = new CharSequence[]{LocaleController.getString("Delete", R.string.Delete)};
        }
        builder.setItems(items, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyUsersActivity$uFpVbNsbGnf4SAu0lo3eiw_fNxk
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showUnblockAlert$8$PrivacyUsersActivity(uid, dialogInterface, i);
            }
        });
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$showUnblockAlert$8$PrivacyUsersActivity(int uid, DialogInterface dialogInterface, int i) {
        if (i == 0) {
            if (this.blockedUsersActivity) {
                getMessagesController().unblockUser(uid);
                return;
            }
            this.uidArray.remove(Integer.valueOf(uid));
            if (!this.blockedUsersActivity) {
                processDone();
            }
            updateRows();
            PrivacyActivityDelegate privacyActivityDelegate = this.delegate;
            if (privacyActivityDelegate != null) {
                privacyActivityDelegate.didUpdateUserList(this.uidArray, false);
            }
            if (this.uidArray.isEmpty()) {
                finishFragment();
            }
        }
    }

    private void updateRows() {
        int count;
        this.rowCount = 0;
        if (!this.blockedUsersActivity || getMessagesController().totalBlockedCount >= 0) {
            int i = this.rowCount;
            int i2 = i + 1;
            this.rowCount = i2;
            this.blockUserRow = i;
            this.rowCount = i2 + 1;
            this.blockUserDetailRow = i2;
            if (this.blockedUsersActivity) {
                count = getMessagesController().blockedUsers.size();
            } else {
                count = this.uidArray.size();
            }
            if (count != 0) {
                int i3 = this.rowCount;
                int i4 = i3 + 1;
                this.rowCount = i4;
                this.usersHeaderRow = i3;
                this.usersStartRow = i4;
                int i5 = i4 + count;
                this.rowCount = i5;
                this.usersEndRow = i5;
                this.rowCount = i5 + 1;
                this.usersDetailRow = i5;
            } else {
                this.usersHeaderRow = -1;
                this.usersStartRow = -1;
                this.usersEndRow = -1;
                this.usersDetailRow = -1;
            }
        }
        ListAdapter listAdapter = this.listViewAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.updateInterfaces) {
            int mask = ((Integer) args[0]).intValue();
            if ((mask & 2) != 0 || (mask & 1) != 0) {
                updateVisibleRows(mask);
                return;
            }
            return;
        }
        if (id == NotificationCenter.blockedUsersDidLoad) {
            this.emptyView.showTextView();
            updateRows();
        }
    }

    private void updateVisibleRows(int mask) {
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView == null) {
            return;
        }
        int count = recyclerListView.getChildCount();
        for (int a = 0; a < count; a++) {
            View child = this.listView.getChildAt(a);
            if (child instanceof ManageChatUserCell) {
                ((ManageChatUserCell) child).update(mask);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.listViewAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.ContactsActivity.ContactsActivityDelegate
    public void didSelectContact(TLRPC.User user, String param, ContactsActivity activity) {
        if (user == null) {
            return;
        }
        getMessagesController().blockUser(user.id);
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return PrivacyUsersActivity.this.rowCount;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int viewType = holder.getItemViewType();
            return viewType == 0 || viewType == 2;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType != 0) {
                if (viewType == 1) {
                    view = new TextInfoPrivacyCell(this.mContext);
                } else if (viewType == 2) {
                    View view2 = new ManageChatTextCell(this.mContext);
                    view2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    view = view2;
                } else {
                    HeaderCell headerCell = new HeaderCell(this.mContext, false, 21, 11, false);
                    headerCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    headerCell.setHeight(43);
                    view = headerCell;
                }
            } else {
                View view3 = new ManageChatUserCell(this.mContext, 7, 6, true);
                view3.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                ((ManageChatUserCell) view3).setDelegate(new ManageChatUserCell.ManageChatUserCellDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyUsersActivity$ListAdapter$sUUcI1vdobSfeQKDFbhwZ6n08ag
                    @Override // im.uwrkaxlmjj.ui.cells.ManageChatUserCell.ManageChatUserCellDelegate
                    public final boolean onOptionsButtonCheck(ManageChatUserCell manageChatUserCell, boolean z) {
                        return this.f$0.lambda$onCreateViewHolder$0$PrivacyUsersActivity$ListAdapter(manageChatUserCell, z);
                    }
                });
                view = view3;
            }
            return new RecyclerListView.Holder(view);
        }

        public /* synthetic */ boolean lambda$onCreateViewHolder$0$PrivacyUsersActivity$ListAdapter(ManageChatUserCell cell, boolean click) {
            if (click) {
                PrivacyUsersActivity.this.showUnblockAlert(((Integer) cell.getTag()).intValue());
                return true;
            }
            return true;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String subtitle;
            String number;
            int itemViewType = holder.getItemViewType();
            if (itemViewType != 0) {
                if (itemViewType == 1) {
                    TextInfoPrivacyCell privacyCell = (TextInfoPrivacyCell) holder.itemView;
                    if (position == PrivacyUsersActivity.this.blockUserDetailRow) {
                        if (PrivacyUsersActivity.this.blockedUsersActivity) {
                            privacyCell.setText(LocaleController.getString("BlockedUsersInfo", R.string.BlockedUsersInfo));
                            return;
                        } else {
                            privacyCell.setText(null);
                            return;
                        }
                    }
                    if (position == PrivacyUsersActivity.this.usersDetailRow) {
                        privacyCell.setText("");
                        return;
                    }
                    return;
                }
                if (itemViewType == 2) {
                    ManageChatTextCell actionCell = (ManageChatTextCell) holder.itemView;
                    actionCell.setColors(Theme.key_windowBackgroundWhiteBlueIcon, Theme.key_windowBackgroundWhiteBlueButton);
                    if (PrivacyUsersActivity.this.blockedUsersActivity) {
                        actionCell.setText(LocaleController.getString("BlockUser", R.string.BlockUser), null, R.drawable.actions_addmember2, false);
                    } else {
                        actionCell.setText(LocaleController.getString("PrivacyAddAnException", R.string.PrivacyAddAnException), null, R.drawable.actions_addmember2, false);
                    }
                    actionCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                }
                if (itemViewType == 3) {
                    HeaderCell headerCell = (HeaderCell) holder.itemView;
                    if (position == PrivacyUsersActivity.this.usersHeaderRow) {
                        if (PrivacyUsersActivity.this.blockedUsersActivity) {
                            headerCell.setText(LocaleController.formatPluralString("BlockedUsersCount", PrivacyUsersActivity.this.getMessagesController().totalBlockedCount));
                        } else {
                            headerCell.setText(LocaleController.getString("PrivacyExceptions", R.string.PrivacyExceptions));
                        }
                        headerCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                        return;
                    }
                    return;
                }
                return;
            }
            ManageChatUserCell userCell = (ManageChatUserCell) holder.itemView;
            int uid = PrivacyUsersActivity.this.blockedUsersActivity ? PrivacyUsersActivity.this.getMessagesController().blockedUsers.keyAt(position - PrivacyUsersActivity.this.usersStartRow) : ((Integer) PrivacyUsersActivity.this.uidArray.get(position - PrivacyUsersActivity.this.usersStartRow)).intValue();
            userCell.setTag(Integer.valueOf(uid));
            if (uid > 0) {
                TLRPC.User user = PrivacyUsersActivity.this.getMessagesController().getUser(Integer.valueOf(uid));
                if (user != null) {
                    if (user.bot) {
                        number = LocaleController.getString("Bot", R.string.Bot).substring(0, 1).toUpperCase() + LocaleController.getString("Bot", R.string.Bot).substring(1);
                    } else {
                        String number2 = user.phone;
                        if (number2 != null && user.phone.length() != 0) {
                            number = PhoneFormat.getInstance().format(Marker.ANY_NON_NULL_MARKER + user.phone);
                        } else {
                            number = LocaleController.getString("NumberUnknown", R.string.NumberUnknown);
                        }
                    }
                    userCell.setData(user, null, number, position != PrivacyUsersActivity.this.usersEndRow - 1);
                }
            } else {
                TLRPC.Chat chat = PrivacyUsersActivity.this.getMessagesController().getChat(Integer.valueOf(-uid));
                if (chat != null) {
                    if (chat.participants_count != 0) {
                        subtitle = LocaleController.formatPluralString("Members", chat.participants_count);
                    } else if (chat.has_geo) {
                        subtitle = LocaleController.getString("MegaLocation", R.string.MegaLocation);
                    } else {
                        String subtitle2 = chat.username;
                        if (TextUtils.isEmpty(subtitle2)) {
                            subtitle = LocaleController.getString("MegaPrivate", R.string.MegaPrivate);
                        } else {
                            subtitle = LocaleController.getString("MegaPublic", R.string.MegaPublic);
                        }
                    }
                    userCell.setData(chat, null, subtitle, position != PrivacyUsersActivity.this.usersEndRow - 1);
                }
            }
            if (position == PrivacyUsersActivity.this.usersEndRow - 1) {
                userCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != PrivacyUsersActivity.this.usersHeaderRow) {
                if (position != PrivacyUsersActivity.this.blockUserRow) {
                    if (position == PrivacyUsersActivity.this.blockUserDetailRow || position == PrivacyUsersActivity.this.usersDetailRow) {
                        return 1;
                    }
                    return 0;
                }
                return 2;
            }
            return 3;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ThemeDescription.ThemeDescriptionDelegate cellDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacyUsersActivity$ce5HErEOT0sEWYNZHv4-YeEO4xo
            @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
            public final void didSetColor() {
                this.f$0.lambda$getThemeDescriptions$9$PrivacyUsersActivity();
            }
        };
        return new ThemeDescription[]{new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{ManageChatUserCell.class, ManageChatTextCell.class, HeaderCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.emptyView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_emptyListPlaceholder), new ThemeDescription(this.emptyView, ThemeDescription.FLAG_PROGRESSBAR, null, null, null, null, Theme.key_progressCircle), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{ManageChatUserCell.class}, new String[]{"nameTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{ManageChatUserCell.class}, new String[]{"statusColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteGrayText), new ThemeDescription(this.listView, 0, new Class[]{ManageChatUserCell.class}, new String[]{"statusOnlineColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteBlueText), new ThemeDescription(this.listView, 0, new Class[]{ManageChatUserCell.class}, null, new Drawable[]{Theme.avatar_savedDrawable}, null, Theme.key_avatar_text), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundRed), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundOrange), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundViolet), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundGreen), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundCyan), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundBlue), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundPink), new ThemeDescription(this.listView, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueHeader), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{ManageChatTextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{ManageChatTextCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayIcon), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{ManageChatTextCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueButton), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{ManageChatTextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueIcon)};
    }

    public /* synthetic */ void lambda$getThemeDescriptions$9$PrivacyUsersActivity() {
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            int count = recyclerListView.getChildCount();
            for (int a = 0; a < count; a++) {
                View child = this.listView.getChildAt(a);
                if (child instanceof ManageChatUserCell) {
                    ((ManageChatUserCell) child).update(0);
                }
            }
        }
    }
}
