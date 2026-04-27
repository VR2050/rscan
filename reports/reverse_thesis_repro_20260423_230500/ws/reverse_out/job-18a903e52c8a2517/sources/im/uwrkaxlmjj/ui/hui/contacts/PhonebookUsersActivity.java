package im.uwrkaxlmjj.ui.hui.contacts;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.fragment.app.FragmentActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import butterknife.BindView;
import com.bjz.comm.net.premission.PermissionUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.XAlertDialog;
import im.uwrkaxlmjj.ui.cells.DividerCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hui.CharacterParser;
import im.uwrkaxlmjj.ui.hviews.MryEmptyTextProgressView;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialog;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;
import im.uwrkaxlmjj.ui.hviews.sidebar.SideBar;
import java.util.ArrayList;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PhonebookUsersActivity extends BaseSearchViewFragment implements NotificationCenter.NotificationCenterDelegate {
    private LinearLayoutManager layoutManager;

    @BindView(R.attr.listview)
    RecyclerListView listView;
    private ListAdapter listViewAdapter;

    @BindView(R.attr.emptyView)
    MryEmptyTextProgressView mEmptyView;

    @BindView(R.attr.sideBar)
    SideBar mSideBar;

    @BindView(R.attr.tv_char)
    MryTextView mTvChar;
    private AlertDialog permissionDialog;

    @BindView(R.attr.searchLayout)
    FrameLayout searchLayout;

    @BindView(R.attr.searchView)
    MrySearchView searchView;
    private boolean checkPermission = true;
    private boolean askAboutContacts = true;
    private ArrayList<TLRPC.User> phoneBookUsers = new ArrayList<>();
    private HashMap<String, ArrayList<TLRPC.User>> map = new HashMap<>();
    private ArrayList<String> mapKeysList = new ArrayList<>();
    private HashMap<String, TLRPC.TL_inputPhoneContact> inputPhoneContactsMap = new HashMap<>();

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.contactAboutPhonebookLoaded);
        this.checkPermission = UserConfig.getInstance(this.currentAccount).syncContacts;
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.contactAboutPhonebookLoaded);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        this.mEmptyView.showProgress();
        if (this.checkPermission && Build.VERSION.SDK_INT >= 23) {
            FragmentActivity activity = getParentActivity();
            if (activity != null) {
                this.checkPermission = false;
                if (activity.checkSelfPermission(PermissionUtils.LINKMAIN) != 0) {
                    if (activity.shouldShowRequestPermissionRationale(PermissionUtils.LINKMAIN)) {
                        AlertDialog.Builder builder = AlertsCreator.createContactsPermissionDialog(activity, new MessagesStorage.IntCallback() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$PhonebookUsersActivity$qFjVPDbMTmE-NAUo3m4aX3CW_XI
                            @Override // im.uwrkaxlmjj.messenger.MessagesStorage.IntCallback
                            public final void run(int i) {
                                this.f$0.lambda$onResume$0$PhonebookUsersActivity(i);
                            }
                        });
                        AlertDialog alertDialogCreate = builder.create();
                        this.permissionDialog = alertDialogCreate;
                        showDialog(alertDialogCreate);
                        return;
                    }
                    askForPermissons(true);
                    return;
                }
                ContactsController.getInstance(this.currentAccount).checkPhonebookUsers();
                return;
            }
            return;
        }
        this.mEmptyView.showTextView();
    }

    public /* synthetic */ void lambda$onResume$0$PhonebookUsersActivity(int param) {
        this.askAboutContacts = param != 0;
        if (param == 0) {
            return;
        }
        askForPermissons(false);
    }

    private void askForPermissons(boolean alert) {
        Activity activity = getParentActivity();
        if (activity == null || !UserConfig.getInstance(this.currentAccount).syncContacts || activity.checkSelfPermission(PermissionUtils.LINKMAIN) == 0) {
            return;
        }
        if (alert && this.askAboutContacts) {
            AlertDialog.Builder builder = AlertsCreator.createContactsPermissionDialog(activity, new MessagesStorage.IntCallback() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$PhonebookUsersActivity$3Ko-BsHZLfm4nMrCJH4wV5Rov9c
                @Override // im.uwrkaxlmjj.messenger.MessagesStorage.IntCallback
                public final void run(int i) {
                    this.f$0.lambda$askForPermissons$1$PhonebookUsersActivity(i);
                }
            });
            showDialog(builder.create());
        } else {
            ArrayList<String> permissons = new ArrayList<>();
            permissons.add(PermissionUtils.LINKMAIN);
            String[] items = (String[]) permissons.toArray(new String[0]);
            activity.requestPermissions(items, 1);
        }
    }

    public /* synthetic */ void lambda$askForPermissons$1$PhonebookUsersActivity(int param) {
        this.askAboutContacts = param != 0;
        if (param == 0) {
            return;
        }
        askForPermissons(false);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onRequestPermissionsResultFragment(int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == 1) {
            for (int a = 0; a < permissions.length; a++) {
                if (grantResults.length > a && PermissionUtils.LINKMAIN.equals(permissions[a])) {
                    if (grantResults[a] == 0) {
                        ContactsController.getInstance(this.currentAccount).checkPhonebookUsers();
                    } else {
                        SharedPreferences.Editor editorEdit = MessagesController.getGlobalNotificationsSettings().edit();
                        this.askAboutContacts = false;
                        editorEdit.putBoolean("askAboutContacts", false).commit();
                    }
                }
            }
        }
    }

    private void groupingUsers(ArrayList<TLRPC.User> users) {
        String key;
        if (users == null) {
            return;
        }
        this.mapKeysList.clear();
        this.map.clear();
        for (TLRPC.User user : users) {
            String key2 = CharacterParser.getInstance().getSelling(UserObject.getFirstName(user));
            if (key2.length() > 1) {
                key2 = key2.substring(0, 1);
            }
            if (key2.length() == 0) {
                key = "#";
            } else {
                key = key2.toUpperCase();
            }
            ArrayList<TLRPC.User> arr = this.map.get(key);
            if (arr == null) {
                arr = new ArrayList<>();
                this.map.put(key, arr);
                this.mapKeysList.add(key);
            }
            arr.add(user);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onBeginSlide() {
        super.onBeginSlide();
        MrySearchView mrySearchView = this.searchView;
        if (mrySearchView != null && mrySearchView.isSearchFieldVisible()) {
            this.searchView.closeSearchField();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_phone_book_users_layout, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        useButterKnife();
        super.createView(context);
        initActionbar();
        initEmptyView();
        initSideBar();
        initList();
        return this.fragmentView;
    }

    private void initSideBar() {
        this.mSideBar.setTextView(this.mTvChar);
        this.mSideBar.setOnTouchingLetterChangedListener(new SideBar.OnTouchingLetterChangedListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$PhonebookUsersActivity$DdUdE7iHfCdCJxvMH2ysTz0juWU
            @Override // im.uwrkaxlmjj.ui.hviews.sidebar.SideBar.OnTouchingLetterChangedListener
            public final void onTouchingLetterChanged(String str) {
                this.f$0.lambda$initSideBar$2$PhonebookUsersActivity(str);
            }
        });
    }

    public /* synthetic */ void lambda$initSideBar$2$PhonebookUsersActivity(String s) {
        if ("↑".equals(s)) {
            this.listView.scrollToPosition(0);
            return;
        }
        if (!"☆".equals(s)) {
            int section = this.listViewAdapter.getSectionForChar(s.charAt(0));
            int position = this.listViewAdapter.getPositionForSection(section);
            if (position != -1) {
                this.listView.getLayoutManager().scrollToPosition(position);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment
    protected MrySearchView getSearchView() {
        this.searchView.setHintText(LocaleController.getString("Search", R.string.Search));
        this.searchLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        return this.searchView;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment
    protected void initSearchView() {
        super.initSearchView();
    }

    private void initActionbar() {
        this.actionBar.setTitle(LocaleController.getString("AppContacts", R.string.AppContacts));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setCastShadows(false);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.contacts.PhonebookUsersActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    PhonebookUsersActivity.this.finishFragment();
                }
            }
        });
    }

    private void initEmptyView() {
        this.mEmptyView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.mEmptyView.setText(LocaleController.getString("NoContacts", R.string.NoContacts));
        this.mEmptyView.setTopImage(R.id.img_empty_default);
    }

    private void initList() {
        this.listView.setEmptyView(this.mEmptyView);
        this.listView.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.listView.setHasFixedSize(true);
        this.listView.setNestedScrollingEnabled(false);
        this.listView.setVerticalScrollBarEnabled(false);
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(this.fragmentView.getContext(), 1, false);
        this.layoutManager = linearLayoutManager;
        this.listView.setLayoutManager(linearLayoutManager);
        ListAdapter listAdapter = new ListAdapter(getParentActivity());
        this.listViewAdapter = listAdapter;
        listAdapter.setList(this.mapKeysList, this.map);
        this.listView.setOverScrollMode(2);
        this.listView.requestDisallowInterceptTouchEvent(true);
        this.listView.setDisallowInterceptTouchEvents(true);
        this.listView.setDisableHighlightState(true);
        this.listView.setAdapter(this.listViewAdapter);
        this.listView.addOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.PhonebookUsersActivity.2
            private boolean scrollingManually;

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                super.onScrollStateChanged(recyclerView, newState);
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                super.onScrolled(recyclerView, dx, dy);
                LinearLayoutManager layoutManager = (LinearLayoutManager) recyclerView.getLayoutManager();
                int firstPosition = layoutManager.findFirstVisibleItemPosition();
                String s = PhonebookUsersActivity.this.listViewAdapter.getLetter(firstPosition);
                PhonebookUsersActivity.this.mSideBar.setChooseChar(s);
            }
        });
        this.listViewAdapter.notifyDataSetChanged();
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.contactAboutPhonebookLoaded) {
            ArrayList<TLRPC.User> arrayList = (ArrayList) args[0];
            this.phoneBookUsers = arrayList;
            this.inputPhoneContactsMap = (HashMap) args[1];
            groupingUsers(arrayList);
            this.listViewAdapter.setList(this.mapKeysList, this.map);
            this.listViewAdapter.notifyDataSetChanged();
            this.mEmptyView.showTextView();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ListAdapter extends RecyclerListView.SectionsAdapter {
        private ArrayList<String> list;
        private Context mContext;
        private HashMap<String, ArrayList<TLRPC.User>> updateMaps;

        public void setList(ArrayList<String> list, HashMap<String, ArrayList<TLRPC.User>> map) {
            this.list = list;
            this.updateMaps = map;
        }

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int count = 0;
            if (this.updateMaps != null) {
                for (String item : this.list) {
                    count += this.updateMaps.get(item).size();
                }
            }
            return count;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getSectionCount() {
            return this.list.size();
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getCountForSection(int section) {
            return this.updateMaps.get(this.list.get(section)).size();
        }

        public int getSectionForChar(char section) {
            for (int i = 0; i < getSectionCount(); i++) {
                String sortStr = this.list.get(i);
                char firstChar = sortStr.toUpperCase().charAt(0);
                if (firstChar == section) {
                    return i;
                }
            }
            return -1;
        }

        public int getPositionForSection(int section) {
            if (section == -1) {
                return -1;
            }
            int positionStart = 0;
            for (int i = 0; i < getSectionCount(); i++) {
                if (i >= section) {
                    return positionStart;
                }
                int count = getCountForSection(i);
                positionStart += count;
            }
            return -1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public boolean isEnabled(int section, int row) {
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getItemViewType(int section, int position) {
            return 1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public Object getItem(int section, int position) {
            String key = this.list.get(section);
            ArrayList<TLRPC.User> updates = this.updateMaps.get(key);
            return updates.get(position);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public void onBindViewHolder(int section, int position, RecyclerView.ViewHolder holder) {
            String str;
            if (holder.getItemViewType() == 1) {
                BackupImageView avatar = (BackupImageView) holder.itemView.findViewById(R.attr.avatarImage);
                avatar.setRoundRadius(AndroidUtilities.dp(7.5f));
                TextView nameText = (TextView) holder.itemView.findViewById(R.attr.nameText);
                TextView appCodeNameText = (TextView) holder.itemView.findViewById(R.attr.bioText);
                MryRoundButton statusBtn = (MryRoundButton) holder.itemView.findViewById(R.attr.statusText);
                TextView statusText2 = (TextView) holder.itemView.findViewById(R.attr.statusText2);
                DividerCell divider = (DividerCell) holder.itemView.findViewById(R.attr.divider);
                nameText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
                appCodeNameText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
                statusBtn.setPrimaryRoundFillStyle(AndroidUtilities.dp(26.0f));
                statusText2.setTextColor(-4737097);
                RelativeLayout.LayoutParams lp1 = (RelativeLayout.LayoutParams) statusBtn.getLayoutParams();
                lp1.rightMargin = AndroidUtilities.dp(27.5f);
                statusBtn.setLayoutParams(lp1);
                RelativeLayout.LayoutParams lp2 = (RelativeLayout.LayoutParams) statusText2.getLayoutParams();
                lp2.rightMargin = AndroidUtilities.dp(27.5f);
                statusText2.setLayoutParams(lp2);
                if (position == getItemCount() - 1) {
                    divider.setVisibility(8);
                }
                final TLRPC.User user = (TLRPC.User) getItem(section, position);
                AvatarDrawable avatarDrawable = new AvatarDrawable(user);
                avatarDrawable.setColor(Theme.getColor(Theme.key_avatar_backgroundInProfileBlue));
                avatar.setImage(ImageLocation.getForUser(user, false), "50_50", avatarDrawable, user);
                TLRPC.TL_inputPhoneContact contact = (TLRPC.TL_inputPhoneContact) PhonebookUsersActivity.this.inputPhoneContactsMap.get(user.phone);
                if (contact != null) {
                    nameText.setText(contact.last_name + contact.first_name);
                }
                if (TextUtils.isEmpty(user.first_name)) {
                    str = "";
                } else {
                    str = LocaleController.getString("AppName", R.string.AppName) + ": " + user.first_name;
                }
                appCodeNameText.setText(str);
                if (!user.mutual_contact) {
                    statusBtn.setText(LocaleController.getString("Add", R.string.Add));
                    statusBtn.setVisibility(0);
                    statusText2.setVisibility(8);
                } else {
                    statusText2.setText(LocaleController.getString("AddedContacts", R.string.AddedContacts));
                    statusBtn.setVisibility(8);
                    statusText2.setVisibility(0);
                }
                statusBtn.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$PhonebookUsersActivity$ListAdapter$VmDnlg_6ICiHkbdE7Cozy2J8zqo
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$onBindViewHolder$0$PhonebookUsersActivity$ListAdapter(user, view);
                    }
                });
            }
        }

        public /* synthetic */ void lambda$onBindViewHolder$0$PhonebookUsersActivity$ListAdapter(TLRPC.User user, View v) {
            PhonebookUsersActivity.this.startContactApply("hello", user);
            Bundle bundle = new Bundle();
            bundle.putInt("from_type", 6);
            AddContactsInfoActivity addContactsInfoActivity = new AddContactsInfoActivity(bundle, user);
            PhonebookUsersActivity.this.presentFragment(addContactsInfoActivity);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public View getSectionHeaderView(int section, View view) {
            return null;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 1) {
                view = LayoutInflater.from(this.mContext).inflate(R.layout.item_contacts_apply_layout, parent, false);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(65.0f)));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public String getLetter(int position) {
            int section = getSectionForPosition(position);
            if (section == -1) {
                return null;
            }
            return this.list.get(section);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public int getPositionForScrollProgress(float progress) {
            return (int) (getItemCount() * progress);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            super.notifyDataSetChanged();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startContactApply(String greet, TLRPC.User user) {
        final XAlertDialog progressDialog = new XAlertDialog(getParentActivity(), 4);
        TLRPCContacts.ContactsRequestApply req = new TLRPCContacts.ContactsRequestApply();
        req.flag = 0;
        req.from_type = 2;
        req.inputUser = getMessagesController().getInputUser(user);
        req.first_name = user.first_name;
        req.last_name = user.first_name;
        req.greet = greet;
        req.group_id = 0;
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$PhonebookUsersActivity$Zq6HR4WaRO_wdIUfI_-_qF916N0
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$startContactApply$3$PhonebookUsersActivity(progressDialog, tLObject, tL_error);
            }
        });
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$PhonebookUsersActivity$vRNRoLryIbrua9aaYBQLajb2hqY
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$startContactApply$4$PhonebookUsersActivity(reqId, dialogInterface);
            }
        });
        try {
            progressDialog.show();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$startContactApply$3$PhonebookUsersActivity(XAlertDialog progressDialog, TLObject response, TLRPC.TL_error error) {
        if (error != null) {
            progressDialog.dismiss();
            XDialog.Builder builder = new XDialog.Builder(getParentActivity());
            builder.setMessage(LocaleController.getString("friends_apply_fail", R.string.friends_apply_fail));
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            builder.create().show();
            return;
        }
        progressDialog.dismiss();
        if (response instanceof TLRPCContacts.ContactApplyResp) {
            TLRPCContacts.ContactApplyResp res = (TLRPCContacts.ContactApplyResp) response;
            getMessagesController().saveContactsAppliesId(res.applyInfo.id);
        }
    }

    public /* synthetic */ void lambda$startContactApply$4$PhonebookUsersActivity(int reqId, DialogInterface dialog) {
        getConnectionsManager().cancelRequest(reqId, true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onSearchExpand() {
        this.mEmptyView.setText(LocaleController.getString("NoResult", R.string.NoResult));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onSearchCollapse() {
        this.mEmptyView.setText(LocaleController.getString("NoContacts", R.string.NoContacts));
        groupingUsers(this.phoneBookUsers);
        ListAdapter listAdapter = this.listViewAdapter;
        if (listAdapter != null) {
            listAdapter.setList(this.mapKeysList, this.map);
            this.listViewAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onTextChange(String text) {
        if (!TextUtils.isEmpty(text)) {
            ArrayList<TLRPC.User> searchedUsers = new ArrayList<>();
            for (TLRPC.User user : this.phoneBookUsers) {
                TLRPC.TL_inputPhoneContact contact = this.inputPhoneContactsMap.get(user.phone);
                if (contact != null) {
                    String str = "";
                    if (contact.last_name != null) {
                        if ((contact.last_name + contact.first_name) != null) {
                            str = contact.first_name;
                        }
                    }
                    String name = str;
                    if (name.contains(text) || name.toLowerCase().contains(text)) {
                        searchedUsers.add(user);
                    }
                }
            }
            groupingUsers(searchedUsers);
            ListAdapter listAdapter = this.listViewAdapter;
            if (listAdapter != null) {
                listAdapter.setList(this.mapKeysList, this.map);
                this.listViewAdapter.notifyDataSetChanged();
            }
        }
    }
}
