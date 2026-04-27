package im.uwrkaxlmjj.ui.fragments;

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SecretChatHelper;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChannelCreateActivity;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.ContactAddActivity;
import im.uwrkaxlmjj.ui.ContactsActivity;
import im.uwrkaxlmjj.ui.GroupCreateActivity;
import im.uwrkaxlmjj.ui.GroupInviteActivity;
import im.uwrkaxlmjj.ui.NewContactActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.MenuDrawable;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.adapters.SearchAdapter;
import im.uwrkaxlmjj.ui.cells.UserCell;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.fragments.adapter.FmtContactsAdapter;
import im.uwrkaxlmjj.ui.hcells.ContactUserCell;
import im.uwrkaxlmjj.ui.hui.chats.MryDialogsActivity;
import im.uwrkaxlmjj.ui.hui.contacts.AddContactsActivity;
import im.uwrkaxlmjj.ui.hui.contacts.AddContactsInfoActivity;
import im.uwrkaxlmjj.ui.hui.contacts.MyGroupingActivity;
import im.uwrkaxlmjj.ui.hui.contacts.NewFriendsActivity;
import im.uwrkaxlmjj.ui.hui.decoration.TopDecorationWithSearch;
import im.uwrkaxlmjj.ui.hui.discovery.ActionIntroActivity;
import im.uwrkaxlmjj.ui.hviews.MryEmptyTextProgressView;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;
import im.uwrkaxlmjj.ui.hviews.sidebar.SideBar;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ContactsFragment extends BaseFmts implements NotificationCenter.NotificationCenterDelegate {
    private static final int ADD_BUTTON = 1;
    private ActionBarMenuItem addItem;
    private int channelId;
    private int chatId;
    private Context context;
    private boolean createSecretChat;
    private boolean creatingChat;
    private FmtContactsDelegate delegate;
    private boolean destroyAfterSelect;
    private boolean disableSections;
    private MryEmptyTextProgressView emptyView;
    private boolean floatingHidden;
    private boolean hasGps;
    private SparseArray<TLRPC.User> ignoreUsers;
    private boolean isCharClicked;
    private LinearLayoutManager layoutManager;
    private SlidingItemMenuRecyclerView listView;
    private FmtContactsAdapter listViewAdapter;
    private boolean needPhonebook;
    private boolean onlyUsers;
    private int prevPosition;
    private int prevTop;
    private boolean returnAsResult;
    private boolean scrollUpdated;
    private FrameLayout searchLayout;
    private SearchAdapter searchListViewAdapter;
    private MrySearchView searchView;
    private boolean searchWas;
    private boolean searching;
    private SideBar sideBar;
    private boolean sortByName;
    private ActionBarMenuItem sortItem;
    private boolean allowBots = true;
    private boolean needForwardCount = true;
    private boolean needFinishFragment = true;
    private boolean resetDelegate = true;
    private String selectAlertString = null;
    private boolean allowUsernameSearch = true;
    private boolean askAboutContacts = true;
    private boolean checkPermission = true;

    public interface FmtContactsDelegate {
        void updateContactsApplyCount(int i);
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.contactsDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.encryptedChatCreated);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.contactApplyUpdateCount);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.userFullInfoDidLoad);
        this.checkPermission = UserConfig.getInstance(this.currentAccount).syncContacts;
        if (this.arguments != null) {
            this.onlyUsers = this.arguments.getBoolean("onlyUsers", false);
            this.destroyAfterSelect = this.arguments.getBoolean("destroyAfterSelect", false);
            this.returnAsResult = this.arguments.getBoolean("returnAsResult", false);
            this.createSecretChat = this.arguments.getBoolean("createSecretChat", false);
            this.selectAlertString = this.arguments.getString("selectAlertString");
            this.allowUsernameSearch = this.arguments.getBoolean("allowUsernameSearch", true);
            this.needForwardCount = this.arguments.getBoolean("needForwardCount", true);
            this.allowBots = this.arguments.getBoolean("allowBots", true);
            this.channelId = this.arguments.getInt("channelId", 0);
            this.needFinishFragment = this.arguments.getBoolean("needFinishFragment", true);
            this.chatId = this.arguments.getInt("chat_id", 0);
            this.disableSections = this.arguments.getBoolean("disableSections", false);
            this.resetDelegate = this.arguments.getBoolean("resetDelegate", false);
        } else {
            this.needPhonebook = true;
        }
        if (!this.createSecretChat && !this.returnAsResult) {
            this.sortByName = SharedConfig.sortContactsByName;
        }
        ContactsController.getInstance(this.currentAccount).checkInviteText();
    }

    private void initActionBar(FrameLayout frameLayout) {
        this.actionBar = createActionBar();
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle(LocaleController.getString("Contacts", R.string.Contacts));
        this.actionBar.setBackButtonDrawable(new MenuDrawable());
        this.actionBar.getBackButton().setVisibility(8);
        frameLayout.addView(this.actionBar, LayoutHelper.createFrame(-1, -2.0f));
        this.actionBar.setDelegate(new ActionBar.ActionBarDelegate() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$ContactsFragment$xLYC7eIibVJLvd9dn4R8d51ds_8
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarDelegate
            public final void onSearchFieldVisibilityChanged(boolean z) {
                this.f$0.lambda$initActionBar$0$ContactsFragment(z);
            }
        });
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.fragments.ContactsFragment.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == 1) {
                    ContactsFragment.this.presentFragment(new AddContactsActivity());
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        this.addItem = menu.addItem(1, R.id.ic_add_circle);
    }

    public /* synthetic */ void lambda$initActionBar$0$ContactsFragment(boolean visible) {
        this.actionBar.getBackButton().setVisibility(visible ? 0 : 8);
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        this.context = getActivity();
        this.searching = false;
        this.searchWas = false;
        this.fragmentView = new FrameLayout(this.context) { // from class: im.uwrkaxlmjj.ui.fragments.ContactsFragment.2
            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                ContactsFragment.this.emptyView.setTranslationY(AndroidUtilities.dp(250.0f));
                if (ContactsFragment.this.listView.getAdapter() == ContactsFragment.this.listViewAdapter) {
                    ContactsFragment.this.emptyView.getVisibility();
                }
            }
        };
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        initActionBar(frameLayout);
        initList(frameLayout);
        initSearchView(frameLayout);
        initSideBar(frameLayout);
        return this.fragmentView;
    }

    private void initSearchView(final FrameLayout frameLayout) {
        FrameLayout frameLayout2 = new FrameLayout(this.context);
        this.searchLayout = frameLayout2;
        frameLayout.addView(frameLayout2, LayoutHelper.createFrameWithActionBar(-1, 55));
        MrySearchView mrySearchView = new MrySearchView(this.context);
        this.searchView = mrySearchView;
        mrySearchView.setHintText(LocaleController.getString("SearchForPeopleAndGroups", R.string.SearchForPeopleAndGroups));
        this.searchLayout.setBackgroundColor(Theme.getColor(Theme.key_searchview_solidColor));
        this.searchView.setEditTextBackground(getParentActivity().getDrawable(R.drawable.shape_edit_bg));
        this.searchLayout.addView(this.searchView, LayoutHelper.createFrame(-1.0f, 35.0f, 17, 10.0f, 10.0f, 10.0f, 10.0f));
        this.searchView.setiSearchViewDelegate(new MrySearchView.ISearchViewDelegate() { // from class: im.uwrkaxlmjj.ui.fragments.ContactsFragment.3
            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onStart(boolean focus) {
                if (focus) {
                    ContactsFragment.this.hideTitle(frameLayout);
                } else {
                    ContactsFragment.this.showTitle(frameLayout);
                }
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onSearchExpand() {
                ContactsFragment.this.searching = true;
                if (ContactsFragment.this.sortItem != null) {
                    ContactsFragment.this.sortItem.setVisibility(8);
                }
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public boolean canCollapseSearch() {
                ContactsFragment.this.searchListViewAdapter.searchDialogs(null);
                ContactsFragment.this.searching = false;
                ContactsFragment.this.searchWas = false;
                ContactsFragment.this.listView.setAdapter(ContactsFragment.this.listViewAdapter);
                ContactsFragment.this.listView.setSectionsType(1);
                ContactsFragment.this.listViewAdapter.notifyDataSetChanged();
                ContactsFragment.this.listView.setFastScrollVisible(true);
                ContactsFragment.this.listView.setVerticalScrollBarEnabled(false);
                ContactsFragment.this.emptyView.setText(LocaleController.getString("NoContacts", R.string.NoContacts));
                ContactsFragment.this.emptyView.setTopImage(R.id.img_empty_default);
                if (ContactsFragment.this.sortItem != null) {
                    ContactsFragment.this.sortItem.setVisibility(0);
                }
                return true;
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onSearchCollapse() {
                ContactsFragment.this.searching = false;
                ContactsFragment.this.searchWas = false;
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onTextChange(String text) {
                if (ContactsFragment.this.searchListViewAdapter == null) {
                    return;
                }
                if (text.length() != 0) {
                    ContactsFragment.this.searchWas = true;
                    if (ContactsFragment.this.listView != null) {
                        ContactsFragment.this.listView.setAdapter(ContactsFragment.this.searchListViewAdapter);
                        ContactsFragment.this.listView.setSectionsType(0);
                        ContactsFragment.this.searchListViewAdapter.notifyDataSetChanged();
                        ContactsFragment.this.listView.setFastScrollVisible(false);
                        ContactsFragment.this.listView.setVerticalScrollBarEnabled(true);
                    }
                    if (ContactsFragment.this.emptyView != null) {
                        ContactsFragment.this.emptyView.setTopImage(R.id.img_empty_default);
                        ContactsFragment.this.emptyView.setText(LocaleController.getString("NoResult", R.string.NoResult));
                    }
                }
                ContactsFragment.this.searchListViewAdapter.searchDialogs(text);
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onActionSearch(String trim) {
            }
        });
    }

    private void initSideBar(FrameLayout frameLayout) {
        TextView textView = new TextView(this.context);
        textView.setTextSize(50.0f);
        textView.setGravity(17);
        textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        frameLayout.addView(textView, LayoutHelper.createFrame(100, 100, 17));
        SideBar sideBar = new SideBar(this.context);
        this.sideBar = sideBar;
        sideBar.setTextView(textView);
        ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        String[] chars = (String[]) sortedUsersSectionsArray.toArray(new String[sortedUsersSectionsArray.size()]);
        this.sideBar.setChars(chars);
        frameLayout.addView(this.sideBar, LayoutHelper.createFrame(35.0f, -2.0f, 21, 0.0f, 90.0f, 0.0f, 0.0f));
        this.sideBar.setOnTouchingLetterChangedListener(new SideBar.OnTouchingLetterChangedListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$ContactsFragment$nn3KhubvXf0D18VjHUkQlGkNuXM
            @Override // im.uwrkaxlmjj.ui.hviews.sidebar.SideBar.OnTouchingLetterChangedListener
            public final void onTouchingLetterChanged(String str) {
                this.f$0.lambda$initSideBar$1$ContactsFragment(str);
            }
        });
    }

    public /* synthetic */ void lambda$initSideBar$1$ContactsFragment(String s) {
        if ("↑".equals(s)) {
            this.listView.scrollToPosition(0);
            this.searchLayout.setScrollY(0);
        } else if (!"☆".equals(s)) {
            int section = this.listViewAdapter.getSectionForChar(s.charAt(0));
            int position = this.listViewAdapter.getPositionForSection(section);
            if (position != -1) {
                this.listView.getLayoutManager().scrollToPosition(position);
                this.isCharClicked = true;
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r12v0 */
    /* JADX WARN: Type inference failed for: r1v7, types: [im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView] */
    /* JADX WARN: Type inference failed for: r2v13 */
    /* JADX WARN: Type inference failed for: r2v4 */
    /* JADX WARN: Type inference failed for: r2v8 */
    /* JADX WARN: Type inference failed for: r2v9, types: [int] */
    /* JADX WARN: Type inference failed for: r4v8, types: [java.lang.Throwable] */
    private void initList(FrameLayout frameLayout) {
        final ?? CanUserDoAdminAction;
        LinearLayout linearLayout = new LinearLayout(this.context);
        frameLayout.addView(linearLayout, LayoutHelper.createFrameWithActionBar(-1, -1));
        this.searchListViewAdapter = new SearchAdapter(this.context, this.ignoreUsers, this.allowUsernameSearch, false, false, this.allowBots, true, 0);
        if (this.chatId != 0) {
            CanUserDoAdminAction = ChatObject.canUserDoAdminAction(MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.chatId)), 3);
        } else if (this.channelId != 0) {
            TLRPC.Chat chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.channelId));
            CanUserDoAdminAction = (ChatObject.canUserDoAdminAction(chat, 3) && TextUtils.isEmpty(chat.username)) ? (char) 2 : (char) 0;
        } else {
            CanUserDoAdminAction = 0;
        }
        try {
            this.hasGps = ApplicationLoader.applicationContext.getPackageManager().hasSystemFeature("android.hardware.location.gps");
        } catch (Throwable th) {
            this.hasGps = false;
        }
        FmtContactsAdapter fmtContactsAdapter = new FmtContactsAdapter(this.context, this.onlyUsers ? 1 : 0, this.needPhonebook, this.ignoreUsers, CanUserDoAdminAction == true ? 1 : 0, this.hasGps) { // from class: im.uwrkaxlmjj.ui.fragments.ContactsFragment.4
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
            public void notifyDataSetChanged() {
                super.notifyDataSetChanged();
                if (ContactsFragment.this.listView != null && ContactsFragment.this.listView.getAdapter() == this) {
                    int count = super.getItemCount();
                    ContactsFragment.this.emptyView.setVisibility(count == 2 ? 0 : 8);
                }
            }
        };
        this.listViewAdapter = fmtContactsAdapter;
        fmtContactsAdapter.setDelegate(new FmtContactsAdapter.FmtContactsAdapterDelegate() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$ContactsFragment$UcG1oyj5hW1SRrPP7V-LXetsm-w
            @Override // im.uwrkaxlmjj.ui.fragments.adapter.FmtContactsAdapter.FmtContactsAdapterDelegate
            public final void onDeleteItem(int i) {
                this.f$0.lambda$initList$2$ContactsFragment(i);
            }
        });
        this.listViewAdapter.setOnContactHeaderItemClickListener(new FmtContactsAdapter.OnContactHeaderItemClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$ContactsFragment$pmHVSD3O6mvHke0Btl8YLmSk_JY
            @Override // im.uwrkaxlmjj.ui.fragments.adapter.FmtContactsAdapter.OnContactHeaderItemClickListener
            public final void onItemClick(View view) {
                this.f$0.lambda$initList$3$ContactsFragment(view);
            }
        });
        this.listViewAdapter.setSortType(1);
        this.listViewAdapter.setDisableSections(true);
        this.listViewAdapter.setClassGuid(getClassGuid());
        MryEmptyTextProgressView mryEmptyTextProgressView = new MryEmptyTextProgressView(this.context);
        this.emptyView = mryEmptyTextProgressView;
        mryEmptyTextProgressView.setShowAtCenter(true);
        this.emptyView.setText(LocaleController.getString("NoContacts", R.string.NoContacts));
        this.emptyView.setTopImage(R.id.img_empty_default);
        this.emptyView.showTextView();
        frameLayout.addView(this.emptyView, LayoutHelper.createFrame(-1, -2, 17));
        SlidingItemMenuRecyclerView slidingItemMenuRecyclerView = new SlidingItemMenuRecyclerView(this.context) { // from class: im.uwrkaxlmjj.ui.fragments.ContactsFragment.5
            @Override // android.view.View
            public void setPadding(int left, int top, int right, int bottom) {
                super.setPadding(left, top, right, bottom);
                if (ContactsFragment.this.emptyView != null) {
                    ContactsFragment.this.emptyView.setPadding(left, 0, right, bottom);
                }
            }
        };
        this.listView = slidingItemMenuRecyclerView;
        slidingItemMenuRecyclerView.setOverScrollMode(2);
        this.listView.setSectionsType(1);
        this.listView.setVerticalScrollBarEnabled(false);
        this.listView.addItemDecoration(new TopDecorationWithSearch());
        ?? r1 = this.listView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(this.context, 1, false);
        this.layoutManager = linearLayoutManager;
        r1.setLayoutManager(linearLayoutManager);
        this.listView.setAdapter(this.listViewAdapter);
        linearLayout.addView(this.listView, LayoutHelper.createLinear(-1, -1, 10.0f, 0.0f, 10.0f, 0.0f));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$ContactsFragment$Us2KOu37C2A8y2ejkNt81MTBvF8
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initList$5$ContactsFragment(CanUserDoAdminAction, view, i);
            }
        });
        this.listView.addOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.fragments.ContactsFragment.6
            private boolean scrollingManually;

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                ContactsFragment.this.isCharClicked = false;
                if (newState == 1) {
                    if (ContactsFragment.this.searching && ContactsFragment.this.searchWas) {
                        AndroidUtilities.hideKeyboard(ContactsFragment.this.getParentActivity().getCurrentFocus());
                    }
                    this.scrollingManually = true;
                    return;
                }
                this.scrollingManually = false;
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                super.onScrolled(recyclerView, dx, dy);
                int off = recyclerView.computeVerticalScrollOffset();
                if (off >= 0) {
                    ContactsFragment.this.searchLayout.setScrollY(off > AndroidUtilities.dp(55.0f) ? AndroidUtilities.dp(55.0f) : off);
                }
                if (!ContactsFragment.this.isCharClicked) {
                    LinearLayoutManager layoutManager = (LinearLayoutManager) recyclerView.getLayoutManager();
                    int firstPosition = layoutManager.findFirstVisibleItemPosition();
                    String s = ContactsFragment.this.listViewAdapter.getLetter(firstPosition);
                    if (TextUtils.isEmpty(s) && ContactsFragment.this.listViewAdapter.getSectionForPosition(firstPosition) == 0) {
                        s = ContactsFragment.this.listViewAdapter.getLetter(ContactsFragment.this.listViewAdapter.getPositionForSection(1));
                    }
                    ContactsFragment.this.sideBar.setChooseChar(s);
                }
            }
        });
    }

    public /* synthetic */ void lambda$initList$2$ContactsFragment(int userId) {
        Bundle args = new Bundle();
        args.putInt("user_id", userId);
        presentFragment(new ContactAddActivity(args));
    }

    public /* synthetic */ void lambda$initList$3$ContactsFragment(View view) {
        int id = view.getId();
        if (id == R.attr.ll_new_friend) {
            presentFragment(new NewFriendsActivity());
        }
        switch (id) {
            case R.attr.ll_my_channel /* 2131296936 */:
                Bundle args2 = new Bundle();
                args2.putInt("dialogsType", 5);
                presentFragment(new MryDialogsActivity(args2));
                break;
            case R.attr.ll_my_group /* 2131296937 */:
                Bundle args1 = new Bundle();
                args1.putInt("dialogsType", 6);
                presentFragment(new MryDialogsActivity(args1));
                break;
            case R.attr.ll_my_grouping /* 2131296938 */:
                presentFragment(new MyGroupingActivity());
                break;
        }
    }

    public /* synthetic */ void lambda$initList$5$ContactsFragment(int inviteViaLink, View view, int position) {
        if (this.searching && this.searchWas) {
            Object object = this.searchListViewAdapter.getItem(position);
            if (object instanceof TLRPC.User) {
                TLRPC.User user = (TLRPC.User) object;
                if (user == null) {
                    return;
                }
                if (this.searchListViewAdapter.isGlobalSearch(position)) {
                    ArrayList<TLRPC.User> users = new ArrayList<>();
                    users.add(user);
                    MessagesController.getInstance(this.currentAccount).putUsers(users, false);
                    MessagesStorage.getInstance(this.currentAccount).putUsersAndChats(users, null, false, true);
                }
                if (this.returnAsResult) {
                    SparseArray<TLRPC.User> sparseArray = this.ignoreUsers;
                    if (sparseArray != null && sparseArray.indexOfKey(user.id) >= 0) {
                        return;
                    } else {
                        return;
                    }
                }
                if (this.createSecretChat) {
                    if (user.id == UserConfig.getInstance(this.currentAccount).getClientUserId()) {
                        return;
                    }
                    this.creatingChat = true;
                    SecretChatHelper.getInstance(this.currentAccount).startSecretChat(getParentActivity(), user);
                    return;
                }
                if (!user.contact && !user.bot) {
                    getMessagesController();
                    if (!MessagesController.isSupportUser(user)) {
                        presentFragment(new AddContactsInfoActivity(null, user));
                        return;
                    }
                }
                Bundle args = new Bundle();
                args.putInt("user_id", user.id);
                if (MessagesController.getInstance(this.currentAccount).checkCanOpenChat(args, getCurrentFragment())) {
                    presentFragment(new ChatActivity(args), false);
                    return;
                }
                return;
            }
            if (object instanceof String) {
                String str = (String) object;
                if (!str.equals("section")) {
                    NewContactActivity activity = new NewContactActivity();
                    activity.setInitialPhoneNumber(str);
                    presentFragment(activity);
                    return;
                }
                return;
            }
            return;
        }
        int section = this.listViewAdapter.getSectionForPosition(position);
        int row = this.listViewAdapter.getPositionInSectionForPosition(position);
        if (row < 0 || section < 0) {
            return;
        }
        if ((!this.onlyUsers || inviteViaLink != 0) && section == 0) {
            if (!this.needPhonebook) {
                if (inviteViaLink != 0) {
                    if (row == 0) {
                        int i = this.chatId;
                        if (i == 0) {
                            i = this.channelId;
                        }
                        presentFragment(new GroupInviteActivity(i));
                        return;
                    }
                    return;
                }
                if (row == 0) {
                    presentFragment(new GroupCreateActivity(new Bundle()));
                    return;
                }
                if (row == 1) {
                    Bundle args2 = new Bundle();
                    args2.putBoolean("onlyUsers", true);
                    args2.putBoolean("destroyAfterSelect", true);
                    args2.putBoolean("createSecretChat", true);
                    args2.putBoolean("allowBots", false);
                    presentFragment(new ContactsActivity(args2), false);
                    return;
                }
                if (row == 2) {
                    SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                    if (!BuildVars.DEBUG_VERSION && preferences.getBoolean("channel_intro", false)) {
                        Bundle args3 = new Bundle();
                        args3.putInt("step", 0);
                        presentFragment(new ChannelCreateActivity(args3));
                        return;
                    } else {
                        presentFragment(new ActionIntroActivity(0));
                        preferences.edit().putBoolean("channel_intro", true).commit();
                        return;
                    }
                }
                return;
            }
            return;
        }
        Object item1 = this.listViewAdapter.getItem(section, row);
        if (item1 instanceof TLRPC.User) {
            TLRPC.User user2 = (TLRPC.User) item1;
            if (this.returnAsResult) {
                SparseArray<TLRPC.User> sparseArray2 = this.ignoreUsers;
                if (sparseArray2 != null && sparseArray2.indexOfKey(user2.id) >= 0) {
                    return;
                } else {
                    return;
                }
            }
            if (this.createSecretChat) {
                this.creatingChat = true;
                SecretChatHelper.getInstance(this.currentAccount).startSecretChat(getParentActivity(), user2);
                return;
            }
            Bundle args4 = new Bundle();
            args4.putInt("user_id", user2.id);
            if (MessagesController.getInstance(this.currentAccount).checkCanOpenChat(args4, getCurrentFragment())) {
                presentFragment(new ChatActivity(args4));
                return;
            }
            return;
        }
        if (item1 instanceof ContactsController.Contact) {
            ContactsController.Contact contact = (ContactsController.Contact) item1;
            String usePhone = null;
            if (!contact.phones.isEmpty()) {
                String usePhone2 = contact.phones.get(0);
                usePhone = usePhone2;
            }
            if (usePhone == null || getParentActivity() == null) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setMessage(LocaleController.getString("InviteUser", R.string.InviteUser));
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            final String arg1 = usePhone;
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$ContactsFragment$nHONBapGdJu6n-UP8CN55gLEa5U
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i2) {
                    this.f$0.lambda$null$4$ContactsFragment(arg1, dialogInterface, i2);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showDialog(builder.create());
        }
    }

    public /* synthetic */ void lambda$null$4$ContactsFragment(String arg1, DialogInterface dialogInterface, int i) {
        try {
            Intent intent = new Intent("android.intent.action.VIEW", Uri.fromParts("sms", arg1, null));
            intent.putExtra("sms_body", ContactsController.getInstance(this.currentAccount).getInviteText(1));
            getParentActivity().startActivityForResult(intent, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    protected void lazyLoadData() {
        super.lazyLoadData();
        FmtContactsAdapter fmtContactsAdapter = this.listViewAdapter;
        if (fmtContactsAdapter != null) {
            fmtContactsAdapter.notifyDataSetChanged();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    public void onResumeForBaseFragment() {
        super.onResumeForBaseFragment();
        FmtContactsAdapter fmtContactsAdapter = this.listViewAdapter;
        if (fmtContactsAdapter != null) {
            fmtContactsAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.contactsDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.encryptedChatCreated);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.contactApplyUpdateCount);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.userFullInfoDidLoad);
    }

    @Override // androidx.fragment.app.Fragment, android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
    }

    @Override // androidx.fragment.app.Fragment
    public void onPause() {
        super.onPause();
        closeSearchView(false);
    }

    public void closeSearchView(boolean anim) {
        MrySearchView mrySearchView = this.searchView;
        if (mrySearchView != null && mrySearchView.isSearchFieldVisible()) {
            this.searchView.closeSearchField(anim);
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        RecyclerView.ViewHolder holder;
        FmtContactsAdapter fmtContactsAdapter;
        if (id == NotificationCenter.contactsDidLoad) {
            FmtContactsAdapter fmtContactsAdapter2 = this.listViewAdapter;
            if (fmtContactsAdapter2 != null) {
                fmtContactsAdapter2.notifyDataSetChanged();
            }
            ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
            String[] chars = (String[]) sortedUsersSectionsArray.toArray(new String[sortedUsersSectionsArray.size()]);
            SideBar sideBar = this.sideBar;
            if (sideBar != null) {
                sideBar.setChars(chars);
                return;
            }
            return;
        }
        if (id == NotificationCenter.updateInterfaces) {
            int mask = ((Integer) args[0]).intValue();
            if ((mask & 2) != 0 || (mask & 1) != 0 || (mask & 4) != 0) {
                updateVisibleRows(mask);
            }
            if ((mask & 4) != 0 && !this.sortByName && (fmtContactsAdapter = this.listViewAdapter) != null) {
                fmtContactsAdapter.sortOnlineContacts();
                return;
            }
            return;
        }
        if (id == NotificationCenter.encryptedChatCreated) {
            if (this.createSecretChat && this.creatingChat) {
                TLRPC.EncryptedChat encryptedChat = (TLRPC.EncryptedChat) args[0];
                Bundle args2 = new Bundle();
                args2.putInt("enc_id", encryptedChat.id);
                NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
                presentFragment(new ChatActivity(args2));
                return;
            }
            return;
        }
        if (id == NotificationCenter.contactApplyUpdateCount) {
            FmtContactsAdapter fmtContactsAdapter3 = this.listViewAdapter;
            if (fmtContactsAdapter3 != null) {
                fmtContactsAdapter3.notifyDataSetChanged();
                return;
            }
            return;
        }
        if (id == NotificationCenter.userFullInfoDidLoad && args[0] != null) {
            int userId = ((Integer) args[0]).intValue();
            FmtContactsAdapter fmtContactsAdapter4 = this.listViewAdapter;
            if (fmtContactsAdapter4 != null && (holder = this.listView.findViewHolderForAdapterPosition(fmtContactsAdapter4.getItemPosition(userId))) != null) {
                ContactUserCell userCell = (ContactUserCell) holder.itemView.findViewById(R.attr.contactUserCell);
                userCell.setUserFull((TLRPC.UserFull) args[1]);
            }
        }
    }

    private void updateVisibleRows(int mask) {
        SlidingItemMenuRecyclerView slidingItemMenuRecyclerView = this.listView;
        if (slidingItemMenuRecyclerView != null) {
            int count = slidingItemMenuRecyclerView.getChildCount();
            for (int a = 0; a < count; a++) {
                View child = this.listView.getChildAt(a);
                if (child instanceof UserCell) {
                    ((UserCell) child).update(mask);
                }
            }
        }
    }

    public void setDelegate(FmtContactsDelegate delegate) {
        this.delegate = delegate;
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    public boolean onBackPressed() {
        MrySearchView mrySearchView = this.searchView;
        if (mrySearchView != null && mrySearchView.isSearchFieldVisible()) {
            this.searchView.closeSearchField();
            return true;
        }
        return super.onBackPressed();
    }
}
