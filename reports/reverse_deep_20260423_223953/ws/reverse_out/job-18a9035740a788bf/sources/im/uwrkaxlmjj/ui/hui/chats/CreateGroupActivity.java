package im.uwrkaxlmjj.ui.hui.chats;

import android.app.Dialog;
import android.content.Context;
import android.content.res.Configuration;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.blankj.utilcode.util.SpanUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.NewContactActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.adapters.SearchAdapter;
import im.uwrkaxlmjj.ui.cells.GraySectionCell;
import im.uwrkaxlmjj.ui.cells.LetterSectionCell;
import im.uwrkaxlmjj.ui.cells.ProfileSearchCell;
import im.uwrkaxlmjj.ui.cells.TextCell;
import im.uwrkaxlmjj.ui.cells.UserCell;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.GroupCreateSpan;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hcells.AvatarDelCell;
import im.uwrkaxlmjj.ui.hcells.UserBoxCell;
import im.uwrkaxlmjj.ui.hui.adapter.CreateGroupAdapter;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;
import im.uwrkaxlmjj.ui.hviews.sidebar.SideBar;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class CreateGroupActivity extends BaseSearchViewFragment implements NotificationCenter.NotificationCenterDelegate {
    private static final int NEXT_BUTTON = 1;
    private boolean allowBots;
    private boolean allowUsernameSearch;
    private boolean askAboutContacts;
    private int chatType;
    private boolean checkPermission;
    private SparseArray<TLRPC.User> checkedMap;
    private boolean creatingChat;
    private ContactsActivityDelegate delegate;
    private boolean disableSections;
    private EmptyTextProgressView emptyView;
    private boolean floatingHidden;
    private CreateGroupHeaderAdapter headerAdapter;
    private FrameLayout headerLayout;
    private RecyclerListView headerListView;
    private SparseArray<TLRPC.User> ignoreUsers;
    private boolean isCharClicked;
    private LinearLayoutManager layoutManager;
    private RecyclerListView listView;
    private CreateGroupAdapter listViewAdapter;
    private int maxCount;
    private boolean needFinishFragment;
    private boolean needForwardCount;
    private boolean needPhonebook;
    private MryTextView nextTextView;
    private AlertDialog permissionDialog;
    private int prevPosition;
    private int prevTop;
    private boolean resetDelegate;
    private boolean scrollUpdated;
    private FrameLayout searchLayout;
    private SearchAdapter searchListViewAdapter;
    private boolean searchWas;
    private boolean searching;
    private String selectAlertString;
    private SparseArray<GroupCreateSpan> selectedContacts;
    private SideBar sideBar;
    private boolean sortByName;
    private MryTextView textInfoCell;

    public interface ContactsActivityDelegate {
        void didSelectContact(TLRPC.User user, String str, CreateGroupActivity createGroupActivity);
    }

    public CreateGroupActivity(Bundle args) {
        super(args);
        this.allowBots = true;
        this.needForwardCount = true;
        this.needFinishFragment = true;
        this.resetDelegate = true;
        this.selectAlertString = null;
        this.allowUsernameSearch = true;
        this.askAboutContacts = true;
        this.checkPermission = true;
        this.checkedMap = new SparseArray<>();
        this.chatType = 4;
        this.selectedContacts = new SparseArray<>();
        this.maxCount = MessagesController.getInstance(this.currentAccount).maxMegagroupCount;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.contactsDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.encryptedChatCreated);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.closeChats);
        this.checkPermission = UserConfig.getInstance(this.currentAccount).syncContacts;
        this.needPhonebook = true;
        ContactsController.getInstance(this.currentAccount).checkInviteText();
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.contactsDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.encryptedChatCreated);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.closeChats);
        this.delegate = null;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.searching = false;
        this.searchWas = false;
        initActionBar();
        this.fragmentView = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.hui.chats.CreateGroupActivity.1
            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                if (CreateGroupActivity.this.listView.getAdapter() == CreateGroupActivity.this.listViewAdapter) {
                    if (CreateGroupActivity.this.emptyView.getVisibility() == 0) {
                        CreateGroupActivity.this.emptyView.setTranslationY(AndroidUtilities.dp(74.0f));
                        return;
                    }
                    return;
                }
                CreateGroupActivity.this.emptyView.setTranslationY(AndroidUtilities.dp(0.0f));
            }
        };
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        super.createView(context);
        initHeaderView(frameLayout, context);
        initList(frameLayout, context);
        initSideBar(frameLayout, context);
        updateHint();
        return this.fragmentView;
    }

    protected RecyclerListView getListView() {
        return this.listView;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment
    public MrySearchView getSearchView() {
        FrameLayout frameLayout = new FrameLayout(getParentActivity());
        this.searchLayout = frameLayout;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        ((FrameLayout) this.fragmentView).addView(this.searchLayout, LayoutHelper.createFrame(-1, 55.0f));
        this.searchView = new MrySearchView(getParentActivity());
        this.searchView.setHintText(LocaleController.getString("SearchForPeopleAndGroups", R.string.SearchForPeopleAndGroups));
        this.searchLayout.addView(this.searchView, LayoutHelper.createFrame(-1.0f, 35.0f, 17, 10.0f, 10.0f, 10.0f, 10.0f));
        return this.searchView;
    }

    private void initActionBar() {
        this.actionBar.setAllowOverlayTitle(false);
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitle(LocaleController.getString("NewGroup", R.string.NewGroup));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.chats.CreateGroupActivity.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == 1) {
                    CreateGroupActivity.this.onNextPressed();
                }
            }
        });
        this.actionBar.setBackTitle(LocaleController.getString("Cancel", R.string.Cancel));
        this.actionBar.getBackTitleTextView().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$CreateGroupActivity$99Zze6l-GejbaxZpknut8u320bg
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initActionBar$0$CreateGroupActivity(view);
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        MryTextView mryTextView = new MryTextView(getParentActivity());
        this.nextTextView = mryTextView;
        mryTextView.setText(LocaleController.getString("Next", R.string.Next));
        this.nextTextView.setTextSize(1, 14.0f);
        this.nextTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.nextTextView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultTitle));
        this.nextTextView.setGravity(16);
        menu.addItemView(1, this.nextTextView);
    }

    public /* synthetic */ void lambda$initActionBar$0$CreateGroupActivity(View v) {
        finishFragment();
    }

    private void initHeaderView(FrameLayout frameLayout, Context context) {
        FrameLayout frameLayout2 = new FrameLayout(context);
        this.headerLayout = frameLayout2;
        frameLayout2.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
        frameLayout.addView(this.headerLayout, LayoutHelper.createFrame(-1, 65, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(55.0f), AndroidUtilities.dp(10.0f), 0));
        MryTextView mryTextViewCreateTextInfoCell = createTextInfoCell(context);
        this.textInfoCell = mryTextViewCreateTextInfoCell;
        this.headerLayout.addView(mryTextViewCreateTextInfoCell, LayoutHelper.createFrame(-1, -1.0f));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.headerListView = recyclerListView;
        recyclerListView.setLayoutManager(new LinearLayoutManager(context, 0, false));
        this.headerListView.setHorizontalScrollBarEnabled(false);
        RecyclerListView recyclerListView2 = this.headerListView;
        CreateGroupHeaderAdapter createGroupHeaderAdapter = new CreateGroupHeaderAdapter();
        this.headerAdapter = createGroupHeaderAdapter;
        recyclerListView2.setAdapter(createGroupHeaderAdapter);
        this.headerLayout.addView(this.headerListView, LayoutHelper.createFrame(-1, -1.0f));
    }

    private void initList(FrameLayout frameLayout, Context context) {
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
        this.emptyView = emptyTextProgressView;
        emptyTextProgressView.setShowAtCenter(true);
        this.emptyView.setText(LocaleController.getString("NoContacts", R.string.NoContacts));
        this.emptyView.showTextView();
        frameLayout.addView(this.emptyView, LayoutHelper.createFrameSearchWithoutActionBar(-1, -1));
        this.searchListViewAdapter = new SearchAdapter(context, this.ignoreUsers, this.allowUsernameSearch, false, false, this.allowBots, true, 0) { // from class: im.uwrkaxlmjj.ui.hui.chats.CreateGroupActivity.3
            @Override // androidx.recyclerview.widget.RecyclerView.Adapter
            public void notifyDataSetChanged() {
                super.notifyDataSetChanged();
                if (CreateGroupActivity.this.listView != null && CreateGroupActivity.this.listView.getAdapter() == this) {
                    int count = super.getItemCount();
                    CreateGroupActivity.this.headerLayout.setVisibility(count == 0 ? 8 : 0);
                }
            }
        };
        CreateGroupAdapter createGroupAdapter = new CreateGroupAdapter(context) { // from class: im.uwrkaxlmjj.ui.hui.chats.CreateGroupActivity.4
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
            public void notifyDataSetChanged() {
                super.notifyDataSetChanged();
                if (CreateGroupActivity.this.listView != null && CreateGroupActivity.this.listView.getAdapter() == this) {
                    int count = super.getItemCount();
                    CreateGroupActivity.this.emptyView.setVisibility(count == 0 ? 0 : 8);
                    CreateGroupActivity.this.headerLayout.setVisibility(count == 0 ? 8 : 0);
                }
            }
        };
        this.listViewAdapter = createGroupAdapter;
        createGroupAdapter.setDisableSections(true);
        RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.hui.chats.CreateGroupActivity.5
            @Override // android.view.View
            public void setPadding(int left, int top, int right, int bottom) {
                super.setPadding(left, top, right, bottom);
                if (CreateGroupActivity.this.emptyView != null) {
                    CreateGroupActivity.this.emptyView.setPadding(left, top, right, bottom);
                }
            }
        };
        this.listView = recyclerListView;
        recyclerListView.setVerticalScrollBarEnabled(false);
        RecyclerListView recyclerListView2 = this.listView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, false);
        this.layoutManager = linearLayoutManager;
        recyclerListView2.setLayoutManager(linearLayoutManager);
        this.listView.setAdapter(this.listViewAdapter);
        this.listView.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -2, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(130.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f)));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$CreateGroupActivity$NXfCbry0tY99GT9pT6MU15nXRmE
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initList$1$CreateGroupActivity(view, i);
            }
        });
        this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.CreateGroupActivity.6
            private boolean scrollingManually;

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                CreateGroupActivity.this.isCharClicked = false;
                if (newState == 1) {
                    if (CreateGroupActivity.this.searching && CreateGroupActivity.this.searchWas) {
                        AndroidUtilities.hideKeyboard(CreateGroupActivity.this.getParentActivity().getCurrentFocus());
                    }
                    this.scrollingManually = true;
                    return;
                }
                this.scrollingManually = false;
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                super.onScrolled(recyclerView, dx, dy);
                if (!CreateGroupActivity.this.isCharClicked) {
                    LinearLayoutManager layoutManager = (LinearLayoutManager) recyclerView.getLayoutManager();
                    int firstPosition = layoutManager.findFirstVisibleItemPosition();
                    String s = CreateGroupActivity.this.listViewAdapter.getLetter(firstPosition);
                    CreateGroupActivity.this.sideBar.setChooseChar(s);
                }
            }
        });
    }

    public /* synthetic */ void lambda$initList$1$CreateGroupActivity(View view, int position) {
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
                if (user.bot) {
                    if (user.bot_nochats) {
                        ToastUtils.show(R.string.BotCantJoinGroups);
                        return;
                    }
                } else {
                    if (this.checkedMap.indexOfKey(user.id) >= 0) {
                        this.checkedMap.remove(user.id);
                    } else {
                        this.checkedMap.put(user.id, user);
                    }
                    this.listViewAdapter.setCheckedMap(this.checkedMap);
                    this.listViewAdapter.notifyDataSetChanged();
                    this.headerAdapter.notifyDataSetChanged();
                }
            } else if (object instanceof String) {
                String str = (String) object;
                if (!str.equals("section")) {
                    NewContactActivity activity = new NewContactActivity();
                    activity.setInitialPhoneNumber(str);
                    presentFragment(activity);
                }
            }
        } else {
            int section = this.listViewAdapter.getSectionForPosition(position);
            int row = this.listViewAdapter.getPositionInSectionForPosition(position);
            if (row < 0 || section < 0) {
                return;
            }
            Object item1 = this.listViewAdapter.getItem(section, row);
            if (item1 instanceof TLRPC.User) {
                TLRPC.User user2 = (TLRPC.User) item1;
                if (user2.bot) {
                    if (user2.bot_nochats) {
                        ToastUtils.show(R.string.BotCantJoinGroups);
                        return;
                    }
                } else {
                    if (this.checkedMap.indexOfKey(user2.id) >= 0) {
                        this.checkedMap.remove(user2.id);
                        View childAt = this.layoutManager.findViewByPosition(position);
                        if (childAt instanceof UserBoxCell) {
                            UserBoxCell cell = (UserBoxCell) childAt;
                            cell.setChecked(false, true);
                        }
                    } else {
                        this.checkedMap.put(user2.id, user2);
                        View childAt2 = this.layoutManager.findViewByPosition(position);
                        if (childAt2 instanceof UserBoxCell) {
                            UserBoxCell cell2 = (UserBoxCell) childAt2;
                            cell2.setChecked(true, true);
                        }
                    }
                    this.listViewAdapter.setCheckedMap(this.checkedMap);
                    this.headerAdapter.notifyDataSetChanged();
                }
            }
        }
        updateHint();
        if (this.searchView != null && this.searchView.isSearchFieldVisible()) {
            this.searchView.closeSearchField();
        }
    }

    private MryTextView createTextInfoCell(Context context) {
        MryTextView textView = new MryTextView(context);
        textView.setTextSize(1, 14.0f);
        textView.setTextColor(Theme.getColor(Theme.key_graySectionText));
        textView.setGravity(17);
        textView.setText(LocaleController.getString("SelectOneOrMoreContacts", R.string.SelectOneOrMoreContacts));
        return textView;
    }

    private void initSideBar(FrameLayout frameLayout, Context context) {
        TextView textView = new TextView(context);
        textView.setTextSize(AndroidUtilities.dp(18.0f));
        textView.setGravity(17);
        textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        textView.setVisibility(8);
        frameLayout.addView(textView, LayoutHelper.createFrame(AndroidUtilities.dp(25.0f), AndroidUtilities.dp(25.0f), 17));
        SideBar sideBar = new SideBar(context);
        this.sideBar = sideBar;
        sideBar.setTextView(textView);
        frameLayout.addView(this.sideBar, LayoutHelper.createFrame(35.0f, -1.0f, 21, 0.0f, 45.0f, 0.0f, 45.0f));
        this.sideBar.setOnTouchingLetterChangedListener(new SideBar.OnTouchingLetterChangedListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.CreateGroupActivity.7
            @Override // im.uwrkaxlmjj.ui.hviews.sidebar.SideBar.OnTouchingLetterChangedListener
            public void onTouchingLetterChanged(String s) {
                if ("↑".equals(s)) {
                    CreateGroupActivity.this.listView.scrollToPosition(0);
                    return;
                }
                if ("☆".equals(s)) {
                    CreateGroupActivity.this.listView.scrollToPosition(0);
                    return;
                }
                int section = CreateGroupActivity.this.listViewAdapter.getSectionForChar(s.charAt(0));
                int position = CreateGroupActivity.this.listViewAdapter.getPositionForSection(section);
                if (position != -1) {
                    CreateGroupActivity.this.listView.getLayoutManager().scrollToPosition(position);
                    CreateGroupActivity.this.isCharClicked = true;
                }
            }
        });
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        CreateGroupAdapter createGroupAdapter = this.listViewAdapter;
        if (createGroupAdapter != null) {
            createGroupAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        if (this.searchView != null && this.searchView.isSearchFieldVisible()) {
            this.searchView.closeSearchField();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onNextPressed() {
        if (this.checkedMap.size() > 0) {
            ArrayList<Integer> result = new ArrayList<>();
            for (int a = 0; a < this.checkedMap.size(); a++) {
                result.add(Integer.valueOf(this.checkedMap.keyAt(a)));
            }
            Bundle args = new Bundle();
            args.putIntegerArrayList("result", result);
            args.putInt("chatType", this.chatType);
            presentFragment(new CreateGroupFinalActivity(args));
            return;
        }
        ToastUtils.show(R.string.YouMustChooseMoreThanOneUser);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateHint() {
        if (this.checkedMap.size() != 0) {
            this.actionBar.setSubtitle(new SpanUtils().append(String.valueOf(this.checkedMap.size())).setForegroundColor(-16711808).append("/").append(String.valueOf(this.maxCount)).create());
        } else {
            this.actionBar.setSubtitle(null);
        }
        this.nextTextView.setEnabled(this.checkedMap.size() != 0);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onDialogDismiss(Dialog dialog) {
        super.onDialogDismiss(dialog);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        CreateGroupAdapter createGroupAdapter;
        if (id == NotificationCenter.contactsDidLoad) {
            CreateGroupAdapter createGroupAdapter2 = this.listViewAdapter;
            if (createGroupAdapter2 != null) {
                createGroupAdapter2.notifyDataSetChanged();
                return;
            }
            return;
        }
        if (id == NotificationCenter.updateInterfaces) {
            int mask = ((Integer) args[0]).intValue();
            if ((mask & 2) != 0 || (mask & 1) != 0 || (mask & 4) != 0) {
                updateVisibleRows(mask);
            }
            if ((mask & 4) != 0 && !this.sortByName && (createGroupAdapter = this.listViewAdapter) != null) {
                createGroupAdapter.sortOnlineContacts();
                return;
            }
            return;
        }
        if (id != NotificationCenter.encryptedChatCreated && id == NotificationCenter.closeChats && !this.creatingChat) {
            removeSelfFromStack();
        }
    }

    private void updateVisibleRows(int mask) {
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            int count = recyclerListView.getChildCount();
            for (int a = 0; a < count; a++) {
                View child = this.listView.getChildAt(a);
                if (child instanceof UserCell) {
                    ((UserCell) child).update(mask);
                }
            }
        }
    }

    public void setDelegate(ContactsActivityDelegate delegate) {
        this.delegate = delegate;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onSearchExpand() {
        this.searching = true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public boolean canCollapseSearch() {
        this.searchListViewAdapter.searchDialogs(null);
        this.searching = false;
        this.searchWas = false;
        this.listView.setAdapter(this.listViewAdapter);
        this.listViewAdapter.notifyDataSetChanged();
        this.listView.setVerticalScrollBarEnabled(false);
        this.listView.setEmptyView(null);
        this.emptyView.setText(LocaleController.getString("NoContacts", R.string.NoContacts));
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onSearchCollapse() {
        this.searching = false;
        this.searchWas = false;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onTextChange(String text) {
        if (this.searchListViewAdapter == null) {
            return;
        }
        if (text.length() != 0) {
            this.searchWas = true;
            RecyclerListView recyclerListView = this.listView;
            if (recyclerListView != null) {
                recyclerListView.setAdapter(this.searchListViewAdapter);
                this.searchListViewAdapter.notifyDataSetChanged();
                this.listView.setVerticalScrollBarEnabled(false);
            }
            EmptyTextProgressView emptyTextProgressView = this.emptyView;
            if (emptyTextProgressView != null) {
                this.listView.setEmptyView(emptyTextProgressView);
                this.emptyView.setText(LocaleController.getString("NoResult", R.string.NoResult));
            }
        }
        this.searchListViewAdapter.searchDialogs(text);
    }

    /* JADX INFO: Access modifiers changed from: private */
    class CreateGroupHeaderAdapter extends RecyclerListView.SelectionAdapter {
        private CreateGroupHeaderAdapter() {
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            AvatarDelCell cell = new AvatarDelCell(CreateGroupActivity.this.getParentActivity());
            cell.setLayoutParams(new RecyclerView.LayoutParams(AndroidUtilities.dp(65.0f), AndroidUtilities.dp(65.0f)));
            return new RecyclerListView.Holder(cell);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            AvatarDelCell cell = (AvatarDelCell) holder.itemView;
            final TLRPC.User user = (TLRPC.User) CreateGroupActivity.this.checkedMap.valueAt(position);
            cell.setUser(user);
            cell.setDelegate(new AvatarDelCell.AvatarDelDelegate() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$CreateGroupActivity$CreateGroupHeaderAdapter$RLGoVkwgDwcdNCgcJOFMPOLV1VI
                @Override // im.uwrkaxlmjj.ui.hcells.AvatarDelCell.AvatarDelDelegate
                public final void onClickDelete() {
                    this.f$0.lambda$onBindViewHolder$0$CreateGroupActivity$CreateGroupHeaderAdapter(user);
                }
            });
        }

        public /* synthetic */ void lambda$onBindViewHolder$0$CreateGroupActivity$CreateGroupHeaderAdapter(TLRPC.User user) {
            CreateGroupActivity.this.checkedMap.remove(user.id);
            notifyDataSetChanged();
            CreateGroupActivity.this.listViewAdapter.setCheckedMap(CreateGroupActivity.this.checkedMap);
            CreateGroupActivity.this.listViewAdapter.notifyDataSetChanged();
            CreateGroupActivity.this.updateHint();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return CreateGroupActivity.this.checkedMap.size();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            super.notifyDataSetChanged();
            if (CreateGroupActivity.this.headerListView != null && CreateGroupActivity.this.headerListView.getAdapter() == this) {
                int count = getItemCount();
                CreateGroupActivity.this.headerListView.setVisibility(count == 0 ? 8 : 0);
                CreateGroupActivity.this.textInfoCell.setVisibility(count == 0 ? 0 : 8);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ThemeDescription.ThemeDescriptionDelegate cellDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$CreateGroupActivity$yORQCarOglmz4c7amCuFXTz4ZzQ
            @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
            public final void didSetColor() {
                this.f$0.lambda$getThemeDescriptions$2$CreateGroupActivity();
            }
        };
        return new ThemeDescription[]{new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCH, null, null, null, null, Theme.key_actionBarDefaultSearch), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCHPLACEHOLDER, null, null, null, null, Theme.key_actionBarDefaultSearchPlaceholder), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SECTIONS, new Class[]{LetterSectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.emptyView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_emptyListPlaceholder), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollActive), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollInactive), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"nameTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"statusColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteGrayText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"statusOnlineColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteBlueText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, null, new Drawable[]{Theme.avatar_savedDrawable}, null, Theme.key_avatar_text), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundRed), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundOrange), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundViolet), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundGreen), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundCyan), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundBlue), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundPink), new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, new Class[]{TextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, new Class[]{TextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueText2), new ThemeDescription(this.listView, 0, new Class[]{TextCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayIcon), new ThemeDescription(this.listView, 0, new Class[]{GraySectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_graySectionText), new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{GraySectionCell.class}, null, null, null, Theme.key_graySection), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, null, new Drawable[]{Theme.dialogs_groupDrawable, Theme.dialogs_broadcastDrawable, Theme.dialogs_botDrawable}, null, Theme.key_chats_nameIcon), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, null, new Drawable[]{Theme.dialogs_verifiedCheckDrawable}, null, Theme.key_chats_verifiedCheck), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, null, new Drawable[]{Theme.dialogs_verifiedDrawable}, null, Theme.key_chats_verifiedBackground), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, Theme.dialogs_offlinePaint, null, null, Theme.key_windowBackgroundWhiteGrayText3), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, Theme.dialogs_onlinePaint, null, null, Theme.key_windowBackgroundWhiteBlueText3), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, (String[]) null, new Paint[]{Theme.dialogs_namePaint, Theme.dialogs_searchNamePaint}, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_name), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, (String[]) null, new Paint[]{Theme.dialogs_nameEncryptedPaint, Theme.dialogs_searchNameEncryptedPaint}, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_secretName)};
    }

    public /* synthetic */ void lambda$getThemeDescriptions$2$CreateGroupActivity() {
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            int count = recyclerListView.getChildCount();
            for (int a = 0; a < count; a++) {
                View child = this.listView.getChildAt(a);
                if (child instanceof UserCell) {
                    ((UserCell) child).update(0);
                } else if (child instanceof ProfileSearchCell) {
                    ((ProfileSearchCell) child).update(0);
                }
            }
        }
    }
}
