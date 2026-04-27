package im.uwrkaxlmjj.ui.hui.chats;

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.res.Configuration;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.SparseArray;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChatActivity;
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
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hui.adapter.StartChatAdapter;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;
import im.uwrkaxlmjj.ui.hviews.sidebar.SideBar;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class StartChatActivity extends BaseSearchViewFragment implements NotificationCenter.NotificationCenterDelegate {
    private static final int DONE_BUTTON = 1;
    private static final int search_button = 0;
    private static final int sort_button = 2;
    private boolean allowBots;
    private boolean allowUsernameSearch;
    private boolean askAboutContacts;
    private boolean checkPermission;
    private boolean creatingChat;
    private ContactsActivityDelegate delegate;
    private boolean disableSections;
    private EmptyTextProgressView emptyView;
    private boolean floatingHidden;
    private SparseArray<TLRPC.User> ignoreUsers;
    private boolean isCharClicked;
    private LinearLayoutManager layoutManager;
    private RecyclerListView listView;
    private StartChatAdapter listViewAdapter;
    private boolean needFinishFragment;
    private boolean needForwardCount;
    private boolean needPhonebook;
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
    private SideBar sideBar;
    private boolean sortByName;

    public interface ContactsActivityDelegate {
        void didSelectContact(TLRPC.User user, String str, StartChatActivity startChatActivity);
    }

    public StartChatActivity(Bundle args) {
        super(args);
        this.allowBots = true;
        this.needForwardCount = true;
        this.needFinishFragment = true;
        this.resetDelegate = true;
        this.selectAlertString = null;
        this.allowUsernameSearch = true;
        this.askAboutContacts = true;
        this.checkPermission = true;
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

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment
    protected MrySearchView getSearchView() {
        FrameLayout frameLayout = new FrameLayout(getParentActivity());
        this.searchLayout = frameLayout;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        ((FrameLayout) this.fragmentView).addView(this.searchLayout, LayoutHelper.createFrame(-1, 55.0f));
        this.searchView = new MrySearchView(getParentActivity());
        this.searchView.setHintText(LocaleController.getString("SearchForPeopleAndGroups", R.string.SearchForPeopleAndGroups));
        this.searchLayout.addView(this.searchView, LayoutHelper.createFrame(-1.0f, 35.0f, 17, 10.0f, 10.0f, 10.0f, 10.0f));
        return this.searchView;
    }

    protected RecyclerListView getListView() {
        return this.listView;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.searching = false;
        this.searchWas = false;
        this.fragmentView = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.hui.chats.StartChatActivity.1
            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                if (StartChatActivity.this.listView.getAdapter() == StartChatActivity.this.listViewAdapter) {
                    if (StartChatActivity.this.emptyView.getVisibility() == 0) {
                        StartChatActivity.this.emptyView.setTranslationY(AndroidUtilities.dp(74.0f));
                        return;
                    }
                    return;
                }
                StartChatActivity.this.emptyView.setTranslationY(AndroidUtilities.dp(0.0f));
            }
        };
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        initActionBar();
        super.createView(context);
        initList(frameLayout, context);
        initSideBar(frameLayout, context);
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setAllowOverlayTitle(false);
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitle(LocaleController.getString("StartChats", R.string.StartChats));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.chats.StartChatActivity.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == 1) {
                    StartChatActivity.this.finishFragment();
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        menu.addRightItemView(1, LocaleController.getString("Cancel", R.string.Cancel));
    }

    private void initList(FrameLayout frameLayout, Context context) {
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
        this.emptyView = emptyTextProgressView;
        emptyTextProgressView.setShowAtCenter(true);
        this.emptyView.setText(LocaleController.getString("NoContacts", R.string.NoContacts));
        this.emptyView.showTextView();
        frameLayout.addView(this.emptyView, LayoutHelper.createFrameSearchWithoutActionBar(-1, -1));
        this.searchListViewAdapter = new SearchAdapter(context, this.ignoreUsers, this.allowUsernameSearch, false, false, this.allowBots, true, 0);
        StartChatAdapter startChatAdapter = new StartChatAdapter(context) { // from class: im.uwrkaxlmjj.ui.hui.chats.StartChatActivity.3
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
            public void notifyDataSetChanged() {
                super.notifyDataSetChanged();
                if (StartChatActivity.this.listView != null && StartChatActivity.this.listView.getAdapter() == this) {
                    int count = super.getItemCount();
                    if (StartChatActivity.this.needPhonebook) {
                        StartChatActivity.this.emptyView.setVisibility(count != 2 ? 8 : 0);
                    } else {
                        StartChatActivity.this.emptyView.setVisibility(count != 0 ? 8 : 0);
                    }
                }
            }
        };
        this.listViewAdapter = startChatAdapter;
        startChatAdapter.setDisableSections(true);
        RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.hui.chats.StartChatActivity.4
            @Override // android.view.View
            public void setPadding(int left, int top, int right, int bottom) {
                super.setPadding(left, top, right, bottom);
                if (StartChatActivity.this.emptyView != null) {
                    StartChatActivity.this.emptyView.setPadding(left, top, right, bottom);
                }
            }
        };
        this.listView = recyclerListView;
        recyclerListView.setHasFixedSize(true);
        this.listView.setNestedScrollingEnabled(false);
        this.listView.setVerticalScrollBarEnabled(false);
        RecyclerListView recyclerListView2 = this.listView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, false);
        this.layoutManager = linearLayoutManager;
        recyclerListView2.setLayoutManager(linearLayoutManager);
        this.listView.setAdapter(this.listViewAdapter);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -2, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(55.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f)));
        this.listView.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$StartChatActivity$JEj0sAGU5HwUs__x-HbiLbmxBg0
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initList$1$StartChatActivity(view, i);
            }
        });
        this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.StartChatActivity.5
            private boolean scrollingManually;

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                StartChatActivity.this.isCharClicked = false;
                if (newState == 1) {
                    if (StartChatActivity.this.searching && StartChatActivity.this.searchWas) {
                        AndroidUtilities.hideKeyboard(StartChatActivity.this.getParentActivity().getCurrentFocus());
                    }
                    this.scrollingManually = true;
                    return;
                }
                this.scrollingManually = false;
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                super.onScrolled(recyclerView, dx, dy);
                if (!StartChatActivity.this.isCharClicked) {
                    LinearLayoutManager layoutManager = (LinearLayoutManager) recyclerView.getLayoutManager();
                    int firstPosition = layoutManager.findFirstVisibleItemPosition();
                    String s = StartChatActivity.this.listViewAdapter.getLetter(firstPosition);
                    if (TextUtils.isEmpty(s) && StartChatActivity.this.listViewAdapter.getSectionForPosition(firstPosition) == 0) {
                        s = StartChatActivity.this.listViewAdapter.getLetter(StartChatActivity.this.listViewAdapter.getPositionForSection(1));
                    }
                    StartChatActivity.this.sideBar.setChooseChar(s);
                }
            }
        });
    }

    public /* synthetic */ void lambda$initList$1$StartChatActivity(View view, int position) {
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
                Bundle args = new Bundle();
                args.putInt("user_id", user.id);
                if (MessagesController.getInstance(this.currentAccount).checkCanOpenChat(args, this)) {
                    presentFragment(new ChatActivity(args), true);
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
        if (section == 0) {
            if (this.needPhonebook && row == 0) {
                presentFragment(new CreateSecureActivity(new Bundle()), false);
                return;
            }
            return;
        }
        Object item1 = this.listViewAdapter.getItem(section, row);
        if (item1 instanceof TLRPC.User) {
            Bundle args2 = new Bundle();
            args2.putInt("user_id", ((TLRPC.User) item1).id);
            if (MessagesController.getInstance(this.currentAccount).checkCanOpenChat(args2, this)) {
                presentFragment(new ChatActivity(args2), true);
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
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$StartChatActivity$elVgSGGXwv0GXSumXO68YYlR85Y
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$0$StartChatActivity(arg1, dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showDialog(builder.create());
        }
    }

    public /* synthetic */ void lambda$null$0$StartChatActivity(String arg1, DialogInterface dialogInterface, int i) {
        try {
            Intent intent = new Intent("android.intent.action.VIEW", Uri.fromParts("sms", arg1, null));
            intent.putExtra("sms_body", ContactsController.getInstance(this.currentAccount).getInviteText(1));
            getParentActivity().startActivityForResult(intent, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private void initSideBar(FrameLayout frameLayout, Context context) {
        TextView textView = new TextView(context);
        textView.setTextSize(50.0f);
        textView.setGravity(17);
        textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        frameLayout.addView(textView, LayoutHelper.createFrame(100, 100, 17));
        SideBar sideBar = new SideBar(context);
        this.sideBar = sideBar;
        sideBar.setTextView(textView);
        frameLayout.addView(this.sideBar, LayoutHelper.createFrame(35.0f, -1.0f, 21, 0.0f, 45.0f, 0.0f, 45.0f));
        this.sideBar.setOnTouchingLetterChangedListener(new SideBar.OnTouchingLetterChangedListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.StartChatActivity.6
            @Override // im.uwrkaxlmjj.ui.hviews.sidebar.SideBar.OnTouchingLetterChangedListener
            public void onTouchingLetterChanged(String s) {
                if ("↑".equals(s)) {
                    StartChatActivity.this.listView.scrollToPosition(0);
                    return;
                }
                if (!"☆".equals(s)) {
                    int section = StartChatActivity.this.listViewAdapter.getSectionForChar(s.charAt(0));
                    int position = StartChatActivity.this.listViewAdapter.getPositionForSection(section);
                    if (position != -1) {
                        StartChatActivity.this.listView.getLayoutManager().scrollToPosition(position);
                        StartChatActivity.this.isCharClicked = true;
                    }
                }
            }
        });
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        StartChatAdapter startChatAdapter = this.listViewAdapter;
        if (startChatAdapter != null) {
            startChatAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        if (this.searchView != null && this.searchView.isSearchFieldVisible()) {
            this.searchView.closeSearchField();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        StartChatAdapter startChatAdapter;
        if (id == NotificationCenter.contactsDidLoad) {
            StartChatAdapter startChatAdapter2 = this.listViewAdapter;
            if (startChatAdapter2 != null) {
                startChatAdapter2.notifyDataSetChanged();
                return;
            }
            return;
        }
        if (id == NotificationCenter.updateInterfaces) {
            int mask = ((Integer) args[0]).intValue();
            if ((mask & 2) != 0 || (mask & 1) != 0 || (mask & 4) != 0) {
                updateVisibleRows(mask);
            }
            if ((mask & 4) != 0 && !this.sortByName && (startChatAdapter = this.listViewAdapter) != null) {
                startChatAdapter.sortOnlineContacts();
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

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ThemeDescription.ThemeDescriptionDelegate cellDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$StartChatActivity$J93RP1KZ5cmYG6GKGpCHPfrpC4c
            @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
            public final void didSetColor() {
                this.f$0.lambda$getThemeDescriptions$2$StartChatActivity();
            }
        };
        return new ThemeDescription[]{new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCH, null, null, null, null, Theme.key_actionBarDefaultSearch), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCHPLACEHOLDER, null, null, null, null, Theme.key_actionBarDefaultSearchPlaceholder), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SECTIONS, new Class[]{LetterSectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.emptyView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_emptyListPlaceholder), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollActive), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollInactive), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"nameTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"statusColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteGrayText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"statusOnlineColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteBlueText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, null, new Drawable[]{Theme.avatar_savedDrawable}, null, Theme.key_avatar_text), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundRed), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundOrange), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundViolet), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundGreen), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundCyan), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundBlue), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundPink), new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, new Class[]{TextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, new Class[]{TextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueText2), new ThemeDescription(this.listView, 0, new Class[]{TextCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayIcon), new ThemeDescription(this.listView, 0, new Class[]{GraySectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_graySectionText), new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{GraySectionCell.class}, null, null, null, Theme.key_graySection), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, null, new Drawable[]{Theme.dialogs_groupDrawable, Theme.dialogs_broadcastDrawable, Theme.dialogs_botDrawable}, null, Theme.key_chats_nameIcon), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, null, new Drawable[]{Theme.dialogs_verifiedCheckDrawable}, null, Theme.key_chats_verifiedCheck), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, null, new Drawable[]{Theme.dialogs_verifiedDrawable}, null, Theme.key_chats_verifiedBackground), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, Theme.dialogs_offlinePaint, null, null, Theme.key_windowBackgroundWhiteGrayText3), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, Theme.dialogs_onlinePaint, null, null, Theme.key_windowBackgroundWhiteBlueText3), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, (String[]) null, new Paint[]{Theme.dialogs_namePaint, Theme.dialogs_searchNamePaint}, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_name), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, (String[]) null, new Paint[]{Theme.dialogs_nameEncryptedPaint, Theme.dialogs_searchNameEncryptedPaint}, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_secretName)};
    }

    public /* synthetic */ void lambda$getThemeDescriptions$2$StartChatActivity() {
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
}
