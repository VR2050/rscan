package im.uwrkaxlmjj.ui.newcall;

import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.text.TextUtils;
import android.util.SparseArray;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.adapters.SearchAdapter;
import im.uwrkaxlmjj.ui.cells.GraySectionCell;
import im.uwrkaxlmjj.ui.cells.LetterSectionCell;
import im.uwrkaxlmjj.ui.cells.ProfileSearchCell;
import im.uwrkaxlmjj.ui.cells.TextCell;
import im.uwrkaxlmjj.ui.cells.UserCell;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.DialogCommonList;
import im.uwrkaxlmjj.ui.hui.adapter.AddNewCallAdapter;
import im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity;
import im.uwrkaxlmjj.ui.hviews.MryEmptyTextProgressView;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;
import im.uwrkaxlmjj.ui.hviews.sidebar.SideBar;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class AddNewCallActivity extends BaseSearchViewFragment implements NotificationCenter.NotificationCenterDelegate {
    private static final int DONE_BUTTON = 1;
    private static final int search_button = 0;
    private static final int sort_button = 2;
    private boolean allowBots = true;
    private boolean allowUsernameSearch = true;
    private boolean checkPermission = true;
    private boolean creatingChat;
    private ContactsActivityDelegate delegate;
    private MryEmptyTextProgressView emptyView;
    private SparseArray<TLRPC.User> ignoreUsers;
    private boolean isCharClicked;
    private LinearLayoutManager layoutManager;
    private RecyclerListView listView;
    private AddNewCallAdapter listViewAdapter;
    private FrameLayout searchLayout;
    private SearchAdapter searchListViewAdapter;
    private boolean searchWas;
    private boolean searching;
    private SideBar sideBar;
    private boolean sortByName;

    public interface ContactsActivityDelegate {
        void didSelectContact(TLRPC.User user, String str, AddNewCallActivity addNewCallActivity);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.contactsDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.encryptedChatCreated);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.closeChats);
        this.checkPermission = UserConfig.getInstance(this.currentAccount).syncContacts;
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
        this.searchView.setHintText(LocaleController.getString("Search", R.string.Search));
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
        this.fragmentView = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.newcall.AddNewCallActivity.1
            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                if (AddNewCallActivity.this.listView.getAdapter() == AddNewCallActivity.this.listViewAdapter) {
                    if (AddNewCallActivity.this.emptyView.getVisibility() == 0) {
                        AddNewCallActivity.this.emptyView.setTranslationY(AndroidUtilities.dp(74.0f));
                        return;
                    }
                    return;
                }
                AddNewCallActivity.this.emptyView.setTranslationY(AndroidUtilities.dp(0.0f));
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
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setTitle(LocaleController.getString("NewCall", R.string.NewCall));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.newcall.AddNewCallActivity.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    AddNewCallActivity.this.finishFragment();
                }
            }
        });
    }

    private void initList(FrameLayout frameLayout, Context context) {
        MryEmptyTextProgressView mryEmptyTextProgressView = new MryEmptyTextProgressView(context);
        this.emptyView = mryEmptyTextProgressView;
        mryEmptyTextProgressView.setText(LocaleController.getString("NoContacts", R.string.NoContacts));
        this.emptyView.setTopImage(R.id.img_empty_default);
        this.emptyView.showTextView();
        this.emptyView.setShowAtCenter(true);
        this.emptyView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        frameLayout.addView(this.emptyView, LayoutHelper.createFrameSearchWithoutActionBar(-1, -1));
        this.searchListViewAdapter = new SearchAdapter(context, this.ignoreUsers, this.allowUsernameSearch, false, false, this.allowBots, true, 0);
        AddNewCallAdapter addNewCallAdapter = new AddNewCallAdapter(context) { // from class: im.uwrkaxlmjj.ui.newcall.AddNewCallActivity.3
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
            public void notifyDataSetChanged() {
                super.notifyDataSetChanged();
                if (AddNewCallActivity.this.listView != null && AddNewCallActivity.this.listView.getAdapter() == this) {
                    int count = super.getItemCount();
                    AddNewCallActivity.this.emptyView.setVisibility(count == 0 ? 0 : 8);
                }
            }
        };
        this.listViewAdapter = addNewCallAdapter;
        addNewCallAdapter.setDisableSections(true);
        RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.newcall.AddNewCallActivity.4
            @Override // android.view.View
            public void setPadding(int left, int top, int right, int bottom) {
                super.setPadding(left, top, right, bottom);
                if (AddNewCallActivity.this.emptyView != null) {
                    AddNewCallActivity.this.emptyView.setPadding(left, top, right, bottom);
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
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.newcall.-$$Lambda$AddNewCallActivity$rwBpBmycD2d2XyyqpoZyAi4m0Zw
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initList$0$AddNewCallActivity(view, i);
            }
        });
        this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.newcall.AddNewCallActivity.5
            private boolean scrollingManually;

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                AddNewCallActivity.this.isCharClicked = false;
                if (newState == 1) {
                    if (AddNewCallActivity.this.searching && AddNewCallActivity.this.searchWas) {
                        AndroidUtilities.hideKeyboard(AddNewCallActivity.this.getParentActivity().getCurrentFocus());
                    }
                    this.scrollingManually = true;
                    return;
                }
                this.scrollingManually = false;
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                super.onScrolled(recyclerView, dx, dy);
                if (!AddNewCallActivity.this.isCharClicked) {
                    LinearLayoutManager layoutManager = (LinearLayoutManager) recyclerView.getLayoutManager();
                    int firstPosition = layoutManager.findFirstVisibleItemPosition();
                    String s = AddNewCallActivity.this.listViewAdapter.getLetter(firstPosition);
                    if (TextUtils.isEmpty(s) && AddNewCallActivity.this.listViewAdapter.getSectionForPosition(firstPosition) == 0) {
                        s = AddNewCallActivity.this.listViewAdapter.getLetter(AddNewCallActivity.this.listViewAdapter.getPositionForSection(1));
                    }
                    AddNewCallActivity.this.sideBar.setChooseChar(s);
                }
            }
        });
    }

    public /* synthetic */ void lambda$initList$0$AddNewCallActivity(View view, int position) {
        TLRPC.User user;
        if (this.searching && this.searchWas) {
            Object object = this.searchListViewAdapter.getItem(position);
            if (!(object instanceof TLRPC.User) || (user = (TLRPC.User) object) == null) {
                return;
            }
            if (this.searchListViewAdapter.isGlobalSearch(position)) {
                ArrayList<TLRPC.User> users = new ArrayList<>();
                users.add(user);
                MessagesController.getInstance(this.currentAccount).putUsers(users, false);
                MessagesStorage.getInstance(this.currentAccount).putUsersAndChats(users, null, false, true);
            }
            startCall(user);
            return;
        }
        int section = this.listViewAdapter.getSectionForPosition(position);
        int row = this.listViewAdapter.getPositionInSectionForPosition(position);
        if (row < 0 || section < 0) {
            return;
        }
        Object item = this.listViewAdapter.getItem(section, row);
        if (item instanceof TLRPC.User) {
            startCall((TLRPC.User) item);
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
        this.sideBar.setOnTouchingLetterChangedListener(new SideBar.OnTouchingLetterChangedListener() { // from class: im.uwrkaxlmjj.ui.newcall.-$$Lambda$AddNewCallActivity$DdYK1rTv5cAuqHU3KS_oN22TbmE
            @Override // im.uwrkaxlmjj.ui.hviews.sidebar.SideBar.OnTouchingLetterChangedListener
            public final void onTouchingLetterChanged(String str) {
                this.f$0.lambda$initSideBar$1$AddNewCallActivity(str);
            }
        });
    }

    public /* synthetic */ void lambda$initSideBar$1$AddNewCallActivity(String s) {
        if ("↑".equals(s)) {
            this.listView.scrollToPosition(0);
            return;
        }
        if (!"☆".equals(s)) {
            int section = this.listViewAdapter.getSectionForChar(s.charAt(0));
            int position = this.listViewAdapter.getPositionForSection(section);
            if (position != -1) {
                this.listView.getLayoutManager().scrollToPosition(position);
                this.isCharClicked = true;
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        AddNewCallAdapter addNewCallAdapter = this.listViewAdapter;
        if (addNewCallAdapter != null) {
            addNewCallAdapter.notifyDataSetChanged();
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
        AddNewCallAdapter addNewCallAdapter;
        if (id == NotificationCenter.contactsDidLoad) {
            AddNewCallAdapter addNewCallAdapter2 = this.listViewAdapter;
            if (addNewCallAdapter2 != null) {
                addNewCallAdapter2.notifyDataSetChanged();
                return;
            }
            return;
        }
        if (id == NotificationCenter.updateInterfaces) {
            int mask = ((Integer) args[0]).intValue();
            if ((mask & 2) != 0 || (mask & 1) != 0 || (mask & 4) != 0) {
                updateVisibleRows(mask);
            }
            if ((mask & 4) != 0 && !this.sortByName && (addNewCallAdapter = this.listViewAdapter) != null) {
                addNewCallAdapter.sortOnlineContacts();
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

    private void startCall(final TLRPC.User user) {
        List<String> list = new ArrayList<>();
        list.add(LocaleController.getString("menu_voice_chat", R.string.menu_voice_chat));
        list.add(LocaleController.getString("menu_video_chat", R.string.menu_video_chat));
        List<Integer> list1 = new ArrayList<>();
        list1.add(Integer.valueOf(R.drawable.menu_voice_call));
        list1.add(Integer.valueOf(R.drawable.menu_video_call));
        DialogCommonList dialogCommonList = new DialogCommonList(getParentActivity(), list, list1, Color.parseColor("#222222"), new DialogCommonList.RecyclerviewItemClickCallBack() { // from class: im.uwrkaxlmjj.ui.newcall.-$$Lambda$AddNewCallActivity$vNc5VpOrVSAnjU8w3_q8xjKkEsc
            @Override // im.uwrkaxlmjj.ui.dialogs.DialogCommonList.RecyclerviewItemClickCallBack
            public final void onRecyclerviewItemClick(int i) {
                this.f$0.lambda$startCall$2$AddNewCallActivity(user, i);
            }
        }, 1);
        dialogCommonList.show();
    }

    public /* synthetic */ void lambda$startCall$2$AddNewCallActivity(TLRPC.User user, int position) {
        if (position == 0) {
            if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                if (user.mutual_contact) {
                    int currentConnectionState = ConnectionsManager.getInstance(this.currentAccount).getConnectionState();
                    if (currentConnectionState == 2 || currentConnectionState == 1) {
                        ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_network", R.string.visual_call_no_network));
                        return;
                    }
                    Intent intent = new Intent();
                    intent.setClass(getParentActivity(), VisualCallActivity.class);
                    intent.putExtra("CallType", 1);
                    ArrayList<Integer> ArrInputPeers = new ArrayList<>();
                    ArrInputPeers.add(Integer.valueOf(user.id));
                    intent.putExtra("ArrayUser", ArrInputPeers);
                    intent.putExtra("channel", new ArrayList());
                    getParentActivity().startActivity(intent);
                    return;
                }
                ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_friend_tip", R.string.visual_call_no_friend_tip));
                return;
            }
            ToastUtils.show((CharSequence) LocaleController.getString("visual_call_busing_tip", R.string.visual_call_busing_tip));
            return;
        }
        if (position == 1) {
            if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                if (user.mutual_contact) {
                    int currentConnectionState2 = ConnectionsManager.getInstance(this.currentAccount).getConnectionState();
                    if (currentConnectionState2 == 2 || currentConnectionState2 == 1) {
                        ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_network", R.string.visual_call_no_network));
                        return;
                    }
                    Intent intent2 = new Intent();
                    intent2.setClass(getParentActivity(), VisualCallActivity.class);
                    intent2.putExtra("CallType", 2);
                    ArrayList<Integer> ArrInputPeers2 = new ArrayList<>();
                    ArrInputPeers2.add(Integer.valueOf(user.id));
                    intent2.putExtra("ArrayUser", ArrInputPeers2);
                    intent2.putExtra("channel", new ArrayList());
                    getParentActivity().startActivity(intent2);
                    return;
                }
                ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_friend_tip", R.string.visual_call_no_friend_tip));
                return;
            }
            ToastUtils.show((CharSequence) LocaleController.getString("visual_call_busing_tip", R.string.visual_call_busing_tip));
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ThemeDescription.ThemeDescriptionDelegate cellDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.newcall.-$$Lambda$AddNewCallActivity$erDkvBrkCqgYEpqVR_LDdHbdGl0
            @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
            public final void didSetColor() {
                this.f$0.lambda$getThemeDescriptions$3$AddNewCallActivity();
            }
        };
        return new ThemeDescription[]{new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCH, null, null, null, null, Theme.key_actionBarDefaultSearch), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCHPLACEHOLDER, null, null, null, null, Theme.key_actionBarDefaultSearchPlaceholder), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SECTIONS, new Class[]{LetterSectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.emptyView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_emptyListPlaceholder), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollActive), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollInactive), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"nameTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"statusColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteGrayText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"statusOnlineColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteBlueText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, null, new Drawable[]{Theme.avatar_savedDrawable}, null, Theme.key_avatar_text), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundRed), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundOrange), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundViolet), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundGreen), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundCyan), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundBlue), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundPink), new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, new Class[]{TextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, new Class[]{TextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueText2), new ThemeDescription(this.listView, 0, new Class[]{TextCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayIcon), new ThemeDescription(this.listView, 0, new Class[]{GraySectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_graySectionText), new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{GraySectionCell.class}, null, null, null, Theme.key_graySection), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, null, new Drawable[]{Theme.dialogs_groupDrawable, Theme.dialogs_broadcastDrawable, Theme.dialogs_botDrawable}, null, Theme.key_chats_nameIcon), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, null, new Drawable[]{Theme.dialogs_verifiedCheckDrawable}, null, Theme.key_chats_verifiedCheck), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, null, new Drawable[]{Theme.dialogs_verifiedDrawable}, null, Theme.key_chats_verifiedBackground), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, Theme.dialogs_offlinePaint, null, null, Theme.key_windowBackgroundWhiteGrayText3), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, Theme.dialogs_onlinePaint, null, null, Theme.key_windowBackgroundWhiteBlueText3), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, (String[]) null, new Paint[]{Theme.dialogs_namePaint, Theme.dialogs_searchNamePaint}, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_name), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, (String[]) null, new Paint[]{Theme.dialogs_nameEncryptedPaint, Theme.dialogs_searchNameEncryptedPaint}, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_secretName)};
    }

    public /* synthetic */ void lambda$getThemeDescriptions$3$AddNewCallActivity() {
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
            MryEmptyTextProgressView mryEmptyTextProgressView = this.emptyView;
            if (mryEmptyTextProgressView != null) {
                this.listView.setEmptyView(mryEmptyTextProgressView);
                this.emptyView.setText(LocaleController.getString("NoResult", R.string.NoResult));
            }
        }
        this.searchListViewAdapter.searchDialogs(text);
    }
}
