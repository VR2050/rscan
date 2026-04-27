package im.uwrkaxlmjj.ui.hui.packet;

import android.content.Context;
import android.graphics.Color;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.core.view.GravityCompat;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.DispatchQueue;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper;
import im.uwrkaxlmjj.ui.cells.GraySectionCell;
import im.uwrkaxlmjj.ui.cells.LetterSectionCell;
import im.uwrkaxlmjj.ui.cells.ManageChatUserCell;
import im.uwrkaxlmjj.ui.cells.UserCell;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.decoration.StickyDecoration;
import im.uwrkaxlmjj.ui.decoration.listener.GroupListener;
import im.uwrkaxlmjj.ui.hui.CharacterParser;
import im.uwrkaxlmjj.ui.hviews.MryEmptyTextProgressView;
import im.uwrkaxlmjj.ui.hviews.sidebar.SideBar;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class SelecteContactsActivity extends BaseFragment {
    private int chatId;
    private StickyDecoration decoration;
    private ContactsActivityDelegate delegate;
    private MryEmptyTextProgressView emptyView;
    private boolean isCharClicked;
    private LinearLayoutManager layoutManager;
    private RecyclerListView listView;
    private ListAdapter listViewAdapter;
    private boolean loadingUsers;
    private Context mContext;
    private ArrayList<TLRPC.ChatParticipant> participants;
    private FrameLayout searchLayout;
    private SearchAdapter searchListViewAdapter;
    private EditText searchView;
    private boolean searchWas;
    private boolean searching;
    private final HashMap<String, ArrayList<TLRPC.User>> sectionsDict;
    private SideBar sideBar;
    private final ArrayList<String> sortedSectionsArray;
    private boolean usersEndReached;

    public interface ContactsActivityDelegate {
        void didSelectContact(TLRPC.User user);
    }

    public void setDelegate(ContactsActivityDelegate delegate) {
        this.delegate = delegate;
    }

    public void setChatInfo(TLRPC.ChatFull chatFull) {
        if (chatFull != null) {
            this.chatId = chatFull.id;
        }
    }

    public void setParticipants(ArrayList<TLRPC.ChatParticipant> participants) {
        this.participants = participants;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void getChannelParticipants() {
        if (this.loadingUsers) {
            return;
        }
        this.loadingUsers = true;
        final TLRPC.TL_channels_getParticipants req = new TLRPC.TL_channels_getParticipants();
        req.channel = MessagesController.getInstance(this.currentAccount).getInputChannel(this.chatId);
        req.filter = new TLRPC.TL_channelParticipantsRecent();
        req.offset = this.participants.size();
        req.limit = ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION;
        int reqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$SelecteContactsActivity$Lkz0wMA91iWjEi0TyEBkZdMsojM
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getChannelParticipants$1$SelecteContactsActivity(req, tLObject, tL_error);
            }
        });
        ConnectionsManager.getInstance(this.currentAccount).bindRequestToGuid(reqId, this.classGuid);
    }

    public /* synthetic */ void lambda$getChannelParticipants$1$SelecteContactsActivity(final TLRPC.TL_channels_getParticipants req, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$SelecteContactsActivity$CVWAjo8yiBmz5zyajPlHP70cGEw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$0$SelecteContactsActivity(error, response, req);
            }
        }, req.offset == 0 ? 300L : 0L);
    }

    public /* synthetic */ void lambda$null$0$SelecteContactsActivity(TLRPC.TL_error error, TLObject response, TLRPC.TL_channels_getParticipants req) {
        if (error == null) {
            if (!(response instanceof TLRPC.TL_channels_channelParticipants)) {
                return;
            }
            TLRPC.TL_channels_channelParticipants res = (TLRPC.TL_channels_channelParticipants) response;
            MessagesController.getInstance(this.currentAccount).putUsers(res.users, false);
            if (res.users.size() < 200) {
                this.usersEndReached = true;
            }
            if (req.offset == 0) {
                MessagesStorage.getInstance(this.currentAccount).putUsersAndChats(res.users, null, true, true);
                MessagesStorage.getInstance(this.currentAccount).updateChannelUsers(this.chatId, res.participants);
            }
            ArrayList<TLRPC.ChatParticipant> temp = new ArrayList<>();
            for (int a = 0; a < res.participants.size(); a++) {
                TLRPC.TL_chatChannelParticipant participant = new TLRPC.TL_chatChannelParticipant();
                participant.channelParticipant = res.participants.get(a);
                participant.inviter_id = participant.channelParticipant.inviter_id;
                participant.user_id = participant.channelParticipant.user_id;
                participant.date = participant.channelParticipant.date;
                temp.add(participant);
            }
            grouping(temp);
            this.participants.addAll(temp);
        }
        this.loadingUsers = false;
        ListAdapter listAdapter = this.listViewAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    private void grouping(ArrayList<TLRPC.ChatParticipant> participants) {
        String key;
        for (TLRPC.ChatParticipant participant : participants) {
            TLRPC.User user = getMessagesController().getUser(Integer.valueOf(participant.user_id));
            if (user != null && user.id != getUserConfig().clientUserId) {
                String key2 = CharacterParser.getInstance().getSelling(UserObject.getName(user));
                if (key2.length() > 1) {
                    key2 = key2.substring(0, 1);
                }
                if (key2.length() == 0) {
                    key = "#";
                } else if ((key2.charAt(0) > 'a' && key2.charAt(0) < 'z') || (key2.charAt(0) > 'A' && key2.charAt(0) < 'Z')) {
                    key = key2.toUpperCase();
                } else {
                    key = "#";
                }
                ArrayList<TLRPC.User> arr = this.sectionsDict.get(key);
                if (arr == null) {
                    arr = new ArrayList<>();
                    this.sectionsDict.put(key, arr);
                    this.sortedSectionsArray.add(key);
                }
                arr.add(user);
            }
        }
        Collections.sort(this.sortedSectionsArray, new Comparator() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$SelecteContactsActivity$-7xX01Z_o2lycQxCaCEfaNsmta8
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return SelecteContactsActivity.lambda$grouping$2((String) obj, (String) obj2);
            }
        });
    }

    static /* synthetic */ int lambda$grouping$2(String o1, String o2) {
        if ("#".equals(o1)) {
            return 1;
        }
        if (!"#".equals(o2) && o1.charAt(0) >= o2.charAt(0)) {
            return o1.charAt(0) > o2.charAt(0) ? 1 : 0;
        }
        return -1;
    }

    public SelecteContactsActivity(Bundle args) {
        super(args);
        this.participants = new ArrayList<>();
        this.sectionsDict = new HashMap<>();
        this.sortedSectionsArray = new ArrayList<>();
        this.loadingUsers = false;
        this.usersEndReached = false;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        getChannelParticipants();
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        this.delegate = null;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        super.createView(context);
        this.mContext = context;
        this.searching = false;
        this.searchWas = false;
        this.fragmentView = new FrameLayout(context);
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        initActionBar();
        initSearchLayot(frameLayout);
        initList(frameLayout, context);
        initSideBar(frameLayout, context);
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setAllowOverlayTitle(false);
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitle(LocaleController.getString(R.string.redpacket_choose_person));
        this.actionBar.setBackTitle(LocaleController.getString("Cancel", R.string.Cancel));
        this.actionBar.getBackTitleTextView().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$SelecteContactsActivity$k2Gw1P5dW0QJMI__qCjCJEXMT1Y
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initActionBar$3$SelecteContactsActivity(view);
            }
        });
    }

    public /* synthetic */ void lambda$initActionBar$3$SelecteContactsActivity(View v) {
        finishFragment();
    }

    private void initSearchLayot(FrameLayout frameLayout) {
        FrameLayout searchLayout = new FrameLayout(this.mContext);
        searchLayout.setPadding(AndroidUtilities.dp(16.0f), 0, AndroidUtilities.dp(16.0f), 0);
        frameLayout.addView(searchLayout, LayoutHelper.createFrame(-1, 48.0f));
        ImageView iconSearch = new ImageView(this.mContext);
        iconSearch.setImageResource(R.id.ic_index_search);
        searchLayout.addView(iconSearch, LayoutHelper.createFrame(15, 15, GravityCompat.START));
        EditText editText = new EditText(this.mContext);
        this.searchView = editText;
        editText.setHint(LocaleController.getString(R.string.new_call_search_hint));
        this.searchView.setBackground(null);
        this.searchView.setPadding(0, 0, AndroidUtilities.dp(28.0f), 0);
        searchLayout.addView(this.searchView, LayoutHelper.createFrame(-1.0f, -2.0f, 16, 21.0f, 0.0f, 0.0f, 0.0f));
        final ImageView deleteIamge = new ImageView(this.mContext);
        deleteIamge.setVisibility(8);
        deleteIamge.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        searchLayout.addView(deleteIamge, LayoutHelper.createFrame(24, -1, 5));
        deleteIamge.setImageResource(R.id.ic_clear_round);
        this.searchView.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.packet.SelecteContactsActivity.1
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                SelecteContactsActivity.this.searching = true;
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                deleteIamge.setVisibility(s.length() > 0 ? 0 : 8);
                if (SelecteContactsActivity.this.searchListViewAdapter == null) {
                    return;
                }
                if (s.length() == 0) {
                    SelecteContactsActivity.this.searchListViewAdapter.searchDialogs(null);
                    SelecteContactsActivity.this.searching = false;
                    SelecteContactsActivity.this.searchWas = false;
                    SelecteContactsActivity.this.listView.addItemDecoration(SelecteContactsActivity.this.decoration);
                    SelecteContactsActivity.this.listView.setAdapter(SelecteContactsActivity.this.listViewAdapter);
                    SelecteContactsActivity.this.listViewAdapter.notifyDataSetChanged();
                    SelecteContactsActivity.this.listView.setVerticalScrollBarEnabled(false);
                    SelecteContactsActivity.this.listView.setEmptyView(null);
                    SelecteContactsActivity.this.emptyView.setTopImage(R.id.img_empty_default);
                    SelecteContactsActivity.this.emptyView.setText(LocaleController.getString("NoContacts", R.string.NoContacts));
                    return;
                }
                SelecteContactsActivity.this.searchWas = true;
                if (SelecteContactsActivity.this.listView != null) {
                    SelecteContactsActivity.this.listView.removeItemDecoration(SelecteContactsActivity.this.decoration);
                    SelecteContactsActivity.this.listView.setAdapter(SelecteContactsActivity.this.searchListViewAdapter);
                    SelecteContactsActivity.this.searchListViewAdapter.notifyDataSetChanged();
                    SelecteContactsActivity.this.listView.setVerticalScrollBarEnabled(false);
                }
                if (SelecteContactsActivity.this.emptyView != null) {
                    SelecteContactsActivity.this.listView.setEmptyView(SelecteContactsActivity.this.emptyView);
                    SelecteContactsActivity.this.emptyView.setTopImage(R.id.img_empty_default);
                    SelecteContactsActivity.this.emptyView.setText(LocaleController.getString("NoResult", R.string.NoResult));
                }
                SelecteContactsActivity.this.searchListViewAdapter.searchDialogs(s.toString());
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
            }
        });
        deleteIamge.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$SelecteContactsActivity$lLdaNPtJvwXmriVRRJEI4GGIAgU
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initSearchLayot$4$SelecteContactsActivity(view);
            }
        });
    }

    public /* synthetic */ void lambda$initSearchLayot$4$SelecteContactsActivity(View v) {
        this.searchView.setText("");
    }

    private void initList(FrameLayout frameLayout, Context context) {
        grouping(this.participants);
        MryEmptyTextProgressView mryEmptyTextProgressView = new MryEmptyTextProgressView(context);
        this.emptyView = mryEmptyTextProgressView;
        mryEmptyTextProgressView.setShowAtCenter(true);
        this.emptyView.setTopImage(R.id.img_empty_default);
        this.emptyView.setText(LocaleController.getString("NoContacts", R.string.NoContacts));
        this.emptyView.showTextView();
        frameLayout.addView(this.emptyView, LayoutHelper.createFrameSearchWithoutActionBar(-1, -1));
        this.searchListViewAdapter = new SearchAdapter(context);
        this.listViewAdapter = new ListAdapter(context, this.sectionsDict, this.sortedSectionsArray) { // from class: im.uwrkaxlmjj.ui.hui.packet.SelecteContactsActivity.2
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
            public void notifyDataSetChanged() {
                super.notifyDataSetChanged();
                if (SelecteContactsActivity.this.listView != null && SelecteContactsActivity.this.listView.getAdapter() == this) {
                    int count = super.getItemCount();
                    SelecteContactsActivity.this.emptyView.setVisibility(count == 0 ? 0 : 8);
                }
            }
        };
        RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.hui.packet.SelecteContactsActivity.3
            @Override // android.view.View
            public void setPadding(int left, int top, int right, int bottom) {
                super.setPadding(left, top, right, bottom);
                if (SelecteContactsActivity.this.emptyView != null) {
                    SelecteContactsActivity.this.emptyView.setPadding(left, top, right, bottom);
                }
            }
        };
        this.listView = recyclerListView;
        recyclerListView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.SelecteContactsActivity.4
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                SelecteContactsActivity.this.isCharClicked = false;
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                if (!SelecteContactsActivity.this.searching && !SelecteContactsActivity.this.searchWas && !SelecteContactsActivity.this.usersEndReached && SelecteContactsActivity.this.layoutManager.findLastVisibleItemPosition() > SelecteContactsActivity.this.participants.size() - 8) {
                    SelecteContactsActivity.this.getChannelParticipants();
                }
                if (!SelecteContactsActivity.this.isCharClicked) {
                    LinearLayoutManager layoutManager = (LinearLayoutManager) recyclerView.getLayoutManager();
                    int firstPosition = layoutManager.findFirstVisibleItemPosition();
                    String s = SelecteContactsActivity.this.listViewAdapter.getLetter(firstPosition);
                    SelecteContactsActivity.this.sideBar.setChooseChar(s);
                }
            }
        });
        this.listView.setVerticalScrollBarEnabled(false);
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, false);
        this.layoutManager = linearLayoutManager;
        this.listView.setLayoutManager(linearLayoutManager);
        StickyDecoration.Builder decorationBuilder = StickyDecoration.Builder.init(new GroupListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$SelecteContactsActivity$KeVJkxEWnRjOPHDyXZE09l9twrU
            @Override // im.uwrkaxlmjj.ui.decoration.listener.GroupListener
            public final String getGroupName(int i) {
                return this.f$0.lambda$initList$5$SelecteContactsActivity(i);
            }
        }).setGroupBackground(Theme.getColor(Theme.key_windowBackgroundGray)).setGroupTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText)).setGroupTextTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf")).setGroupHeight(AndroidUtilities.dp(24.0f)).setDivideColor(Color.parseColor("#EE96BC")).setGroupTextSize(AndroidUtilities.dp(14.0f)).setTextSideMargin(AndroidUtilities.dp(15.0f));
        StickyDecoration stickyDecorationBuild = decorationBuilder.build();
        this.decoration = stickyDecorationBuild;
        this.listView.addItemDecoration(stickyDecorationBuild);
        this.listView.setAdapter(this.listViewAdapter);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1, 0, AndroidUtilities.dp(48.0f), 0, 0));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$SelecteContactsActivity$g9uyk6e1s25ZYNLiTlDVCAX79NI
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initList$6$SelecteContactsActivity(view, i);
            }
        });
    }

    public /* synthetic */ String lambda$initList$5$SelecteContactsActivity(int position) {
        if (this.listViewAdapter.getItemCount() > position && position > -1) {
            return this.listViewAdapter.getLetter(position);
        }
        return null;
    }

    public /* synthetic */ void lambda$initList$6$SelecteContactsActivity(View view, int position) {
        ContactsActivityDelegate contactsActivityDelegate;
        ContactsActivityDelegate contactsActivityDelegate2;
        if (this.searching && this.searchWas) {
            Object object = this.searchListViewAdapter.getItem(position);
            if (object instanceof TLRPC.User) {
                TLRPC.User user = (TLRPC.User) object;
                ContactsActivityDelegate contactsActivityDelegate3 = this.delegate;
                if (contactsActivityDelegate3 != null) {
                    contactsActivityDelegate3.didSelectContact(user);
                }
                finishFragment();
                return;
            }
            if (object instanceof TLRPC.TL_chatChannelParticipant) {
                TLRPC.TL_chatChannelParticipant participant = (TLRPC.TL_chatChannelParticipant) object;
                TLRPC.User user2 = getMessagesController().getUser(Integer.valueOf(participant.user_id));
                if (user2 != null && (contactsActivityDelegate2 = this.delegate) != null) {
                    contactsActivityDelegate2.didSelectContact(user2);
                }
                finishFragment();
                return;
            }
            if (object instanceof TLRPC.TL_channelParticipant) {
                TLRPC.TL_channelParticipant participant2 = (TLRPC.TL_channelParticipant) object;
                TLRPC.User user3 = getMessagesController().getUser(Integer.valueOf(participant2.user_id));
                if (user3 != null && (contactsActivityDelegate = this.delegate) != null) {
                    contactsActivityDelegate.didSelectContact(user3);
                }
                finishFragment();
                return;
            }
            return;
        }
        int section = this.listViewAdapter.getSectionForPosition(position);
        int row = this.listViewAdapter.getPositionInSectionForPosition(position);
        if (row < 0 || section < 0) {
            return;
        }
        Object item1 = this.listViewAdapter.getItem(section, row);
        if (item1 instanceof TLRPC.User) {
            TLRPC.User user4 = (TLRPC.User) item1;
            ContactsActivityDelegate contactsActivityDelegate4 = this.delegate;
            if (contactsActivityDelegate4 != null) {
                contactsActivityDelegate4.didSelectContact(user4);
            }
            finishFragment();
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
        frameLayout.addView(this.sideBar, LayoutHelper.createFrame(35.0f, 420.0f, 21, 0.0f, 56.0f, 0.0f, 56.0f));
        this.sideBar.setOnTouchingLetterChangedListener(new SideBar.OnTouchingLetterChangedListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$SelecteContactsActivity$0hfcOKMrsdV0fJq792X3v4OBMYU
            @Override // im.uwrkaxlmjj.ui.hviews.sidebar.SideBar.OnTouchingLetterChangedListener
            public final void onTouchingLetterChanged(String str) {
                this.f$0.lambda$initSideBar$7$SelecteContactsActivity(str);
            }
        });
    }

    public /* synthetic */ void lambda$initSideBar$7$SelecteContactsActivity(String s) {
        int section = this.listViewAdapter.getSectionForChar(s.charAt(0));
        int position = this.listViewAdapter.getPositionForSection(section);
        if (position != -1 && this.listView.getLayoutManager() != null) {
            this.listView.getLayoutManager().scrollToPosition(position);
            this.isCharClicked = true;
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

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        EditText editText = this.searchView;
        if (editText != null && !TextUtils.isEmpty(editText.getText().toString().trim())) {
            this.searchView.setText("");
            return false;
        }
        return super.onBackPressed();
    }

    /* JADX INFO: Access modifiers changed from: private */
    class SearchAdapter extends RecyclerListView.SelectionAdapter {
        private int contactsStartRow;
        private int globalStartRow;
        private int groupStartRow;
        private Context mContext;
        private SearchAdapterHelper searchAdapterHelper;
        private ArrayList<TLObject> searchResult = new ArrayList<>();
        private ArrayList<CharSequence> searchResultNames = new ArrayList<>();
        private Runnable searchRunnable;
        private int totalCount;

        public SearchAdapter(Context context) {
            this.mContext = context;
            SearchAdapterHelper searchAdapterHelper = new SearchAdapterHelper(true);
            this.searchAdapterHelper = searchAdapterHelper;
            searchAdapterHelper.setDelegate(new SearchAdapterHelper.SearchAdapterHelperDelegate() { // from class: im.uwrkaxlmjj.ui.hui.packet.SelecteContactsActivity.SearchAdapter.1
                @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
                public /* synthetic */ SparseArray<TLRPC.User> getExcludeUsers() {
                    return SearchAdapterHelper.SearchAdapterHelperDelegate.CC.$default$getExcludeUsers(this);
                }

                @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
                public void onDataSetChanged() {
                    SearchAdapter.this.notifyDataSetChanged();
                }

                @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
                public void onSetHashtags(ArrayList<SearchAdapterHelper.HashtagObject> arrayList, HashMap<String, SearchAdapterHelper.HashtagObject> hashMap) {
                }
            });
        }

        public void searchDialogs(final String query) {
            if (this.searchRunnable != null) {
                Utilities.searchQueue.cancelRunnable(this.searchRunnable);
                this.searchRunnable = null;
            }
            if (TextUtils.isEmpty(query)) {
                this.searchResult.clear();
                this.searchResultNames.clear();
                this.searchAdapterHelper.mergeResults(null);
                this.searchAdapterHelper.queryServerSearch(null, false, false, true, false, SelecteContactsActivity.this.chatId, false, 2);
                notifyDataSetChanged();
                return;
            }
            DispatchQueue dispatchQueue = Utilities.searchQueue;
            Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$SelecteContactsActivity$SearchAdapter$nrio-RvHCIf_I8xxqsmqso5tORQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$searchDialogs$0$SelecteContactsActivity$SearchAdapter(query);
                }
            };
            this.searchRunnable = runnable;
            dispatchQueue.postRunnable(runnable, 300L);
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* JADX INFO: renamed from: processSearch, reason: merged with bridge method [inline-methods] */
        public void lambda$searchDialogs$0$SelecteContactsActivity$SearchAdapter(final String query) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$SelecteContactsActivity$SearchAdapter$XUDz2Wcx1y3tH2Nfw4FW9qz7IpU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$processSearch$2$SelecteContactsActivity$SearchAdapter(query);
                }
            });
        }

        public /* synthetic */ void lambda$processSearch$2$SelecteContactsActivity$SearchAdapter(final String query) {
            this.searchRunnable = null;
            final ArrayList<TLRPC.ChatParticipant> participantsCopy = new ArrayList<>(SelecteContactsActivity.this.participants);
            final ArrayList<TLRPC.Contact> contactsCopy = null;
            this.searchAdapterHelper.queryServerSearch(query, false, false, true, false, SelecteContactsActivity.this.chatId, false, 2);
            Utilities.searchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$SelecteContactsActivity$SearchAdapter$Exif72raQ4ig-wVfGYl8L1KAO_U
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$1$SelecteContactsActivity$SearchAdapter(query, participantsCopy, contactsCopy);
                }
            });
        }

        /* JADX WARN: Removed duplicated region for block: B:51:0x011d A[LOOP:1: B:30:0x00af->B:51:0x011d, LOOP_END] */
        /* JADX WARN: Removed duplicated region for block: B:95:0x00de A[SYNTHETIC] */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public /* synthetic */ void lambda$null$1$SelecteContactsActivity$SearchAdapter(java.lang.String r21, java.util.ArrayList r22, java.util.ArrayList r23) {
            /*
                Method dump skipped, instruction units count: 514
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hui.packet.SelecteContactsActivity.SearchAdapter.lambda$null$1$SelecteContactsActivity$SearchAdapter(java.lang.String, java.util.ArrayList, java.util.ArrayList):void");
        }

        private void updateSearchResults(final ArrayList<TLObject> users, final ArrayList<CharSequence> names, final ArrayList<TLObject> participants) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$SelecteContactsActivity$SearchAdapter$0zJt1i8xxA0XH2v7ok9MUB8wh_M
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$updateSearchResults$3$SelecteContactsActivity$SearchAdapter(users, names, participants);
                }
            });
        }

        public /* synthetic */ void lambda$updateSearchResults$3$SelecteContactsActivity$SearchAdapter(ArrayList users, ArrayList names, ArrayList participants) {
            this.searchResult = users;
            this.searchResultNames = names;
            this.searchAdapterHelper.mergeResults(users);
            ArrayList<TLObject> search = this.searchAdapterHelper.getGroupSearch();
            search.clear();
            search.addAll(participants);
            notifyDataSetChanged();
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() != 1;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int contactsCount = this.searchResult.size();
            int globalCount = this.searchAdapterHelper.getGlobalSearch().size();
            int groupsCount = this.searchAdapterHelper.getGroupSearch().size();
            int count = contactsCount != 0 ? 0 + contactsCount + 1 : 0;
            if (globalCount != 0) {
                count += globalCount + 1;
            }
            if (groupsCount != 0) {
                return count + groupsCount + 1;
            }
            return count;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            this.totalCount = 0;
            int count = this.searchAdapterHelper.getGroupSearch().size();
            if (count != 0) {
                this.groupStartRow = 0;
                this.totalCount += count + 1;
            } else {
                this.groupStartRow = -1;
            }
            int count2 = this.searchResult.size();
            if (count2 != 0) {
                int i = this.totalCount;
                this.contactsStartRow = i;
                this.totalCount = i + count2 + 1;
            } else {
                this.contactsStartRow = -1;
            }
            int count3 = this.searchAdapterHelper.getGlobalSearch().size();
            if (count3 != 0) {
                int i2 = this.totalCount;
                this.globalStartRow = i2;
                this.totalCount = i2 + count3 + 1;
            } else {
                this.globalStartRow = -1;
            }
            super.notifyDataSetChanged();
        }

        public TLObject getItem(int i) {
            int count = this.searchAdapterHelper.getGroupSearch().size();
            if (count != 0) {
                if (count + 1 > i) {
                    if (i == 0) {
                        return null;
                    }
                    return this.searchAdapterHelper.getGroupSearch().get(i - 1);
                }
                i -= count + 1;
            }
            int count2 = this.searchResult.size();
            if (count2 != 0) {
                if (count2 + 1 > i) {
                    if (i == 0) {
                        return null;
                    }
                    return this.searchResult.get(i - 1);
                }
                i -= count2 + 1;
            }
            int count3 = this.searchAdapterHelper.getGlobalSearch().size();
            if (count3 == 0 || count3 + 1 <= i || i == 0) {
                return null;
            }
            return this.searchAdapterHelper.getGlobalSearch().get(i - 1);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new ManageChatUserCell(this.mContext, 2, 2, true);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                ((ManageChatUserCell) view).setDelegate(new ManageChatUserCell.ManageChatUserCellDelegate() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$SelecteContactsActivity$SearchAdapter$taOcE3hFTfYCYIFuON-qAg5gQ70
                    @Override // im.uwrkaxlmjj.ui.cells.ManageChatUserCell.ManageChatUserCellDelegate
                    public final boolean onOptionsButtonCheck(ManageChatUserCell manageChatUserCell, boolean z) {
                        return this.f$0.lambda$onCreateViewHolder$4$SelecteContactsActivity$SearchAdapter(manageChatUserCell, z);
                    }
                });
            } else {
                view = new GraySectionCell(this.mContext);
            }
            return new RecyclerListView.Holder(view);
        }

        public /* synthetic */ boolean lambda$onCreateViewHolder$4$SelecteContactsActivity$SearchAdapter(ManageChatUserCell cell, boolean click) {
            TLObject object = getItem(((Integer) cell.getTag()).intValue());
            if (!(object instanceof TLRPC.ChannelParticipant)) {
                return false;
            }
            return false;
        }

        /* JADX WARN: Removed duplicated region for block: B:43:0x00ee  */
        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void onBindViewHolder(androidx.recyclerview.widget.RecyclerView.ViewHolder r21, int r22) {
            /*
                Method dump skipped, instruction units count: 463
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hui.packet.SelecteContactsActivity.SearchAdapter.onBindViewHolder(androidx.recyclerview.widget.RecyclerView$ViewHolder, int):void");
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewRecycled(RecyclerView.ViewHolder holder) {
            if (holder.itemView instanceof ManageChatUserCell) {
                ((ManageChatUserCell) holder.itemView).recycle();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            if (i == this.globalStartRow || i == this.groupStartRow || i == this.contactsStartRow) {
                return 1;
            }
            return 0;
        }
    }

    private static class ListAdapter extends RecyclerListView.SectionsAdapter {
        private Context mContext;
        ArrayList<String> sortedUsersSectionsArray;
        HashMap<String, ArrayList<TLRPC.User>> usersSectionsDict;

        ListAdapter(Context mContext, HashMap<String, ArrayList<TLRPC.User>> usersSectionsDict, ArrayList<String> sortedUsersSectionsArray) {
            this.mContext = mContext;
            this.usersSectionsDict = usersSectionsDict;
            this.sortedUsersSectionsArray = sortedUsersSectionsArray;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public Object getItem(int section, int position) {
            if (section < 0 || section >= this.sortedUsersSectionsArray.size()) {
                return null;
            }
            ArrayList<TLRPC.User> arr = this.usersSectionsDict.get(this.sortedUsersSectionsArray.get(section));
            if (position >= arr.size()) {
                return null;
            }
            return arr.get(position);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public String getLetter(int position) {
            int section = getSectionForPosition(position);
            if (section == -1) {
                section = this.sortedUsersSectionsArray.size() - 1;
            }
            if (section >= 0 && section <= this.sortedUsersSectionsArray.size()) {
                return this.sortedUsersSectionsArray.get(section);
            }
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public int getPositionForScrollProgress(float progress) {
            return (int) (getItemCount() * progress);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getSectionCount() {
            ArrayList<String> arrayList = this.sortedUsersSectionsArray;
            if (arrayList == null) {
                return 0;
            }
            return arrayList.size();
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getCountForSection(int section) {
            ArrayList<TLRPC.User> arr;
            if (section < this.sortedUsersSectionsArray.size() && (arr = this.usersSectionsDict.get(this.sortedUsersSectionsArray.get(section))) != null) {
                int count = arr.size();
                if (section != this.sortedUsersSectionsArray.size() - 1) {
                    return count + 1;
                }
                return count;
            }
            return 0;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public boolean isEnabled(int section, int row) {
            if (section >= this.sortedUsersSectionsArray.size()) {
                return true;
            }
            ArrayList<TLRPC.User> arr = this.usersSectionsDict.get(this.sortedUsersSectionsArray.get(section));
            return row < arr.size();
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getItemViewType(int section, int position) {
            if (section < this.sortedUsersSectionsArray.size()) {
                ArrayList<TLRPC.User> arr = this.usersSectionsDict.get(this.sortedUsersSectionsArray.get(section));
                return position < arr.size() ? 0 : 3;
            }
            return 1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public View getSectionHeaderView(int section, View view) {
            if (view == null) {
                view = new LetterSectionCell(this.mContext);
            }
            LetterSectionCell cell = (LetterSectionCell) view;
            if (section < this.sortedUsersSectionsArray.size()) {
                cell.setLetter(this.sortedUsersSectionsArray.get(section));
            } else {
                cell.setLetter("");
            }
            return view;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new UserCell(this.mContext, 58, 1, false);
            } else {
                view = new View(this.mContext);
            }
            return new RecyclerListView.Holder(view);
        }

        public int getSectionForChar(char section) {
            for (int i = 0; i < getSectionCount() - 1; i++) {
                String sortStr = this.sortedUsersSectionsArray.get(i);
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
            int N = getSectionCount();
            for (int i = 0; i < N; i++) {
                if (i >= section) {
                    return positionStart;
                }
                int count = getCountForSection(i);
                positionStart += count;
            }
            return -1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public void onBindViewHolder(int section, int position, RecyclerView.ViewHolder holder) {
            if (holder.getItemViewType() == 0) {
                UserCell userCell = (UserCell) holder.itemView;
                userCell.setAvatarPadding(6);
                ArrayList<TLRPC.User> arr = this.usersSectionsDict.get(this.sortedUsersSectionsArray.get(section));
                TLRPC.User user = arr.get(position);
                userCell.setData(user, null, null, 0);
            }
        }
    }
}
